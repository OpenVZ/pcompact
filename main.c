/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 * This file is part of OpenVZ. OpenVZ is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include <sys/stat.h>

#include <vz/vzevent.h>
#include <vzctl/libvzctl.h>
#include <ploop/libploop.h>

#include "parser.h"

#define COMPACT_CONF "/etc/vz/pcompact.conf"
#define COMPACT_STATE "/var/run/pcompact.pid"
#define COMPACT_LOG_FILE "/var/log/pcompact.log"

static struct {
	int threshhold;
	int delta; /* how many data should be freed */
	int log_level;
	int dry;
	int oneshot;
	int quiet;
	int defrag;
} config = {
		.threshhold	= 20,
		.delta		= 10,
		.log_level	= 0,
		.dry		= 0,
		.oneshot	= 0,
		.quiet		= 0,
		.defrag		= 1,
};

static int stop = 0;
static int keep_running = 1;
static dev_t compact_dev;

static void sigint_handler(int signo)
{
	stop = 1;
	keep_running = 0;
}

static void *vzevent_monitor(void *arg)
{
	struct vzctl_state_evt *s;
	int n;
	vzevt_handle_t *evt = (vzevt_handle_t *) arg;
	int fd = evt->sock;

	while (keep_running) {
		vzevt_t *e = NULL;
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		n = select(fd + 1, &rfds, NULL, NULL, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			vzctl2_log(-1, errno, "vzevent_monitor: select(): %m");
			break;
		}

		if (FD_ISSET(fd, &rfds) && vzevt_recv(evt, &e) == 1) {
			s = (struct vzctl_state_evt *) e->buffer;
			if (e->type == VZEVENT_VZCTL_EVENT_TYPE &&
					s->state == VZCTL_ENV_UMOUNT &&
					compact_dev == s->dev) {
				vzctl2_log(0, 0, "Cancel compacting %s", s->ctid);
				stop = 1;
			}
			vzevt_free(e);
		}
	}
	return NULL;
}

static void print_discard_stat(struct ploop_discard_stat *pds)
{
	vzctl2_log(0, 0, "ploop=%ldMB image=%ldMB data=%ldMB balloon=%ldMB",
			pds->ploop_size >> 20,
			pds->image_size >> 20,
			pds->data_size >> 20,
			pds->balloon_size >> 20);
}

static void print_internal_stat(
	const struct vps *vps,
	const struct ploop_discard_stat *pds_before,
	const struct ploop_discard_stat *pds_after,
	const struct timeval *tv_elapsed )
{
	int old_quiet;

	/* write internal stats exclusively to log file */
	old_quiet = vzctl2_set_log_quiet(1);
	vzctl2_log(0, 0, "Stats: uuid=%s ploop_size=%ldMB image_size_before=%ldMB"
		" image_size_after=%ldMB compaction_time=%ld.%03lds type=%s",
		vps->uuid,
		pds_before->ploop_size >> 20,
		pds_before->image_size >> 20,
		pds_after->image_size >> 20,
		(long)tv_elapsed->tv_sec, (long)tv_elapsed->tv_usec / 1000,
		(vps->status == VPS_RUNNING ? "online" : "offline"));
	vzctl2_set_log_quiet(old_quiet);
}

static void log_start(const char *uuid, const char *task_id, struct ploop_discard_stat *pds, int disk_id, double rate)
{
	char out[1024];

	sprintf(out, "{\"operation\":\"pcompactStart\", \"uuid\":\"%s\", "
		"\"disk_id\":%d, \"task_id\":\"%s\", \"ploop_size\":%lu, \"image_size\":%lu, "
		"\"data_size\":%lu, \"balloon_size\":%lu, \"rate\":%.1f, "
		"\"config_dry\":%d, \"config_threhshold\":%d}",
		uuid, disk_id, task_id, pds->ploop_size >> 20, pds->image_size >> 20,
		pds->data_size >> 20, pds->balloon_size >> 20, rate, config.dry,
		config.threshhold);

	syslog(LOG_INFO, out);
}

static void log_finish(const char *uuid, const char *task_id, const struct ploop_discard_stat *pds,
	const struct ploop_discard_stat *pds_after, int disk_id, const struct timeval *tv_elapsed, int code)
{
	char out[1024];

	sprintf(out, "{\"operation\":\"pcompactFinish\", \"uuid\":\"%s\", "
		"\"disk_id\":%d, \"task_id\":\"%s\", \"was_compacted\":1, \"ploop_size\":%lu, "
		"\"stats_before\": {\"image_size\":%lu, \"data_size\":%lu, \"balloon_size\":%lu}, "
		"\"stats_after\": {\"image_size\":%lu, \"data_size\":%lu, \"balloon_size\":%lu},"
		"\"time_spent\":\"%ld.%03lds\", \"result\":%d}",

		uuid, disk_id, task_id, pds->ploop_size >> 20, pds->image_size >> 20,
		pds->data_size >> 20, pds->balloon_size >> 20,
		pds_after->image_size >> 20, pds_after->data_size >> 20,
		pds_after->balloon_size >> 20, (long)tv_elapsed->tv_sec,
		(long)tv_elapsed->tv_usec / 1000, code);

	syslog(LOG_INFO, out);
}

static void log_cancel(const char *uuid, const char *task_id, int disk_id)
{
	char out[1024];

	sprintf(out, "{\"operation\":\"pcompactFinish\", \"uuid\":\"%s\", "
		"\"disk_id\":%d, \"task_id\":\"%s\", \"was_compacted\":0}",
		uuid, disk_id, task_id);
	syslog(LOG_INFO, out);
}

int ploop_compact(const struct vps *vps, const char *descr, int disk_id)
{
	int err = 0, was_compacted = 0;
	double rate;
	char task_id[39] = "";
	char dev[64], part[64];
	struct ploop_disk_images_data *di;
	struct ploop_discard_stat pds, pds_after;
	struct timeval tv_before, tv_after, tv_delta;
	struct stat st;
	uuid_t u;

	if (ploop_open_dd(&di, descr))
		return -1;

	if (ploop_get_dev(di, dev, sizeof(dev)) ||
			ploop_get_part(di, dev, part, sizeof(part))) {
		ploop_close_dd(di);
		return -1;
	}

	stop = 0;
	if (stat(part, &st) == 0)
		compact_dev = st.st_rdev;

	err = ploop_discard_get_stat(di, &pds);
	if (err) {
		vzctl2_log(-1, 0, "Failed to get discard stat: %s",
				ploop_get_last_error());
		ploop_close_dd(di);
		return err;
	}

	if (di->nsnapshots > 1) {
		vzctl2_log(0, 0, "This ploop image contains snapshots."
			" Trying to compact the last delta file.");
		vzctl2_log(0, 0, "For best compacting results, remove snapshots.");
	}

	print_discard_stat(&pds);

	rate = ((double) pds.image_size - pds.data_size) / pds.ploop_size * 100;
	vzctl2_log(0, 0, "Rate: %.1f (threshold=%d)",
			rate, config.threshhold);

	uuid_generate(u);
	uuid_unparse(u, task_id);

	log_start(vps->uuid, task_id, &pds, disk_id, rate);

	/* Image size can be less than data size. to avoid negative rate */
	if (rate < 0)
		rate = 0;

	if (rate > config.threshhold) {
		rate = (rate - (config.delta < rate ? config.delta : 0))
				* pds.ploop_size / 100;
		vzctl2_log(0, 0, "Start compacting (to free %.0fMB)",
				rate / (1 << 20));
		if (!config.dry) {

			was_compacted = 1;

			/* store time before compacting */
			gettimeofday(&tv_before, NULL);

			/* compact ploop */
			struct ploop_discard_param param = {
				.minlen_b = 0,
				.to_free = rate,
				.stop = &stop,
				.defrag = !!config.defrag,
			};
			err = ploop_discard(di, &param);

			/* store time after compacting */
			gettimeofday(&tv_after, NULL);
			timersub(&tv_after, &tv_before, &tv_delta);

			if (ploop_discard_get_stat(di, &pds_after) == 0) {
				print_discard_stat(&pds_after);
				print_internal_stat(vps, &pds, &pds_after, &tv_delta);
			}

			vzctl2_log(0, 0, "End compacting");
		}
	}

	if (was_compacted)
		log_finish(vps->uuid, task_id, &pds, &pds_after, disk_id, &tv_delta, err);
	else
		log_cancel(vps->uuid, task_id, disk_id);

	ploop_close_dd(di);
	compact_dev = 0;
	return err;
}

static int parse_config()
{
	struct vzctl_config *conf;
	const char *res;
	int err;

	conf = vzctl2_conf_open(COMPACT_CONF, 0, &err);
	if (err)
		return -1;

	res = NULL;
	vzctl2_conf_get_param(conf, "THRESHOLD", &res);
	if (res)
		config.threshhold = atoi(res);

	res = NULL;
	vzctl2_conf_get_param(conf, "DELTA", &res);
	if (res)
		config.delta = atoi(res);

	res = NULL;
	vzctl2_conf_get_param(conf, "DEFRAG", &res);
	if (res)
		config.defrag = (strcmp(res, "yes") == 0);

	vzctl2_conf_close(conf);

	return err;
}

int state_fd = -1;

static int open_state_file()
{
	int fd, err;
	char buf[20];

	fd = open(COMPACT_STATE, O_CREAT | O_RDWR, 0644);
	if (fd == -1) {
		vzctl2_log(-1, errno, "Can't create a pid file: %s", COMPACT_STATE);
		return -1;
	}

	/* Prevent to execute two instances simultaneously */
	err = flock(fd, LOCK_EX | LOCK_NB);
	if (err == -1) {
		vzctl2_log(-1, errno, "Can't lock %s", COMPACT_STATE);
		close(fd);
		return err;
	}

	buf[sizeof(buf) - 1] = '\0';
	err = read(fd, buf, sizeof(buf) - 1);
	if (err == -1) {
		vzctl2_log(-1, errno, "Can't read %s", COMPACT_STATE);
		close(fd);
	}

	state_fd = fd;

	if (err == 0)
		return INT_MAX;

	return atoi(buf);
}

/* Save the current VPS number in the start file */
static int update_stat_file(const int state)
{
	int err;

	err = ftruncate(state_fd, 0);
	if (err == -1) {
		vzctl2_log(-1, errno, "Can't truncate the state file %s", COMPACT_STATE);
		return -1;
	}

	lseek(state_fd, 0, SEEK_SET);

	err = dprintf(state_fd, "%d", state);
	if (err == -1) {
		vzctl2_log(-1, errno, "Can't write the state file %s", COMPACT_STATE);
		return err;
	}

	return 0;
}

/**
 * Enumerate all VPSs and compact their disks.
 * If this functions is interrupted, it will start from
 * the next VPS than in a previous case.
 * */
static int scan()
{
	int i, err, pstate, vps;
	struct vps_list vpses;

	err = vps_get_list(&vpses);
	if (err)
		return 1;

	pstate = open_state_file();
	if (pstate < 0)
		return -1;

	if (pstate > vpses.num)
		pstate = 0;
	else
		pstate++; /* start from the next one */

	openlog("pcompact", LOG_PID, LOG_INFO | LOG_USER);

	for (i = 0; i < vpses.num; i++) {
		struct vps_disk_list d;
		int mount = 0, ret;
		char cmd[128];
		int j;

		vps = (i + pstate) % vpses.num;

		vzctl2_log(0, 0, "Inspect %s", vpses.vpses[vps].uuid);

		err = update_stat_file(vps);
		if (err < 0)
			goto out;

		err = vps_get_disks(vpses.vpses + vps, &d);
		if (err || d.disks == NULL)
			continue;

		if (vpses.vpses[vps].status == VPS_STOPPED) {
			snprintf(cmd, sizeof(cmd), "/usr/bin/prlctl mount %s --verbose %d",
							vpses.vpses[vps].uuid, config.quiet ? -1 : config.log_level);
			ret = system(cmd);
			if (ret)
				vzctl2_log(-1, 0, "%s returned code %d", cmd, ret);
			else
				mount = 1;
		}

		for (j = 0; j < d.num; j++) {
			vzctl2_log(0, 0, "Inspect %s", d.disks[j]);
			if (vpses.vpses[vps].type != VPS_CT)
				continue;

			ploop_compact(&vpses.vpses[vps], d.disks[j], j);
		}

		vps_disk_list_free(&d);

		if (mount) {
			snprintf(cmd, sizeof(cmd), "/usr/bin/prlctl umount %s --verbose %d",
							vpses.vpses[vps].uuid, config.quiet ? -1 : config.log_level);
			ret = system(cmd);
			if (ret)
				vzctl2_log(-1, 0, "%s returned code %d", cmd, ret);
		}

		if (config.oneshot)
			break;
	}
out:
	closelog();
	vps_list_free(&vpses);
	return 0;
}

static void usage(char **argv)
{
	vzctl2_log(-1, 0, "Usage:\n"
		   "\t%s [-vnsq] [-t timeout[smh]]\n\n"
		   "Options:\n"
		   "  -v\tincrease verbosity.\n"
		   "\tCould be used several times to increase verbosity higher\n"
		   "  -n\tprint the actions that would be executed, but do not execute them\n"
		   "  -s\tcompact only first not yet compacted disk\n"
		   "  -t\twork only specified time. Suffixes for seconds, minutes and hours are allowed\n"
		   "  -q\tdisable printing of non-error messages to the standard output (console).",
		   argv[0]);
}

static int settimer(const char *opt)
{
	timer_t timer;
	struct itimerspec its = {};
	char * endptr;
	int val = strtoul(opt, &endptr, 0);

	if (strlen(endptr) > 1) {
		vzctl2_log(-1, 0, "Invalid argument - %s", opt);
		return -1;
	}

	switch (*endptr)
	{
		case 's': case 'S': case 0:
			break;
		case 'm': case 'M':
			val *= 60;
			break;
		case 'h': case 'H':
			val *= 3600; break;
		default:
			vzctl2_log(-1, 0, "Invalid argument - %s", opt);
			return -1;
	};

	its.it_value.tv_sec = val;

	if (timer_create(CLOCK_MONOTONIC, NULL, &timer) == -1) {
		vzctl2_log(-1, errno, "Can't set up a timer");
		return 1;
	}
	if (timer_settime(timer, 0, &its, NULL) == -1) {
		vzctl2_log(-1, errno, "Can't set up a timer");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int err, opt;
	static const char short_opts[] = "nvst:q";
	struct sigaction sa = {
		.sa_handler     = sigint_handler,
		.sa_flags	= SA_RESTART,
	};

	vzctl2_lib_init();

	vzctl2_init_log("pcompact");

	err = parse_config();
	if (err < 0) {
		fprintf(stderr, "Can't parse config: %s\n", COMPACT_CONF);
		return 1;
	}

	while ((opt = getopt(argc, argv, short_opts)) != -1) {
		switch (opt) {
			case 'v':
				config.log_level++;
			break;
			case 'n':
				config.dry = 1;
			break;
			case 's':
				config.oneshot = 1;
			break;
			case 't':
				if (settimer(optarg))
					return 1;
			break;
			case 'q':
				config.quiet = 1;
			break;
			default:
				usage(argv);
				exit(1);
		}
	}

	vzctl2_set_log_file(COMPACT_LOG_FILE);
	vzctl2_set_log_enable(1);
	vzctl2_set_log_quiet(config.quiet);
	vzctl2_set_log_level(config.log_level);
	vzctl2_set_log_verbose(config.log_level);

	sigemptyset(&sa.sa_mask);

        if (sigaction(SIGINT, &sa, NULL) ||
        		sigaction(SIGALRM, &sa, NULL) ||
        		sigaction(SIGTERM, &sa, NULL)) {
                vzctl2_log(-1, errno, "Can't set signal handler");
                exit(1);
        }

        vzevt_handle_t *evt;
        pthread_t evt_th;

        if (vzevt_register(&evt)) {
                syslog(LOG_ERR, "Unable to register vzevent handler");
                return 1;
        }

        if (pthread_create(&evt_th, NULL, vzevent_monitor, evt)) {
                syslog( LOG_ERR, "pthread_create: %m");
                return 1;
        }

	scan();

	keep_running = 0;
	pthread_kill(evt_th, SIGTERM);
	pthread_join(evt_th, NULL);
	vzevt_unregister(evt);
	vzctl2_lib_close();

	return 0;
}
