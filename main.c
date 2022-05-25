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

#include "parser.h"

#define COMPACT_CONF "/etc/vz/pcompact.conf"
#define COMPACT_STATE "/var/run/pcompact.pid"
#define COMPACT_LOG_FILE "/var/log/pcompact.log"

static struct {
	int threshold;
	int image_defrag_threshold;
	int delta; /* how many data should be freed */
	int log_level;
	int dry;
	int oneshot;
	int quiet;
	int defrag;
} config = {
		.threshold	= 20,
		.image_defrag_threshold	= 10,
		.delta		= 10,
		.log_level	= 0,
		.dry		= 0,
		.oneshot	= 0,
		.quiet		= 0,
		.defrag		= 1,
};

static volatile int stop = 0;
static volatile int keep_running = 1;
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

static void log_start(const char *uuid, const char *task_id, const struct vzctl_compact_param *param)
{
	char out[1024];

	snprintf(out, sizeof(out), "{\"operation\":\"pcompactStart\", \"uuid\":\"%s\", "
		"\"task_id\":\"%s\", \"config_dry\":%d, \"config_threhshold\":%d}",
		uuid, task_id, param->dry, param->threshold);

	syslog(LOG_INFO, "%s", out);
}

static void log_finish(const char *uuid, const char *task_id, int code)
{
	char out[1024];

	snprintf(out, sizeof(out), "{\"operation\":\"pcompactFinish\", \"uuid\":\"%s\", "
		"\"task_id\":\"%s\", \"was_compacted\":1, \"result\":%d}",
		uuid, task_id, code);

	syslog(LOG_INFO, "%s", out);
}

static void log_cancel(const char *uuid, const char *task_id)
{
	char out[1024];

	snprintf(out, sizeof(out), "{\"operation\":\"pcompactFinish\", \"uuid\":\"%s\", "
		"\"task_id\":\"%s\", \"was_compacted\":0}",
		uuid, task_id);
	syslog(LOG_INFO, "%s", out);
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
		config.threshold = atoi(res);
	res = NULL;
	vzctl2_conf_get_param(conf, "IMAGE_DEFRAG_THRESHOLD", &res);
	if (res)
		config.image_defrag_threshold = atoi(res);

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

	memset(buf, 0, sizeof(buf));
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
	if (pstate < 0) {
		closelog();
		vps_list_free(&vpses);
		return -1;
	}

	if (pstate > vpses.num)
		pstate = 0;
	else
		pstate++; /* start from the next one */

	openlog("pcompact", LOG_PID, LOG_INFO | LOG_USER);

	for (i = 0; i < vpses.num && keep_running; i++) {
		int ret = 0;
		int flags = 0;
		int isCompactEnabled = 0;
		ctid_t ctID;
		struct vzctl_env_handle *h = NULL;
		char task_id[39] = "";
		uuid_t task_uuid;
		struct vzctl_compact_param param = {
				.defrag = config.defrag,
				.threshold = config.threshold,
				.delta = config.delta,
				.dry = config.dry,
				.stop = (int *)&stop,
				.compact_dev = &compact_dev,
		};

		vps = (i + pstate) % vpses.num;

		vzctl2_log(0, 0, "Inspect %s", vpses.vpses[vps].uuid);

		err = update_stat_file(vps);
		if (err < 0)
			goto out;

		if (vzctl2_parse_ctid(vpses.vpses[vps].uuid, ctID)) {
			vzctl2_log(-1, 0, "Error: Invalid CT ID %s. Skip it", vpses.vpses[vps].uuid);
			continue;
		}
		h = vzctl2_env_open(ctID, flags, &ret);
		if (ret || !h){
			vzctl2_log(-1, 0, "Error [%d]: cannot open CT [%s]. Skip it", ret, ctID);
			continue;
		}

		stop = 0;

		vzctl2_env_get_autocompact(vzctl2_get_env_param(h), &isCompactEnabled);
		if (isCompactEnabled == 0) {
			//skip current CT
			vzctl2_env_close(h);
			continue;
		}

		uuid_generate(task_uuid);
		uuid_unparse(task_uuid, task_id);

		log_start(vpses.vpses[vps].uuid, task_id, &param);

		ret = vzctl2_env_compact(h, &param, sizeof(param));

		if (ret) {
			vzctl2_log(-1, 0, "vzctl2_env_compact return error code: %d", ret);
			log_cancel(vpses.vpses[vps].uuid, task_id);
		} else
			log_finish(vpses.vpses[vps].uuid, task_id, err);

		vzctl2_env_close(h);

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
		   "\t%s [-vnsq] [-t timeout[smh]] [-D]\n\n"
		   "Options:\n"
		   "  -v\tincrease verbosity.\n"
		   "\tCould be used several times to increase verbosity higher\n"
		   "  -n\tprint the actions that would be executed, but do not execute them\n"
		   "  -s\tcompact only first not yet compacted disk\n"
		   "  -t\twork only specified time. Suffixes for seconds, minutes and hours are allowed\n"
		   "  -q\tdisable printing of non-error messages to the standard output (console).\n"
		   "  -D\tdefragment file system only.\n",
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

	while ((opt = getopt(argc, argv, "nvst:qD")) != -1) {
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
			case 'D':
				config.defrag = 2;
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
