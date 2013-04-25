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
} config = {
		.threshhold	= 20,
		.delta		= 10,
		.log_level	= 0,
		.dry		= 0,
		.oneshot	= 0,
};

static int stop = 0;

static void sigint_handler(int signo)
{
	stop = 1;
}

static void print_discard_stat(struct ploop_discard_stat *pds)
{
	vzctl2_log(0, 0, "ploop=%ldMB image=%ldMB data=%ldMB balloon=%ldMB",
			pds->ploop_size >> 20,
			pds->image_size >> 20,
			pds->data_size >> 20,
			pds->balloon_size >> 20);
}

int ploop_compact(const char *descr)
{
	int err = 0;
	double rate;
	struct ploop_discard_stat pds;
	struct ploop_disk_images_data *di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(descr, di)) {
		ploop_free_diskdescriptor(di);
		return -1;
	}

	vzctl2_log(0, 0, "Disk: %s", descr);
	err = ploop_discard_get_stat(di, &pds);
	if (err) {
		vzctl2_log(-1, 0, "Failed to get discard stat: %s",
				ploop_get_last_error());
		ploop_free_diskdescriptor(di);
		return err;
	}

	print_discard_stat(&pds);

	rate = ((double) pds.image_size - pds.data_size) / pds.ploop_size * 100;
	vzctl2_log(0, 0, "Rate: %.1f (threshold=%d)",
			rate, config.threshhold);

	if (rate > config.threshhold) {
		rate = (rate - (config.delta < rate ? config.delta : 0))
				* pds.ploop_size / 100;

		vzctl2_log(0, 0, "Start compacting (to free %.0fMB)",
				rate / (1 << 20));
		if (!config.dry) {
			struct ploop_discard_param param = {};

			param.minlen_b = 0;
			param.to_free = rate;
			param.stop = &stop;

			err = ploop_discard(di, &param);
			if (ploop_discard_get_stat(di, &pds) == 0)
				print_discard_stat(&pds);
			vzctl2_log(0, 0, "End compaction");
		}
	}

	ploop_free_diskdescriptor(di);
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
	err = vzctl2_conf_get_param(conf, "THRESHOLD", &res);
	if (err)
		goto err;
	if (res)
		config.threshhold = atoi(res);
	res = NULL;
	err = vzctl2_conf_get_param(conf, "DELTA", &res);
	if (err)
		goto err;
	if (res)
		config.delta = atoi(res);
err:
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
		if (err)
			continue;

		if (vpses.vpses[vps].status == VPS_STOPPED) {
			snprintf(cmd, sizeof(cmd), "/usr/bin/prlctl mount %s",
							vpses.vpses[vps].uuid);
			ret = system(cmd);
			if (ret)
				vzctl2_log(-1, 0, "%s returned code %d", cmd, ret);
			else
				mount = 1;
		}

		for (j = 0; j < d.num; j++) {
			vzctl2_log(0, 0, "Inspect %s", d.disks[j]);
			if (vpses.vpses[vps].type == VPS_CT)
				ploop_compact(d.disks[j]);
		}
		vps_disk_list_free(&d);

		if (mount) {
			snprintf(cmd, sizeof(cmd), "/usr/bin/prlctl umount %s",
							vpses.vpses[vps].uuid);
			ret = system(cmd);
			if (ret)
				vzctl2_log(-1, 0, "%s returned code %d", cmd, ret);
		}

		if (config.oneshot)
			break;
	}
out:
	vps_list_free(&vpses);
	return 0;
}

static void usage(char **argv)
{
	vzctl2_log(-1, 0, "Usage:\n"
		   "\t%s [-vns] [-t timeout[smh]]\n\n"
		   "Options:\n"
		   "  -v\tincrease verbosity.\n"
		   "\tCould be used several times to increase verbosity higher\n"
		   "  -n\tprint the actions that would be executed, but do not execute them\n"
		   "  -s\tcompact only first not yet compacted disk\n"
		   "  -t\twork only specified time. Suffixes for seconds, minutes and hours are allowed.",
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
	static const char short_opts[] = "nvst:";
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
			default:
				usage(argv);
				exit(1);
		}
	}

	vzctl2_set_log_file(COMPACT_LOG_FILE);
	vzctl2_set_log_enable(1);
	vzctl2_set_log_quiet(0);
	vzctl2_set_log_level(config.log_level);
	vzctl2_set_log_verbose(config.log_level);

	sigemptyset(&sa.sa_mask);

        if (sigaction(SIGINT, &sa, NULL)) {
                vzctl2_log(-1, errno, "Can't set signal handler");
                exit(1);
        }
        if (sigaction(SIGALRM, &sa, NULL)) {
                vzctl2_log(-1, errno, "Can't set signal handler");
                exit(1);
        }

	scan();

	vzctl2_lib_close();

	return 0;
}
