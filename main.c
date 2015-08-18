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
static int __defrag_pid = -1;

static void sigint_handler(int signo)
{
	if (__defrag_pid != -1)
		kill(__defrag_pid, SIGTERM);
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

static int defrag(char *dev, char *mnt, unsigned int block_size)
{
	int status;
	char s[16];
	int rc = 0;
	char *arg[] = {
		"/usr/libexec/e4defrag", "-c", s, dev, mnt, NULL
	};

	if (access(arg[0], F_OK))
		return 0;

	snprintf(s, sizeof(s), "%u", block_size);

	__defrag_pid = fork();
	if (__defrag_pid == -1) {
		vzctl2_log(-1, errno, "Unable to fork: %m");
		return -1;
	} else if (__defrag_pid == 0) {
		execv(arg[0], arg);
		exit(1);
	}

	while (waitpid(__defrag_pid, &status, 0) == -1)
		if (errno != EINTR) {
			__defrag_pid = -1;
			vzctl2_log(-1, errno, "%s error in waitpid(%d)",
					arg[0], __defrag_pid);
			return -1;
		}

	__defrag_pid = -1;
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)) {
			vzctl2_log(-1, 0, "%s exited with %d", arg[0], rc);
			return -1;
		}
	} else if (WIFSIGNALED(status)) {
		vzctl2_log(-1, 0, "%s got signal %d", arg[0], WTERMSIG(status));
		return -1;
	}

	return 0;
}

int ploop_defrag(const char *descr)
{
	char dev[64];
	char mnt[PATH_MAX];
	int rc;
	struct ploop_disk_images_data *di;
	struct ploop_spec spec;

	if (ploop_open_dd(&di, descr)) {
		vzctl2_log(-1, 0, "ploop_open_dd %s: %s",
				descr, ploop_get_last_error());
		return -1;
	}

	rc = ploop_get_dev(di, dev, sizeof(dev));
	if (rc) {
		if (rc == -1)
			vzctl2_log(-1, 0, "ploop_get_dev %s: %s",
				descr, ploop_get_last_error());
		goto err;
	}

	rc = ploop_get_spec(di, &spec);
	if (rc) {
		vzctl2_log(-1, 0, "ploop_get_spec %s: %s",
				descr, ploop_get_last_error());
		goto err;
	}

	rc = ploop_get_mnt_by_dev(dev, mnt, sizeof(mnt));
	if (rc) {
		if (rc == -1)
			vzctl2_log(-1, 0, "ploop_get_mnt_by_dev %s %s: %s",
				descr, dev, ploop_get_last_error());
		goto err;
	}

	rc = ploop_get_partition_by_mnt(mnt, dev, sizeof(dev));
	if (rc) {
		if (rc ==  -1)
			vzctl2_log(-1, 0, "ploop_get_partition_by_mnt %s %s: %s",
				descr, mnt, ploop_get_last_error());
		goto err;
	}

	vzctl2_log(0, 0, "Start defrag %s dev=%s mnt=%s blocksize=%u",
			descr, dev, mnt, spec.blocksize);
	rc = defrag(dev, mnt, spec.blocksize << 9);
err:

	ploop_close_dd(di);

	return rc;
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

int ploop_compact(const struct vps *vps, const char *descr)
{
	int err = 0;
	double rate;
	struct ploop_disk_images_data *di;
	struct ploop_discard_stat pds, pds_after;
	struct timeval tv_before, tv_after, tv_delta;

	if (ploop_open_dd(&di, descr))
		return -1;

	vzctl2_log(0, 0, "Disk: %s", descr);
	err = ploop_discard_get_stat(di, &pds);
	if (err) {
		vzctl2_log(-1, 0, "Failed to get discard stat: %s",
				ploop_get_last_error());
		ploop_free_diskdescriptor(di);
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
	/* Image size can be less than data size. to avoid negative rate */
	if (rate < 0)
		rate = 0;

	if (rate > config.threshhold) {
		rate = (rate - (config.delta < rate ? config.delta : 0))
				* pds.ploop_size / 100;

		vzctl2_log(0, 0, "Start compacting (to free %.0fMB)",
				rate / (1 << 20));
		if (!config.dry) {

			/* store time before compacting */
			gettimeofday(&tv_before, NULL);

			/* compact ploop */
			struct ploop_discard_param param = {};
			param.minlen_b = 0;
			param.to_free = rate;
			param.stop = &stop;
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

			if (config.defrag)
				ploop_defrag(d.disks[j]);

			ploop_compact(&vpses.vpses[vps], d.disks[j]);
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
