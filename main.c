#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

static int ploop_get_dev_and_mnt(const char *disk_descriptor,
				char *dev, int dlen, char *mnt, int mlen)
{
	int ret;
	struct ploop_disk_images_data *di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(disk_descriptor, di)) {
		ploop_free_diskdescriptor(di);
		return -1;
	}

	ret = ploop_get_dev(di, dev, dlen);
	ploop_free_diskdescriptor(di);
	if (ret < 0)
		return -1;

	if (ret == 1) {
		vzctl2_log(-1, 0, "The image isn't mounted");
		return -1;
	}

	if (ploop_get_mnt_by_dev(dev, mnt, mlen)) {
		fprintf(stderr, "Unable to find mount point for %s\n", dev);
		return -1;
	}

	return 0;

}

int ploop_compact(const char *descr)
{
	int err = 0;
	double rate;
	struct ploop_discard_stat pds;
	char device[PATH_MAX];
	char mount_point[PATH_MAX];

	err = ploop_get_dev_and_mnt(descr, device, sizeof(device),
				mount_point, sizeof(mount_point));
	if (err) {
		vzctl2_log(-1, 0, "Can't get parameters of %s", descr);
		return err;
	}

	err = ploop_discard_get_stat(device, mount_point, &pds);
	if (err)
		return err;

	vzctl2_log(1, 0, "Disk: %s", descr);
	vzctl2_log(1, 0, "Data size:    %8ldMB", pds.data_size >> 20);
	vzctl2_log(1, 0, "Ploop size:   %8ldMB", pds.ploop_size >> 20);
	vzctl2_log(1, 0, "Image size:   %8ldMB", pds.image_size >> 20);

	rate = ((double) pds.image_size - pds.data_size) / pds.ploop_size * 100;
	vzctl2_log(0, 0, "Rate: %.1f", rate);

	if (rate > config.threshhold) {
		vzctl2_log(0, 0, "Start compacting");

		rate = (rate - config.threshhold + config.delta) * pds.ploop_size / 100;

		vzctl2_log(0, 0, "To free %.0fMB", rate / (1 << 20));
		if (!config.dry)
			err = ploop_discard(device, mount_point, 0, rate, &stop);
	}

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
	err = vzctl2_conf_get_param(conf, "THRESHOLD", &res);
	if (err)
		goto err;
	config.threshhold = atoi(res);

	err = vzctl2_conf_get_param(conf, "DELTA", &res);
	if (err)
		goto err;
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
		int j;

		vps = (i + pstate) % vpses.num;

		vzctl2_log(0, 0, "Inspect %s", vpses.vpses[vps].uuid);

		err = update_stat_file(vps);
		if (err < 0)
			goto out;

		err = vps_get_disks(vpses.vpses + vps, &d);
		if (err)
			continue;

		for (j = 0; j < d.num; j++) {
			vzctl2_log(0, 0, "Inspect %s", d.disks[j]);
			if (vpses.vpses[vps].type == VPS_CT) {
				err = ploop_compact(d.disks[j]);
				if (err) {
					vps_disk_list_free(&d);
					continue;
				}
			}
		}
		vps_disk_list_free(&d);

		if (config.oneshot)
			break;
	}
out:
	vps_list_free(&vpses);
	return 0;
}

static void usage(char **argv)
{
	vzctl2_log(-1, 0, "Usage: %s [-vns]", argv[0]);
}

int main(int argc, char **argv)
{
	int err, opt;
	static const char short_opts[] = "nvs";
	struct sigaction sa = {
		.sa_handler     = sigint_handler,
		.sa_flags	= SA_RESTART,
	};

	ploop_lib_init();
	vzctl2_lib_init();

	vzctl2_init_log("pcompact");

	err = parse_config();
	if (err < 0) {
		fprintf(stderr, "Can't parse config: %s", COMPACT_CONF);
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

	scan();

	vzctl2_lib_close();

	return 0;
}
