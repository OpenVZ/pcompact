#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <yajl/yajl_parse.h>

#include <vzctl/libvzctl.h>
#include "parser.h"

static char key[128];
static int hdd_section;
static int autocompact_disabled;

static int yajl_map_key(void *ctx, const unsigned char *stringVal,
							unsigned int stringLen)
{
	if (stringLen + 1 > sizeof(key))
		return 0;

	key[stringLen] = 0;
	memcpy(key, stringVal, stringLen);

	return 1;
}

static int list_yajl_string(void *ctx, const unsigned char * stringVal,
							unsigned int stringLen)
{
	struct vps_list *l = (struct vps_list *) ctx;

	if (!strcmp(key, "uuid")) {
		if (stringLen > sizeof(l->vpses[l->num].uuid))
			return 0;
		memcpy(l->vpses[l->num].uuid, stringVal, stringLen);
		return 1;
	}

	if (!strcmp(key, "type")) {
		if (!strncmp("CT", stringVal, stringLen))
			l->vpses[l->num].type = VPS_CT;
		else if (!strncmp("VM", stringVal, stringLen))
			l->vpses[l->num].type = VPS_VM;
		else {
			vzctl2_log(-1, 0, "Unknow type: %.*s", stringLen, stringVal);
			return -1;
		}
	}

	if (!strcmp(key, "status")) {
		if (!strncmp("running", stringVal, stringLen))
			l->vpses[l->num].status = VPS_RUNNING;
		else if (!strncmp("mounted", stringVal, stringLen))
			l->vpses[l->num].status = VPS_MOUNTED;
	}

	key[0] = '\0';

	return 1;
}

static int list_yajl_start_map(void * ctx)
{
	struct vps_list *l = (struct vps_list *) ctx;

	if (l->size < (l->num + 1) * sizeof(struct vps)) {
		int size = l->size + 4096;
		void *p = realloc(l->vpses, size);
		if (p == NULL) {
			vzctl2_log(-1, ENOMEM, "Not enought memory");
			return -1;
		}
		l->vpses = p;
		l->size = size;
	}

	memset(l->vpses + l->num, 0, sizeof(struct vps));

	return 1;
}

static int list_yajl_end_map(void * ctx)
{
	struct vps_list *l = (struct vps_list *) ctx;

	l->num++;
	return 1;
}

static int disk_yajl_start_map(void * ctx)
{
	/* new entry */
	if (!strncmp(key, "ID", 2))
		autocompact_disabled = 0;
	else if (!strncmp(key, "hdd", 3))
		hdd_section = 1;
	return 1;
}

static int disk_yajl_end_map(void * ctx)
{
	hdd_section = 0;
	return 1;
}

static int add_disk_entry(struct vps_disk_list *l, const char *stringVal,
		unsigned int stringLen)
{
	const char ddxml[] = "/DiskDescriptor.xml";

	if (l->size < (l->num + 1) * sizeof(char *)) {
		int size = l->size + 4096;
		void *p = realloc(l->disks, size);
		if (p == NULL) {
			vzctl2_log(-1, ENOMEM, "Not enought memory");
			return -1;
		}
		l->disks = p;
		l->size = size;
	}

	l->disks[l->num] = malloc(stringLen + 1 + strlen(ddxml));
	if (l->disks[l->num] == NULL) {
		vzctl2_log(-1, ENOMEM, "Not enought memory");
		return -1;
	}
	l->disks[l->num][stringLen + strlen(ddxml)] = '\0';
	memcpy(l->disks[l->num], stringVal, stringLen);
	memcpy(l->disks[l->num] + stringLen, ddxml, sizeof(ddxml));

	l->num++;

	return 1;
}

static int disk_yajl_string(void *ctx, const unsigned char *stringVal,
		unsigned int stringLen)
{
	struct vps_disk_list *l = (struct vps_disk_list *) ctx;

	if (!strcmp(key, "Autocompact")) {
		autocompact_disabled = (strncmp(stringVal, "off", stringLen) == 0);
	} else if (!autocompact_disabled && hdd_section) {
		if (!strcmp(key, "image")) {
			return add_disk_entry(l, stringVal, stringLen);
		} else if (!strcmp(key, "autocompact") && strncmp(stringVal, "off", stringLen)) {
			/* logic based on strict order 'image,autocompact' */
			free(l->disks[--l->num]);
			l->disks[l->num] = NULL;
		}
	}

	key[0] = '\0';

	return 1;
}

static int parse_command(char *const argv[], yajl_callbacks *callbacks, void *ctx)
{
	int output[2], ret, exit_code = -1, status;
	pid_t pid;
	char buf[4096];
	int size;
	yajl_handle hand;
	yajl_status stat;

	hand = yajl_alloc(callbacks, NULL, NULL, ctx);
	if (hand == NULL) {
		vzctl2_log(-1, ENOMEM, "Not enough memory");
		return -1;
	}

	ret = pipe(output);
	if (ret)
		goto free;

	pid = fork();
	if (pid < 0)
		goto free;

	if (pid == 0) {
		close(output[0]);
		dup2(output[1], 1);
		execvp(argv[0], argv);
	}

	close(output[1]);

	while (1) {
		size = read(output[0], buf, sizeof(buf));
		if (size < 0) {
			vzctl2_log(-1, errno, "read() failed");
			goto wait;
		}
		if (size == 0)
			break;

		stat = yajl_parse(hand, buf, size);
		if (stat != yajl_status_ok && stat != yajl_status_insufficient_data)
			break;
	}

	if (stat == yajl_status_ok)
		stat = yajl_parse_complete(hand);

	if (stat != yajl_status_ok) {
		unsigned char * str = yajl_get_error(hand, 0, buf, size);
		vzctl2_log(-1, 0, "%s", (char *) str);
		yajl_free_error(hand, str);
		goto wait;
	}

	exit_code = 0;
wait:
	pid = waitpid(pid, &status, 0);
	if (pid == -1) {
		perror("wait failed");
		exit_code = -11;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "prlctl return non-zero code %d\n", status);
		exit_code = -11;
	}
free:
	yajl_free(hand);

	return exit_code;
}

int vps_get_list(struct vps_list *l)
{
	int ret;
	yajl_callbacks callbacks = {
					.yajl_map_key	= yajl_map_key,
					.yajl_string	= list_yajl_string,
					.yajl_start_map	= list_yajl_start_map,
					.yajl_end_map	= list_yajl_end_map,
				};
	char *argv[] = {"prlctl", "list", "-aj", "--vmtype=ct", NULL};

	l->num = 0;
	l->size = 0;
	l->vpses = NULL;

	ret = parse_command(argv, &callbacks, l);
	if (ret) {
		vzctl2_log(-1, 0, "Failed to get Containers list");
		vps_list_free(l);
	}
	return ret;
}

int vps_get_disks(struct vps *vps, struct vps_disk_list *l)
{
	int ret;
	yajl_callbacks callbacks = {
					.yajl_map_key	= yajl_map_key,
					.yajl_string	= disk_yajl_string,
					.yajl_start_map	= disk_yajl_start_map,
					.yajl_end_map	= disk_yajl_end_map,
				};
	char *argv[] = {"prlctl", "list", "-iHj", vps->uuid, NULL};

	l->num = 0;
	l->size = 0;
	l->disks = NULL;

	ret = parse_command(argv, &callbacks, l);
	if (ret) {
		vzctl2_log(-1, 0, "Failed to get Container %s disks list",
				vps->uuid);
		vps_disk_list_free(l);
	}
	return ret;
}

void vps_list_free(struct vps_list *l)
{
	free(l->vpses);
}

void vps_disk_list_free(struct vps_disk_list *l)
{
	int i;

	for (i = 0; i < l->num; i++)
		free(l->disks[i]);
	free(l->disks);
}

#ifdef MAIN
int main(int argc, char **argv)
{
	int i, ret;
	struct vps_list list;

	vzctl2_lib_init();
	vzctl2_init_log("parser");
	vzctl2_set_log_enable(1);
	vzctl2_set_log_quiet(0);
	vzctl2_set_log_verbose(5);

	ret = vps_get_list(&list);
	if (ret)
		return 1;

	for (i = 0; i < list.num; i++) {
		struct vps_disk_list disk_list;
		int j;
		printf("%s %d\n", list.vpses[i].uuid, list.vpses[i].type);
		vps_get_disks(list.vpses + i, &disk_list);
		for (j = 0; j < disk_list.num; j++)
			printf("%s\n", disk_list.disks[j]);
		vps_disk_list_free(&disk_list);
	}

	vps_list_free(&list);

	return 0;
}
#endif
