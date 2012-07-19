#ifndef __VZCOM_PARSER__
#define __VZCOM_PARSER__

enum {
	VPS_VM,
	VPS_CT,
};

enum status {
	VPS_STOPPED = 0,
	VPS_RUNNING,
	VPS_MOUNTED,
};

#define VPS_NANE_SIZE 36
struct vps {
	char uuid[VPS_NANE_SIZE];
	char eof;
	unsigned type;
	enum status status;
};

struct vps_list {
	struct vps *vpses;
	int size;
	int num;
};
struct vps_disk_list {
	char **disks;
	int size;
	int num;
};

extern int vps_get_list(struct vps_list *l);
extern void vps_list_free(struct vps_list *l);
extern int vps_get_disks(struct vps *vps, struct vps_disk_list *l);
extern void vps_disk_list_free(struct vps_disk_list *l);

#endif
