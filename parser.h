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

#define VPS_UUID_SIZE 36
struct vps {
	char uuid[VPS_UUID_SIZE];
	char eof;
	unsigned type;
	enum status status;
};

struct vps_list {
	struct vps *vpses;
	int size;
	int num;
};

extern int vps_get_list(struct vps_list *l);
extern void vps_list_free(struct vps_list *l);

#endif
