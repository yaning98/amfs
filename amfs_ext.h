#ifndef	__AMFS_EXT_H__
#define	__AMFS_EXT_H__


/*
 * Copyright (C) 2009,2015 Teradata Corporation
 *
 * This software is licensed: (i) under the terms of Version 2
 * (June, 1991) of the GNU General Public License as published
 * by the Free Software Foundation (see the file "COPYING" in
 * the main directory of this package for the specific terms of
 * the foregoing license), and (ii) WITHOUT WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, AND NON-INFRINGEMENT.
 *
 */

#include <linux/fs.h>
#include <linux/ioctl.h>


typedef	struct {
	unsigned long	offset;
	unsigned long	size;
} amfs_area_t;


#define	AMFS_IOCTL_BACKING_STORE_ACTIVE		_IOW('A', 0, unsigned int)
#define	AMFS_IOCTL_FILE_AREA_PERSISTENT		_IOW('A', 1, amfs_area_t)
#define	AMFS_IOCTL_FILE_AREA_VOLATILE		_IOW('A', 2, amfs_area_t)
#define	AMFS_IOCTL_FILE_BACKING_STORE		_IOW('A', 4, char *)
#define	AMFS_IOCTL_FILE_BACKING_STORE_ACTIVE	_IOW('A', 5, unsigned int)
#define	AMFS_IOCTL_LOG_ACTIVE			_IOW('A', 6, unsigned int)
#define	AMFS_IOCTL_PERSISTENT_AREAS		_IOWR('A', 7, unsigned long *)
#define	AMFS_IOCTL_SANITY_CHECKS		_IOW('A', 8, int)
#define	AMFS_IOCTL_FILE_SANITY_CHECKS		_IOW('A', 9, int)


#ifdef __KERNEL__

extern	int	amfs_cmd(unsigned int, void *, struct file *);

#endif	/* __KERNEL__ */
#endif	/* __AMFS_EXT_H__ */
