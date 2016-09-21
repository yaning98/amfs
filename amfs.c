
/*
 * Anonymous memory filesystem.
 *
 * Copyright (C) 2009,2012-2015 Teradata Corporation
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
 *
 * This is based on code from ramfs which is
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 *
 */

#include <linux/version.h>

#include <asm/current.h>

#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/shmem_fs.h>  /* shmem_file_setup */

#include <asm/uaccess.h>

#include "amfs_ext.h"

/* Check for AMFS integrated into kernel. */
#ifndef	CONFIG_AMFS

#define AMFS_MAGIC		0x53464d41

typedef struct amfs_inode
amfs_inode_t;

struct amfs_inode {

	struct	inode	inode;

	/* AMFS specific data. */

	/* This lock protects rb tree information. */
	rwlock_t	lock;

	/* File area persistency tracked here. */
	struct {
		struct rb_root	root;
	} persist;

	struct {
		unsigned long	pages;
		unsigned long	**page;
		struct file	*file_p;
		unsigned int	active;
	} backing_store;

	int	sanity_checking;

};

typedef	struct {

	struct rb_node		node;
	amfs_area_t		area;
} amfs_persist_node_t;


typedef struct amfs_super_block
amfs_super_block_t;

struct amfs_super_block {

	rwlock_t		lock;
	char			*backing_store_dir;
	int			backing_store;
	int			sanity_checking;
	struct super_block	*sb;
};

/* used for passing parameters of mount command*/ 
typedef struct {
	char			bs[1024];
	int			bs_state;
	int			fault_check;
} amfs_mnt_opts_t;

/* Internal functions. */
static struct inode	*amfs_alloc_inode(struct super_block *);
static int		amfs_area_compare(struct rb_node *,
						struct rb_node *,
						struct rb_node **);
static void		amfs_area_destroy(struct rb_node *);
static int		amfs_area_merge(struct rb_root *,
					struct rb_node *);
static int		amfs_area_split(struct rb_node *,
					struct rb_node *);
static int		amfs_backing_store(amfs_inode_t *,
						amfs_area_t *, int,
						unsigned long *);
static unsigned int	amfs_backing_store_activate(amfs_inode_t *,
							amfs_area_t *);
static unsigned int	amfs_backing_store_active(amfs_inode_t *,
							amfs_area_t *);
static void		amfs_backing_store_destroy(amfs_inode_t *);
/*static unsigned long	amfs_backing_store_pages(amfs_inode_t *);*/
       int		amfs_cmd(unsigned int, void *, struct file *);

static int		amfs_commit_write(struct file *, struct page *,
					unsigned int, unsigned int);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static int 		amfs_create(struct inode *,struct dentry *, 
					umode_t, bool);
#else
static int		amfs_create(struct inode *, struct dentry *,
					int, struct nameidata *);
#endif
static struct rb_node	*amfs_delete(struct rb_root *,
					struct rb_node *,
					int (*)(struct rb_node *,
						struct rb_node *,
						struct rb_node **),
					void (*)(struct rb_node *),
					int (*)(struct rb_node *,
						struct rb_node *));
static void		amfs_destroy(struct rb_root *,
					void (*)(struct rb_node *));
static void		amfs_destroy_inode(struct inode *);
static int		amfs_fill_super(struct super_block *, void *,
					int);
static struct inode	*amfs_get_inode(struct super_block *,
						const struct inode *, int,
						dev_t);
static int		amfs_insert(struct rb_root *, struct rb_node *,
					struct rb_node **,
					int (*)(struct rb_node *,
						struct rb_node *,
						struct rb_node **),
					int (*)(struct rb_root *,
						struct rb_node *));
static long		amfs_ioctl_internal(struct inode *,
							unsigned int, void *);
static void		amfs_kill_sb(struct super_block *);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static int		amfs_mkdir(struct inode *, struct dentry *, umode_t);

static int		amfs_mknod(struct inode *, struct dentry *,
				umode_t, dev_t);
#else
static int		amfs_mkdir(struct inode *, struct dentry *,
					int);
static int		amfs_mknod(struct inode *, struct dentry *,
					int, dev_t);
#endif
static struct dentry	*amfs_mount(struct file_system_type *, int,
					const char *, void *);
static long		amfs_persistent_pages(amfs_inode_t *, char *,
						unsigned long);
static int		amfs_prepare_write(struct file *,
				struct page *, unsigned int,
				unsigned int);
static int		amfs_readpage(struct file *, struct page *);
static struct rb_node	*amfs_search(struct rb_root *,
					struct rb_node *,
					int (*)(struct rb_node *,
						struct rb_node *,
						struct rb_node **));
static int		amfs_symlink(struct inode *, struct dentry *,
					const char *);
/*static void		amfs_unlink_backing_store(struct file *); */
static long		amfs_unlocked_ioctl(struct file *,
					unsigned int, unsigned long);
static int		amfs_write_begin(struct file *,
					struct address_space *, loff_t,
					unsigned int, unsigned int,
					struct page **, void **);
static int		amfs_write_end(struct file *,
					struct address_space *, loff_t,
					unsigned int, unsigned int,
					struct page *, void *);
static int		amfs_writepage(struct page *,
					struct writeback_control *);
static void __exit	exit_amfs_fs(void);
static int __init	init_amfs_fs(void);


static struct address_space_operations
amfs_ao = {
	.readpage	= amfs_readpage,
	.write_begin	= amfs_write_begin,
	.write_end	= amfs_write_end,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.writepage	= amfs_writepage,
};


static struct backing_dev_info
amfs_bdi = {
	.name		= "amfs",
	.ra_pages	= 0,
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};


static struct file_operations
amfs_fo = {
	.unlocked_ioctl	= amfs_unlocked_ioctl,
	.read		= do_sync_read,
	.aio_read	= generic_file_aio_read,
	.write		= do_sync_write,
	.aio_write	= generic_file_aio_write,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
	.llseek		= generic_file_llseek,
};


static struct file_system_type
amfs_fs = {
	.name		= "amfs",
	.mount		= amfs_mount,
	.kill_sb	= amfs_kill_sb,
};

static struct inode_operations
amfs_ido = {
	.create		= amfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.symlink	= amfs_symlink,
	.mkdir		= amfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= amfs_mknod,
	.rename		= simple_rename,
};


static struct inode_operations
amfs_ifo = {
	.getattr	= simple_getattr,
};


static struct super_operations
amfs_so = {
	.alloc_inode	= amfs_alloc_inode,
	.destroy_inode	= amfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.statfs		= simple_statfs,
};


static struct kmem_cache
*amfs_persist_nodes;

/*static atomic_t
amfs_sanity_checking = ATOMIC_INIT(1);*/

static atomic_t
backing_store = ATOMIC_INIT(0);


static struct inode *
amfs_alloc_inode(struct super_block *sb)
{
	amfs_inode_t		*amfs_inode;
	unsigned long		flags;
	amfs_persist_node_t	*node_data;


	if (!(amfs_inode = kmalloc(sizeof(*amfs_inode), GFP_KERNEL))){
		return(NULL);
	}

	if (!(node_data = kmem_cache_alloc(amfs_persist_nodes, GFP_KERNEL))){
		kfree(amfs_inode);
		return(NULL);
	}

	/* Initialize inode */
	inode_init_once(&amfs_inode->inode);

	rwlock_init(&amfs_inode->lock);

	write_lock_irqsave(&amfs_inode->lock, flags);

	/* Initialize persistency tree. */
	amfs_inode->persist.root = RB_ROOT;

	/* Initialize file backing store. */

	/* By default, there will be no private backing store. */
	amfs_inode->backing_store.pages = 0;
	amfs_inode->backing_store.page = 0;
	amfs_inode->backing_store.file_p = 0;

	/* By default make entire area defined by inode persistent.
	   Initially we want this filesystem to behave the same as ramfs. */
	memset(node_data, 0, sizeof(*node_data));
	node_data->area.offset = 0;
	node_data->area.size = ULONG_MAX;

	if (amfs_insert(&amfs_inode->persist.root, &node_data->node, 0,
			amfs_area_compare, amfs_area_merge)){

		kmem_cache_free(amfs_persist_nodes, node_data);
		write_unlock_irqrestore(&amfs_inode->lock, flags);

		kfree(amfs_inode);
		return(NULL);
	}

	write_unlock_irqrestore(&amfs_inode->lock, flags);

	return (&amfs_inode->inode);
}


static int
amfs_area_compare(struct rb_node *rb_key, struct rb_node *rb_node,
			struct rb_node **best)
{
	amfs_persist_node_t	*key;
	amfs_persist_node_t	*match;
	amfs_persist_node_t	*node;

	key = container_of(rb_key, amfs_persist_node_t, node);
	match = (*best) ? container_of(*best, amfs_persist_node_t, node) : 0;
	node = container_of(rb_node, amfs_persist_node_t, node);

	if (key->area.offset < node->area.offset) {
		if ((key->area.offset + key->area.size) > node->area.offset) {
			match = (match) ?
				((node->area.offset < match->area.offset) ?
					node : match) : node;

			*best = &match->node;
		}
		return -1;
	}

	if (key->area.offset > node->area.offset) {
		if (key->area.offset < (node->area.offset + node->area.size)) {
			match = (match) ?
				((node->area.offset < match->area.offset) ?
					node : match) : node;

			*best = &match->node;
		}

		return 1;
	}

	if (!(key->area.size == node->area.size))
		*best = &node->node;

	return 0;
}


static void
amfs_area_destroy(struct rb_node *rb_node)
{
	amfs_persist_node_t	*node;

	if (!rb_node)
		return;

	node = container_of(rb_node, amfs_persist_node_t, node);

	memset(node, 0, sizeof(*node));
	kmem_cache_free(amfs_persist_nodes, node);
}


static int
amfs_area_merge(struct rb_root *root, struct rb_node *rb_node)
{
	amfs_persist_node_t	*adjacent;
	amfs_persist_node_t	*node;
	struct rb_node		*rb_node_adjacent;

	if (!(root && rb_node))
		return 0;

	node = container_of(rb_node, amfs_persist_node_t, node);

	/* Look at previous node. */
	adjacent = ((rb_node_adjacent = rb_prev(rb_node))) ?
			container_of(rb_node_adjacent, amfs_persist_node_t,
					node) : 0;

	/* Is it adjacent to our node? */
	if (adjacent &&
		((adjacent->area.offset + adjacent->area.size) ==
			node->area.offset)) {
		amfs_persist_node_t     key;

		/* Delete the previous node, and update our node to
		   include previous node's area.                    */
		memset(&key, 0, sizeof(key));
		key.area.offset = adjacent->area.offset;
		key.area.size = adjacent->area.size;

		/* Delete the previous node.  This should never fail. */
		if (amfs_delete(root, &key.node, amfs_area_compare,
			amfs_area_destroy, 0))
			panic("amfs_delete(%p, %p, amfs_area_compare, "
				"amfs_area_destroy, 0) failed!\n",
				root, &key);

		/* Update our node. */
		node->area.offset = key.area.offset;
		node->area.size += key.area.size;

		return -1;
	}

	/* Look at next node. */
	adjacent = ((rb_node_adjacent = rb_next(rb_node))) ?
	         container_of(rb_node_adjacent, amfs_persist_node_t,node) : 0;

	/* Is it adjacent to our node? */
	if (adjacent &&
		((node->area.offset + node->area.size) ==
			adjacent->area.offset)) {
		amfs_persist_node_t     key;

		/* Delete the next node and update our node to
		   include the next node's area.               */
		memset(&key, 0, sizeof(key));
		key.area.offset = adjacent->area.offset;
		key.area.size = adjacent->area.size;

		/* Delete the next node.  This should never fail. */
		if (amfs_delete(root, &key.node, amfs_area_compare,
				amfs_area_destroy, 0))
			panic("amfs_delete(%p, %p, amfs_area_compare, "
				"amfs_area_destroy, 0) failed!\n",
				root, &key);

		/* Update our node. */
		node->area.size += key.area.size;

		return 1;
	}

	return 0;
}


static int
amfs_area_split(struct rb_node *rb_node, struct rb_node *rb_key)
{
	amfs_persist_node_t	*key;
	unsigned long		key_end;
	amfs_persist_node_t	*node;
	unsigned long		node_end;

	if (!(rb_node && rb_key))
		return -1;

	key = container_of(rb_key, amfs_persist_node_t, node);
	node = container_of(rb_node, amfs_persist_node_t, node);

	key_end = key->area.offset + key->area.size;
	node_end = node->area.offset + node->area.size;

	/* Check for completely covered node. */
	if ((!(key->area.offset > node->area.offset) && !(key_end < node_end)))
		return 1;

	/* Check for partially covered node at start of node. */
	if (!(key->area.offset > node->area.offset) && (key_end < node_end)) {
		node->area.offset = key_end;
		node->area.size = node_end - node->area.offset;

		key->area.offset = key_end;
		key->area.size = 0;

		return -1;
	}

	/* Check for partially covered node at end of node. */
	if ((key->area.offset > node->area.offset) && !(key_end < node_end)) {
		node->area.size = key->area.offset - node->area.offset;

		key->area.offset = node_end;
		key->area.size = key_end - node_end;
		return -1;
	}

	/* We have a split node. */
	node->area.size = key->area.offset - node->area.offset;

	key->area.offset += key->area.size;
	key->area.size = node_end - key->area.offset;

	return 0;
}


static int
amfs_backing_store(amfs_inode_t *amfs_inode, amfs_area_t *area_p, int opt,
			unsigned long *data_p)
{
	unsigned int	bit;
	int		bits;
	unsigned long	cur_bits;
	unsigned long	index;
	unsigned long	offset;
	unsigned long	set_bits;
	unsigned long	set_word;
	unsigned long	size;
	unsigned int	word;

	if (!(amfs_inode && area_p && (size = area_p->size))) {
		if (data_p)
			*data_p = 0;
		return 0;
	}

	offset = area_p->offset;

	index = (offset / PAGE_SIZE) /
	         ((PAGE_SIZE / sizeof(unsigned long)) * BITS_PER_LONG);

	if (!(index < amfs_inode->backing_store.pages)) {
		unsigned long	**new;

		if (!(opt > 0)) {
			if (data_p)
				*data_p = 0;

			area_p->offset = offset + area_p->size;
			area_p->size = 0;

			return 0;
		}

		if (!(new = krealloc(amfs_inode->backing_store.page,
				(sizeof(*amfs_inode->backing_store.page) *
				index + 1), GFP_ATOMIC)))
			return -1;

		memset(&new[amfs_inode->backing_store.pages], 0,
			(sizeof(*amfs_inode->backing_store.page) *
			(index + 1)) -
			(sizeof(*amfs_inode->backing_store.page) *
			amfs_inode->backing_store.pages));

		amfs_inode->backing_store.page = new;
		amfs_inode->backing_store.pages = index + 1;
	}

	if (!amfs_inode->backing_store.page[index]) {

		if (!(opt > 0)) {
			if (data_p)
				*data_p = 0;

			area_p->offset = offset + area_p->size;
			area_p->size = 0;

			return 0;
		}

		if (!(amfs_inode->backing_store.page[index] =
			kmalloc(PAGE_SIZE, GFP_ATOMIC)))
			return -1;

		memset(amfs_inode->backing_store.page[index], 0, PAGE_SIZE);
	}

	word = ((offset / PAGE_SIZE) / BITS_PER_LONG) %
		(PAGE_SIZE / sizeof(unsigned long));

	bit = (offset / PAGE_SIZE) % BITS_PER_LONG;
	bits = BITS_PER_LONG -
			(((size / PAGE_SIZE) > BITS_PER_LONG) ?
			BITS_PER_LONG : (size / PAGE_SIZE));

	set_bits = 0xffffffffffffffffUL >> bits;
	set_word = ((set_bits << bit) & 0xffffffffffffffffUL);
	cur_bits = hweight_long(set_word);

	if (opt < 0)
		amfs_inode->backing_store.page[index][word] &= ~set_word;

	if (opt > 0)
		amfs_inode->backing_store.page[index][word] |= set_word;

	area_p->offset = offset + (cur_bits * PAGE_SIZE);
	area_p->size = size - (cur_bits * PAGE_SIZE);

	if (data_p)
		*data_p = (amfs_inode->backing_store.page[index][word] &
		           set_word);
	return (area_p->size) ? 1 : 0;
}


static unsigned int
amfs_backing_store_activate(amfs_inode_t *amfs_inode, 
                                    amfs_area_t *amfs_area_p)
{
	amfs_area_t	area;
	int		ret;

	if (!(amfs_inode && amfs_area_p))
		return 0;

	area = *amfs_area_p;

	while ((ret = amfs_backing_store(amfs_inode, &area, 1, 0)) > 0);

	if (ret)
		return 0;

	return 1;
}
		
static unsigned int
amfs_backing_store_active(amfs_inode_t *amfs_inode, 
                                 amfs_area_t *amfs_area_p)
{
	amfs_area_t	area;
	unsigned long	data = 0;

	if (!(amfs_inode && amfs_area_p))
		return 0;

	area = *amfs_area_p;

	for (;;) {
		unsigned int	ret;

		ret = amfs_backing_store(amfs_inode, &area, 0, &data);

		if (data)
			return 1;

		if (!ret)
			break;
	}

	return 0;
}


static void
amfs_backing_store_destroy(amfs_inode_t *amfs_inode)
{
	unsigned long	i;
	unsigned long	**page;
	unsigned long	pages;

	page = amfs_inode->backing_store.page;
	pages = amfs_inode->backing_store.pages;

	amfs_inode->backing_store.pages = 0;
	amfs_inode->backing_store.page = 0;

	for (i=0; i<pages; i++) {

		if (!page[i])
			continue;

		kfree(page[i]);
		page[i] = 0;
	}
	kfree(page);
}
#if 0
static unsigned long
amfs_backing_store_pages(amfs_inode_t *amfs_inode)
{
	amfs_area_t	area;
	unsigned long	data;
	unsigned long	flags;
	unsigned long	pages = 0;

	if (!amfs_inode)
		return 0;

	area.offset = 0;
	area.size = ULONG_MAX;

	read_lock_irqsave(&amfs_inode->lock, flags);

	for (;;) {
		int	ret;

		ret = amfs_backing_store(amfs_inode, &area, 0, &data);

		pages += hweight_long(data);

		if (!ret)
			break;
	}

	read_unlock_irqrestore(&amfs_inode->lock, flags);

	return pages;
}
#endif

int
amfs_cmd(unsigned int cmd, void *argp, struct file *file)
{
	struct inode	*inode;

	/* Sanity checks. */
	if (!argp)
		return -EINVAL;

	if (!file)
		inode = 0;

	/* Since we could potentially be called with
	   files not controlled by amfs, check this here. */
	if (file && !(file->f_dentry &&
			(inode = file->f_dentry->d_inode) &&
			(inode->i_op == &amfs_ifo) &&
			(inode->i_fop == &amfs_fo)))
		return -EINVAL;
	

	return(amfs_ioctl_internal(inode, cmd, argp));
}
EXPORT_SYMBOL(amfs_cmd);


static int
amfs_commit_write(struct file *file, struct page *page,
			unsigned int offset, unsigned int to)
{
	amfs_inode_t		*amfs_inode;
	struct inode		*file_inode;
	struct file		*file_p;
	struct inode 		*inode;
	unsigned long		flags;
	loff_t			pos;


	/* Sanity checks. */
	if (!(file && page && page->mapping &&
	    (amfs_inode = (amfs_inode_t *)(inode = page->mapping->host)))){
		return(AOP_TRUNCATED_PAGE);
	}

	pos = page_offset(page) + to;

	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (pos > inode->i_size){

		i_size_write(inode, pos);
	}

	read_lock_irqsave(&amfs_inode->lock, flags);

	/* Update backing store file size if present. */
	if (((file_p = amfs_inode->backing_store.file_p) &&
		file_p->f_dentry &&
		(file_inode = file_p->f_dentry->d_inode))){

		read_unlock_irqrestore(&amfs_inode->lock, flags);
		i_size_write(file_inode, pos);
	} else {
		read_unlock_irqrestore(&amfs_inode->lock, flags);
	}

	set_page_dirty(page);
	return(0);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static int
amfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
#else
static int
amfs_create(struct inode *dir, struct dentry *dentry, int mode,
	struct nameidata *nd)
#endif
{
	// printk("AMFS:amfs_create\n");  /* GYN */
	return(amfs_mknod(dir, dentry, (mode | S_IFREG), 0));
}


static struct rb_node *
amfs_delete(struct rb_root *root, struct rb_node *key,
		int (*amfs_node_compare)(struct rb_node *, struct rb_node *,
						struct rb_node **),
		void (*amfs_node_destroy)(struct rb_node *),
		int (*amfs_node_split)(struct rb_node *, struct rb_node *))
{
	struct rb_node	*rb_node;
	struct rb_node	*best_match = 0;

	if (!(root && key && amfs_node_compare && amfs_node_destroy))
		return 0;

	rb_node = root->rb_node;

	while (rb_node) {
		int	compare;

		compare = amfs_node_compare(key, rb_node, &best_match);

		 if (compare < 0)
			rb_node = rb_node->rb_left;

		if (compare > 0)
			 rb_node = rb_node->rb_right;

		if (compare == 0)
			break;
	}

	/* Best match is only set if a partial match was made. */
	if (best_match) {

		/* When amfs_node_split is defined, the passed in
		   key is also a node to insert if best match needs
		   to be split.                                     */
		if (amfs_node_split) {
			int	split;

			if ((split = amfs_node_split(best_match, key)) > 0) {

				/* Node is fully covered.  Delete it. */
				rb_erase(best_match, root);
				amfs_node_destroy(best_match);
			}

			if (!split) {
				/* This insert should never fail. We are
				   splitting an existing node and we never
				   drop our lock.                          */
				if (amfs_insert(root, key, 0,
							amfs_area_compare,
							amfs_area_merge))
					panic("amfs_insert(%p, %p, "
						"amfs_area_compare, "
						"amfs_area_merge) failed!\n",
						root, &key);
				return key;
			}

			return best_match;
		}

		return best_match;
	}
	
	if (rb_node) {

		rb_erase(rb_node, root);
		amfs_node_destroy(rb_node);
	}

	return 0;
}


static void
amfs_destroy(struct rb_root *root, 
             void (*amfs_node_destroy)(struct rb_node *))
{
	struct rb_node	*rb_node;

	if (!(root && amfs_node_destroy))
		return;

	while ((rb_node = rb_first(root))) {
		rb_erase(rb_node, root);
		amfs_node_destroy(rb_node);
	}
}


static void
amfs_destroy_inode(struct inode *inode)
{
	amfs_inode_t		*amfs_inode;
	amfs_super_block_t	*amfs_sb;
	struct file		*file_p;
	unsigned long		flags;

	/* Sanity checks. */
	if (!((amfs_inode = (amfs_inode_t *)inode) &&
		inode->i_sb && (amfs_sb = inode->i_sb->s_fs_info))){

		return;
	}

	write_lock_irqsave(&amfs_inode->lock, flags);

	/* Destroy persistency information. */
	amfs_destroy(&amfs_inode->persist.root, amfs_area_destroy);

	/* Release private backing store. */
	amfs_backing_store_destroy(amfs_inode);

	file_p = amfs_inode->backing_store.file_p;
	amfs_inode->backing_store.file_p = 0;

	write_unlock_irqrestore(&amfs_inode->lock, flags);

	if (!(file_p && file_p->f_dentry)){
		kfree(inode);
		return;
	}

	/* Close the backing store file. */
	filp_close(file_p, 0);

	/* Free memory for amfs file inode. */
	kfree(inode);
}


static int
amfs_fill_super(struct super_block *sb, void *data, int silent)
{
	amfs_inode_t		*amfs_inode;
	amfs_super_block_t	*amfs_sb;
	unsigned long		flags;
	struct inode		*inode;
	amfs_persist_node_t	key;
	struct dentry		*root;
	amfs_mnt_opts_t		*opts = (amfs_mnt_opts_t *)data;


	/* Sanity checks. */
	if (!sb){
		kfree(opts);
		return(-EINVAL);
	}

	/* Get memory for amfs mount private data. */
	if (!(amfs_sb = kmalloc(sizeof(*amfs_sb), GFP_KERNEL))){
		kfree(opts);
		return(-ENOMEM);
	}

	rwlock_init(&amfs_sb->lock);

	/* Get memory for amfs backing store directory name. */
	if (!(amfs_sb->backing_store_dir = 
	      kmalloc(sizeof(amfs_mnt_opts_t) + 1, GFP_KERNEL))){
		kfree(amfs_sb);
		kfree(opts);
		return(-ENOMEM);
	}

	/* By default use backing store and 
	   enable global SIGBUS sanity checking. */
	amfs_sb->backing_store = opts->bs_state;
	amfs_sb->sanity_checking = opts->fault_check;
	amfs_sb->sb = sb;

	strcpy(amfs_sb->backing_store_dir, (char *)opts->bs);
	kfree(opts);    /* no long need */

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_fs_info = amfs_sb;
	sb->s_magic = AMFS_MAGIC;
	sb->s_op = &amfs_so;
	sb->s_time_gran = 1;

	if (!(amfs_inode = (amfs_inode_t *)
		(inode = amfs_get_inode(sb, 0, (S_IFDIR | 0755), 0)))){

		kfree(amfs_sb->backing_store_dir);
		kfree(amfs_sb);
		return(-ENOMEM);
	}

	/* Only regular files need to maintain persistency. */
	memset(&key, 0, sizeof(key));
	key.area.offset = 0;
	key.area.size = ULONG_MAX;

	write_lock_irqsave(&amfs_inode->lock, flags);

	/* Delete default persistency state. Should never fail. */
	if (amfs_delete(&amfs_inode->persist.root, &key.node,
			amfs_area_compare, amfs_area_destroy, 0))
		panic("amfs_delete(%p, %p, amfs_area_compare, "
			"amfs_area_destroy, 0) failed!\n",
			&amfs_inode->persist.root, &key);

	write_unlock_irqrestore(&amfs_inode->lock, flags);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	root = d_make_root(inode);
#else
	root = d_alloc_root(inode)
#endif
	if (!root){

		iput(inode);
		kfree(amfs_sb->backing_store_dir);
		kfree(amfs_sb);
		return(-ENOMEM);
	}

	sb->s_root = root;

	return(0);
}


static struct inode *
amfs_get_inode(struct super_block *sb, const struct inode *dir,
			int mode, dev_t dev)
{
	amfs_inode_t		*amfs_inode;
	struct inode 		*inode;


	/* Sanity checks. */
	if (!(sb && (amfs_inode = (amfs_inode_t *)(inode = new_inode(sb))))){
		return(NULL);
	}

	/* Generic inode initializations. */
	inode->i_ino = get_next_ino();
	inode_init_owner(inode, dir, mode);
	inode->i_mapping->a_ops = &amfs_ao;
	inode->i_mapping->backing_dev_info = &amfs_bdi;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;

	/* Inode type specific initializations. */

	switch (mode & S_IFMT){
	default:
		init_special_inode(inode, mode, dev);
		break;

	case S_IFREG:
		inode->i_op = &amfs_ifo;
		inode->i_fop = &amfs_fo;
		break;

	case S_IFDIR:
		inode->i_op = &amfs_ido;
		inode->i_fop = &simple_dir_operations;

		/* directory inodes start off with i_nlink == 2
		   (for "." entry)                              */
		inc_nlink(inode);
		break;

	case S_IFLNK:
		inode->i_op = &page_symlink_inode_operations;
		break;
	}

	return(inode);
}
/*
 *  Purpose:
 *      This function converts strings in decimal or hex format to integers.
 */
static s32 atoi(char *psz_buf)
{
	char *pch = psz_buf;
	s32 base = 0;

	while (isspace(*pch))
		pch++;

	if (*pch == '-' || *pch == '+') {
		base = 10;
		pch++;
	} else if (*pch && tolower(pch[strlen(pch) - 1]) == 'h') {
		base = 16;
	}

	return simple_strtoul(pch, NULL, base);
}

/*
 * The main option parsing method.  Also makes sure that all of the mandatory
 * mount options were set.
 * amfs_mount options are:
 * bs=<"string">  If "bs" option is NOT specified, dev_name will be used as 
 *                "string".
 *                if "string" == "amfs", backing store file directory "string"
 *                will be "amfs"
 *                else backing store file directory "string" will be 
 *                initialized with "string".
 *
 * bs_state=<integer>  Set initial global backing store state to
 *                     either off (0) or on (1). The default setting 
 *                     will be on (1).
 *
 * fault_check=<integer>  Set initial fault checking state of mount 
 *                        to either panic (-1), no fault checking (0), or 
 *                        send SIGBUS (1). The current default is send 
 *                        SIGBUS (1)
 * Input:
 *    options  - amfs options following the -o option in mount command
 *    dev_name - one of the mount parameter.
 * Output:
 *    opts - parsed options.
 */
static int parse_options(char *options, const char *dev_name, 
                             amfs_mnt_opts_t *opts)
{
	char *token;

	while ((token = strsep((char **)&options, ",")) != NULL) {
		if (!*token) {
			printk("amfs_mount::token is zero\n");
			continue;
		}

		if (strstr(token, "bs=")) {
			strcpy((char *)opts->bs, &token[3]);
			continue;
		} else if (strstr(token, "bs_state=")) {
			opts->bs_state = atoi(&token[9]);
			continue;
		} else if (strstr(token, "fault_check=")) {
			if (!strcmp((char *)&token[12], "-1")) {
				opts->fault_check = -1;
			} else {
				opts->fault_check = atoi(&token[12]);
			}
			continue;
		} else {
			printk("amfs_mount::unsupported command: %s\n", token);
		}
	}

	return 0;

}

static struct dentry *
amfs_mount(struct file_system_type *fs_type, int flags, 
           const char *dev_name, void *data)
{
	amfs_mnt_opts_t *opts;
	int             err;

	opts = kmalloc(sizeof(amfs_mnt_opts_t), GFP_KERNEL);
	printk("size of amfs_mnt_opts_t=%d\n", (int)sizeof(amfs_mnt_opts_t));
	if (opts == NULL) 
		return ERR_PTR(ENOMEM);
	
	/* set default value first */
	strcpy((char *)opts->bs, dev_name);
	opts->bs_state    = 1;
	opts->fault_check = 1;
	
	if ((err = parse_options((char *)data, dev_name, opts)) != 0){
		kfree(opts);
		return ERR_PTR(err);
	}
	printk("amfs_mount::opts.bs=%s\n", opts->bs);
	return mount_nodev(fs_type, flags, (void *)opts, amfs_fill_super);
}


static int
amfs_insert(struct rb_root *root, 
            struct rb_node *node,
            struct rb_node **match_p,
            int (*amfs_node_compare)(struct rb_node *, struct rb_node *,
                  struct rb_node **),
            int (*amfs_node_merge)(struct rb_root *, struct rb_node *))
{
	struct rb_node  **new;
	struct rb_node  *parent = 0;
	struct rb_node  *best_match = 0;

	if (!(root && node && amfs_node_compare)) {
		if (match_p)
			*match_p = 0;

		return 0;
	}

	new = &root->rb_node;

	while (*new) {
		int compare;

		parent = *new;
		compare = amfs_node_compare(node, parent, &best_match);

		if (compare < 0)
			new = &parent->rb_left;

		if (compare > 0)
			new = &parent->rb_right;

		if (compare == 0) {
			best_match = parent;
			break;
		}
	}

	if (best_match) {

		if (match_p)
			*match_p = best_match;

		return 1;
	}

	rb_link_node(node, parent, new);
	rb_insert_color(node, root);

	if (match_p)
		*match_p = node;

	if (amfs_node_merge)
		while (amfs_node_merge(root, node));

	return 0;
}


static long
amfs_ioctl_internal(struct inode *inode, unsigned int cmd, void *argp)
{
	amfs_inode_t		*amfs_inode;
	unsigned int		backing_store_set;
	/*struct file		*file_p;*/
	unsigned long		flags;
	amfs_persist_node_t	node;
	amfs_persist_node_t	*node_p;
	int			sanity_checks_set;

	//printk("amfs_ioctl_internal, cmd=0x%x\n",cmd);
	switch (cmd){

	case	AMFS_IOCTL_BACKING_STORE_ACTIVE:

		backing_store_set = *((unsigned int *)argp);

		/* First check for mount point specific call. */
		if (inode) {
			amfs_super_block_t *amfs_sb;

			if (!(inode->i_sb &&
				(amfs_sb = inode->i_sb->s_fs_info)))
				return -EINVAL;

			amfs_sb->backing_store = (backing_store_set) ? 1 : 0;
			return 0;
		}

		/* This affects all amfs mounted filesystems. */
		if (backing_store_set){

			atomic_set(&backing_store, 1);
		} else {

			atomic_set(&backing_store, 0);
		}
		return 0;

	case	AMFS_IOCTL_FILE_AREA_PERSISTENT:

		if (!(amfs_inode = (amfs_inode_t *)inode))
			return -EINVAL;

		if (!(node_p = kmem_cache_alloc(amfs_persist_nodes,
			(in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL)))
			return -ENOMEM;

		memset(node_p, 0, sizeof(*node_p));
		node_p->area = *((amfs_area_t *)argp);

		if (!(node_p->area.offset <
			(node_p->area.offset + node_p->area.size))) {

			kmem_cache_free(amfs_persist_nodes, node_p);
			return -EINVAL;
		}

		write_lock_irqsave(&amfs_inode->lock, flags);

		if ((amfs_insert(&amfs_inode->persist.root, &node_p->node, 0,
				amfs_area_compare, amfs_area_merge))) {

			/* Free up node if it was not needed. */
			kmem_cache_free(amfs_persist_nodes, node_p);

			write_unlock_irqrestore(&amfs_inode->lock, flags);

			return -EBUSY;
		}

		write_unlock_irqrestore(&amfs_inode->lock, flags);
		return 0;

	case	AMFS_IOCTL_FILE_AREA_VOLATILE:

		if (!(amfs_inode = (amfs_inode_t *)inode))
			return -EINVAL;

		if (!(node_p = kmem_cache_alloc(amfs_persist_nodes,
			(in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL)))
			return -ENOMEM;

		memset(node_p, 0, sizeof(*node_p));
		node_p->area = *((amfs_area_t *)argp);

		if (!(node_p->area.offset < (node_p->area.offset +
						node_p->area.size))) {

			memset(node_p, 0, sizeof(*node_p));
			kmem_cache_free(amfs_persist_nodes, node_p);

			return -EINVAL;
		}

		write_lock_irqsave(&amfs_inode->lock, flags);

		for (;;) {
			struct rb_node *match;

			/* Check for split node.  In this case, our node
			   was used for additional node required.        */
			if ((match = amfs_delete(&amfs_inode->persist.root,
							&node_p->node,
							amfs_area_compare,
							amfs_area_destroy,
							amfs_area_split)) ==
				&node_p->node)
				break;

			/* Check if delete was complete OR our node's area
			   has been completely been accounted for.         */
			if (!(match && node_p->area.size)) {

				/* Complete deletion.  Free our node. */
				memset(node_p, 0, sizeof(*node_p));
				kmem_cache_free(amfs_persist_nodes, node_p);
				break;
			}
		}

		write_unlock_irqrestore(&amfs_inode->lock, flags);

		/* Free up backing store blocks. */
		node.area = *((amfs_area_t *)argp);
		write_lock_irqsave(&amfs_inode->lock, flags);
		while (amfs_backing_store(amfs_inode, &node.area, -1, 0) > 0);
		write_unlock_irqrestore(&amfs_inode->lock, flags);

		return 0;

	case	AMFS_IOCTL_FILE_BACKING_STORE:
		return -EINVAL;

#if 0 /* for now, we don't use it.*/
		if (!(amfs_inode = (amfs_inode_t *)inode))
			return -EINVAL;
		file_p = filp_open((const char *)argp,
			           (O_CREAT | O_EXCL | O_RDWR |
			            O_LARGEFILE | O_TRUNC), 0);

		if (IS_ERR(file_p)){

			return PTR_ERR(file_p);
		}

		/* Now that backing store file is created and open,
		   unlink it.  The file blocks will be freed once
		   the backing store file is closed.               */
		amfs_unlink_backing_store(file_p);

		write_lock_irqsave(&amfs_inode->lock, flags);

		if (amfs_inode->backing_store.file_p){
			struct file *file_orig_p;

			node.area.offset = 0;
			node.area.size = ULONG_MAX;

			/* If backing store is active, it cannot be replaced. */
			if (amfs_backing_store_active(amfs_inode,
							&node.area)){

				write_unlock_irqrestore(&amfs_inode->lock,
							flags);

				filp_close(file_p, 0);
				return -EBUSY;
			}

			file_orig_p = amfs_inode->backing_store.file_p;

			amfs_inode->backing_store.file_p = file_p;
			amfs_backing_store_destroy(amfs_inode);
			amfs_inode->backing_store.active = 1;
			write_unlock_irqrestore(&amfs_inode->lock, flags);

			filp_close(file_orig_p, 0);
		} else {
			amfs_inode->backing_store.file_p = file_p;
			amfs_backing_store_destroy(amfs_inode);
			amfs_inode->backing_store.active = 1;
			write_unlock_irqrestore(&amfs_inode->lock, flags);
		}

		return 0;
#endif

	case	AMFS_IOCTL_FILE_BACKING_STORE_ACTIVE:

		if (!(amfs_inode = (amfs_inode_t *)inode))
			return -EINVAL;

		backing_store_set = *((unsigned int *)argp);

		write_lock_irqsave(&amfs_inode->lock, flags);

		if (!amfs_inode->backing_store.file_p){

			write_unlock_irqrestore(&amfs_inode->lock, flags);
			return -ENODEV;
		}

		if (backing_store_set){

			amfs_inode->backing_store.active = 1;
		} else {

			amfs_inode->backing_store.active = 0;
		}
		write_unlock_irqrestore(&amfs_inode->lock, flags);

		return 0;

	case	AMFS_IOCTL_FILE_SANITY_CHECKS:

		if (!(amfs_inode = (amfs_inode_t *)inode))
			return -EINVAL;

		sanity_checks_set = *((int *)argp);

		amfs_inode->sanity_checking = (!sanity_checks_set) ? 0 :
				((sanity_checks_set > 0) ? 1 : -1);
		return 0;
			
	case	AMFS_IOCTL_SANITY_CHECKS:

		sanity_checks_set = *((int *)argp);

		/* First check for mount point specific call. */
		if (inode) {
			amfs_super_block_t *amfs_sb;

			if (!(inode->i_sb &&
				(amfs_sb = inode->i_sb->s_fs_info)))
				return -EINVAL;

			amfs_sb->sanity_checking = (!sanity_checks_set) ? 0 :
				((sanity_checks_set > 0) ? 1 : -1);

			return 0;
		}
		return -EINVAL;

	default:

		return -EINVAL;
	}

	return -EINVAL;
}


static void
amfs_kill_sb(struct super_block *sb)
{
	amfs_super_block_t	*amfs_sb;

	/* Remove this amfs_sb from being globally visible. */
	if ((amfs_sb = sb->s_fs_info)){
		sb->s_fs_info = 0;
	}

	/* Release super block data. */
	kill_litter_super(sb);

	if (amfs_sb)
		kfree(amfs_sb);
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static int
amfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#else
static int
amfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
#endif
{
	int retval;

	if (!(dir && dentry)){
		return(-ENOSPC);
	}

	if (!(retval = amfs_mknod(dir, dentry, (mode | S_IFDIR), 0))){
		inc_nlink(dir);
	}

	return(retval);
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static int
amfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
#else
static int
amfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
#endif
{
	amfs_inode_t		*amfs_inode;
	amfs_super_block_t	*amfs_sb;
	struct file		*file_p;
	unsigned long		flags;
	struct inode		*inode;
	loff_t 			size;
	
	/* Sanity checks. */
	if (!(dir && dentry &&
		dir->i_sb && (amfs_sb = dir->i_sb->s_fs_info) &&
		(amfs_inode = (amfs_inode_t *)
		    (inode = amfs_get_inode(dir->i_sb, dir, mode, dev))))){
		return(-ENOSPC);
	}

	if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;

		if (S_ISDIR(mode)){
			inode->i_mode |= S_ISGID;
		}
	}

	d_instantiate(dentry, inode);

	/* Up reference count so directory remains. */
	dget(dentry);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

	if (!((mode & S_IFMT) == S_IFREG)){
		unsigned long		flags;
		amfs_persist_node_t	key;

		/* Only regular files need to maintain persistency. */
		memset(&key, 0, sizeof(key));
		key.area.offset = 0;
		key.area.size = ULONG_MAX;

		write_lock_irqsave(&amfs_inode->lock, flags);

		/* Delete default persistency state. Should never fail. */
		if (amfs_delete(&amfs_inode->persist.root, &key.node,
				amfs_area_compare, amfs_area_destroy, 0))
			panic("amfs_delete(%p, %p, amfs_area_compare, "
				"amfs_area_destroy, 0) failed!\n",
				&amfs_inode->persist.root, &key);

		write_unlock_irqrestore(&amfs_inode->lock, flags);

		return(0);
	}


	/* Create backing store file. */
	size = amfs_inode->backing_store.pages << PAGE_SHIFT;
	printk("amfs_mknod:: size=%d\n", (int)size);
	file_p=shmem_file_setup(dentry->d_name.name, size,0);
	
	if (IS_ERR(file_p)){
		return(0);
	}

	write_lock_irqsave(&amfs_inode->lock, flags);

	amfs_inode->backing_store.file_p = file_p;
	amfs_backing_store_destroy(amfs_inode);

	/* Initialize file backing store and sanity checking to active
	   and SIGBUS sanity checking.                                 */
	amfs_inode->backing_store.active = 1;
	amfs_inode->sanity_checking = 1;

	write_unlock_irqrestore(&amfs_inode->lock, flags);

	return(0);
}

static long
amfs_persistent_pages(amfs_inode_t *amfs_inode, char *buffer,
			unsigned long length)
{
	unsigned long   flags;
	struct rb_node  *node;
	unsigned long   offset;

	read_lock_irqsave(&amfs_inode->lock, flags);

	node = rb_first(&amfs_inode->persist.root);
	offset = 0;

	for (; node && ((offset + sizeof(amfs_area_t)) < length);
		node = rb_next(node), offset += sizeof(amfs_area_t)){
		amfs_persist_node_t     *node_data;

		node_data = container_of(node, amfs_persist_node_t, node);

		if (copy_to_user(&buffer[offset], &node_data->area,
					sizeof(amfs_area_t))) {
			read_unlock_irqrestore(&amfs_inode->lock, flags);
			return -EFAULT;
		}
	}
	read_unlock_irqrestore(&amfs_inode->lock, flags);
	return 0;
}


static int
amfs_prepare_write(struct file *file, struct page *page,
			unsigned int from, unsigned int to)
{
	/* Sanity checks. */
	if (!(file && page && (to >= from))){
		return(-EINVAL);
	}

	/* First access to page.  We never care what
	   contents are so just make page up to date. */
	SetPageUptodate(page);

	return(0);
}

static int
amfs_readpage(struct file *file, struct page *page)
{
	amfs_inode_t		*amfs_inode;
	amfs_super_block_t	*amfs_sb;
	struct page		*bs_page;
	struct file		*file_p;
	unsigned long		flags;
	struct inode		*inode;
	struct address_space	*mapping = 0;
	amfs_persist_node_t	node;
	int			sanity_checking;


	/* Sanity checks. */
	if (!(file && (mapping = page->mapping) &&
		(amfs_inode = (amfs_inode_t *)(inode = mapping->host)) &&
		inode->i_sb && (amfs_sb = inode->i_sb->s_fs_info))){
		unlock_page(page);
		return(-EINVAL);
	}

	if (PageUptodate(page)){
		unlock_page(page);
		return(0);
	}

	memset(&node, 0, sizeof(node));

	/* Set up area for this page. */
	node.area.offset = page_offset(page);
	node.area.size = PAGE_CACHE_SIZE;

	/* Check if private backing store is being used.  If
	   so, we need to check if page resides on the private
	   backing store.                                          */
	read_lock_irqsave(&amfs_sb->lock, flags);
	sanity_checking = amfs_sb->sanity_checking;
	read_unlock_irqrestore(&amfs_sb->lock, flags);

	/* First check mount point global sanity checks. */
	if (sanity_checking){
		read_lock_irqsave(&amfs_inode->lock, flags);

		/* Is this part of a persistent area?
		   NOTE: This really should always be true. */
		if (!amfs_search(&amfs_inode->persist.root, &node.node,
					amfs_area_compare)){
			read_unlock_irqrestore(&amfs_inode->lock, flags);

			if (sanity_checking < 0){
				panic("amfs: amfs_readpage(): "
					"file 0x%lx, page 0x%lx, "
					"inode 0x%lx, area 0x%lx\n",
					(unsigned long)file,
					(unsigned long)page,
					(unsigned long)inode,
					(unsigned long)&node.area);

			}

			ClearPageUptodate(page);
			SetPageError(page);
			unlock_page(page);
			return(-EIO);
		}
	} else {

		read_lock_irqsave(&amfs_inode->lock, flags);

		/* File specific sanity checking. */
		if ((sanity_checking = amfs_inode->sanity_checking) &&
			!amfs_search(&amfs_inode->persist.root, &node.node,
					amfs_area_compare)){
			read_unlock_irqrestore(&amfs_inode->lock, flags);

			if (sanity_checking < 0){
				panic("amfs: amfs_readpage(): "
					"file 0x%lx, page 0x%lx, "
					"inode 0x%lx, area 0x%lx\n",
					(unsigned long)file,
					(unsigned long)page,
					(unsigned long)inode,
					(unsigned long)&node.area);
			}

			ClearPageUptodate(page);
			SetPageError(page);
			unlock_page(page);
			return(-EIO);
		}
	}

	/* Getting to this point, means this page is persistent. */

	/* Do we have a page on backing store. */
	if (!((file_p = amfs_inode->backing_store.file_p) &&
		file_p->f_mapping &&
		amfs_backing_store_active(amfs_inode, &node.area))){
		int	err;

		read_unlock_irqrestore(&amfs_inode->lock, flags);
		err = amfs_prepare_write(file, page, 0, 0);
		unlock_page(page);
		return(err);
	}

	read_unlock_irqrestore(&amfs_inode->lock, flags);

	/* We have data on backing store.  Get page cache page
	   associated with this data, copy it to our page cache
	   page and remove the backing store page cache page.     */
	bs_page = read_mapping_page(file_p->f_mapping, page->index, 0);
	if (IS_ERR(bs_page)) {

		ClearPageUptodate(page);
		SetPageError(page);
		unlock_page(page);
		return(-EIO);
	}
	lock_page(bs_page);
	wait_on_page_writeback(bs_page);

	SetPageUptodate(page);
	copy_highpage(page, bs_page);
	set_page_dirty(page);

	unlock_page(page);

	generic_error_remove_page(file_p->f_mapping, bs_page);
	unlock_page(bs_page);
	page_cache_release(bs_page);

	return(0);
}

static struct rb_node *
amfs_search(struct rb_root *rb_root, struct rb_node *key,
		int (*amfs_node_compare)(struct rb_node *, struct rb_node *,
						struct rb_node **))
{
	struct rb_node	*rb_node;
	struct rb_node	*best_match = 0;

	if (!(rb_root && key && amfs_node_compare))
		return 0;

	rb_node = rb_root->rb_node;

	while (rb_node) {
		int compare;

		compare = amfs_node_compare(key, rb_node, &best_match);

		if (compare < 0)
			rb_node = rb_node->rb_left;

		if (compare > 0)
			rb_node = rb_node->rb_right;

		if (compare == 0)
			return rb_node;
	}

	return best_match;
}


static int
amfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	int		error;
	struct inode	*inode;
	int		l;


	if (!(dir && dentry && symname &&
	    (inode = amfs_get_inode(dir->i_sb,dir,(S_IFLNK|S_IRWXUGO),0)))){
		return(-ENOSPC);
	}

	l = strlen(symname)+1;
	if ((error = page_symlink(inode, symname, l))){
		iput(inode);
		return(error);
	}

	if (dir->i_mode & S_ISGID){
		inode->i_gid = dir->i_gid;
	}

	d_instantiate(dentry, inode);
	dget(dentry);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;

	return(0);
}

#if 0   /* no one call it */
static void
amfs_unlink_backing_store(struct file *file_p)
{
	struct dentry		*dir_dentry;
	struct inode		*dir_inode;
	struct dentry		*file_dentry;
	struct inode		*file_inode;


	/* Sanity check. */
	if (!file_p){
		return;
	}

	/* Get reference to dentry and pointer to
	   the inode for backing store file.      */
	file_dentry = dget(file_p->f_dentry);
	file_inode = file_dentry->d_inode;

	/* Get reference to dentry and pointer to
	   the inode for directory containing
	   backing store file.                    */
	dir_dentry = dget_parent(file_dentry);
	dir_inode = dir_dentry->d_inode;

	/* Single thread our changes to the directory. */
	mutex_lock(&dir_inode->i_mutex);

	/* Need to up the reference count for
	   backing store file so vfs_unlink()
	   does not complain.                 */
	atomic_inc(&file_inode->i_count);

	/* Remove entry from directory */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	(void)vfs_unlink(dir_inode, file_dentry, NULL);
#else
	(void)vfs_unlink(dir_inode, file_dentry);
#endif

	/* Release dentry reference for backing store file. */
	dput(file_dentry);

	mutex_unlock(&dir_inode->i_mutex);

	/* Release inode reference for backing store file. */
	iput(file_inode);

	/* Release dentry reference for directory that
	   contained the backing store file.           */
	dput(dir_dentry);

	/* At this point if the backing store file is still open, it
	   becomes an orphaned file.                                 */
}
#endif

static long
amfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void			*argp;
	struct inode		*inode;


	/* Sanity checks. */
	if (!(file && file->f_dentry &&
		(inode = file->f_dentry->d_inode))){

		return(-EINVAL);
	}

	switch (cmd){

	case	AMFS_IOCTL_BACKING_STORE_ACTIVE:
		{
			unsigned int	backing_store_set;

			backing_store_set = arg;

			return(amfs_ioctl_internal(inode, cmd,
					&backing_store_set));
		}
		break;

	case	AMFS_IOCTL_FILE_AREA_PERSISTENT:
	case 	AMFS_IOCTL_FILE_AREA_VOLATILE:
		{
			amfs_area_t	area;

			argp = (void __user *)arg;

			if (copy_from_user(&area, argp, sizeof(area))){

				return(-EFAULT);
			}

			return(amfs_ioctl_internal(inode, cmd, &area));
		}
		break;

	case	AMFS_IOCTL_FILE_BACKING_STORE:
		{
			char	*backing_store_file;
			long	backing_store_file_len;
			long	ret_val;


			argp = (void __user *)arg;
			if (!(backing_store_file_len = strlen_user(argp))){
				return(-EFAULT);
			}
			if (!(backing_store_file = 
			  (char*)kmalloc(backing_store_file_len ,GFP_KERNEL))){
				return(-ENOMEM); 
			}
			if (strncpy_from_user(backing_store_file, argp, 
			                      backing_store_file_len) <= 0){
				return(-EFAULT);
			}

			if (IS_ERR(backing_store_file)){

				return(PTR_ERR(backing_store_file));
			}

			ret_val = amfs_ioctl_internal(inode, cmd,
							backing_store_file);

			kfree(backing_store_file);

			return(ret_val);
		}
		break;

	case	AMFS_IOCTL_FILE_BACKING_STORE_ACTIVE:
		{
			unsigned int	backing_store_set;

			backing_store_set = arg;

			return(amfs_ioctl_internal(inode, cmd,
			                           &backing_store_set));
		}
		break;

	case	AMFS_IOCTL_FILE_SANITY_CHECKS:
	case	AMFS_IOCTL_SANITY_CHECKS:
		{
			int	sanity_checks_set;

			sanity_checks_set = arg;

			return(amfs_ioctl_internal(inode, cmd,
			                           &sanity_checks_set));

		}
		break;

	case	AMFS_IOCTL_PERSISTENT_AREAS:
		{
			amfs_inode_t	*amfs_inode;
			char		*buffer;
			unsigned long	length;

			buffer = (char __user *)arg;

			if (copy_from_user(&length, buffer, sizeof(length))){
				return -EFAULT;
			}

			if (!(amfs_inode = (amfs_inode_t *)inode) ||
				(length < sizeof(length)))
				return -EINVAL;

			return(amfs_persistent_pages(amfs_inode,
					&buffer[sizeof(length)],
					length - sizeof(length)));
		}
		break;

	default:
		return(-EINVAL);
	}

	return(-EINVAL);
}


static int
amfs_write_begin(struct file *file_p, struct address_space *mapping,
		loff_t pos, unsigned int len, unsigned int flags,
		struct page **page_p, void **fs_data_p)
{
	unsigned int	from;
	pgoff_t		index;
	struct page	*page;


	index = (pos >> PAGE_CACHE_SHIFT);
	from = (pos & (PAGE_CACHE_SIZE - 1));

	if (!(page = grab_cache_page_write_begin(mapping, index, flags))){
		return(-ENOMEM);
	}

	*page_p = page;

	return(amfs_prepare_write(file_p, page, from, from + len));
}


static int
amfs_write_end(struct file *file_p, struct address_space *mapping,
		loff_t pos, unsigned int len, unsigned int copied,
		struct page *page, void *fs_data)
{
	unsigned int	from;


	from = (pos & (PAGE_CACHE_SIZE - 1));

	amfs_commit_write(file_p, page, from, from + copied);

	unlock_page(page);
	page_cache_release(page);

	return(copied);
}

static int
amfs_writepage(struct page *page, struct writeback_control *wbc)
{
	amfs_inode_t		*amfs_inode;
	amfs_super_block_t	*amfs_sb;
	int			backing_store;
	struct page		*bs_page;
	struct file		*file_p;
	unsigned long		flags;
	struct inode		*inode;
	struct address_space	*mapping = 0;
	amfs_persist_node_t	node;


	/* Sanity checks. */
	if (!(page && wbc &&
		(mapping = page->mapping) &&
		(amfs_inode = (amfs_inode_t *)(inode = mapping->host)) &&
		inode->i_sb && (amfs_sb = inode->i_sb->s_fs_info))){

		if (page){
			set_page_writeback(page);
			SetPageUptodate(page);
			unlock_page(page);
			end_page_writeback(page);
		}

		return(0);
	}

	/* See if the area this page covers is persistent. */
	memset(&node, 0, sizeof(node));
	node.area.offset = page_offset(page);
	node.area.size = PAGE_SIZE;

	read_lock_irqsave(&amfs_sb->lock, flags);
	backing_store = amfs_sb->backing_store;
	read_unlock_irqrestore(&amfs_sb->lock, flags);

	read_lock_irqsave(&amfs_inode->lock, flags);

	/* Check if area is persistent. */
	if (!amfs_search(&amfs_inode->persist.root, &node.node,
				amfs_area_compare)){

		/* Area is not persistent.  Allow page to be used for
		   something else if necessary.                       */
		read_unlock_irqrestore(&amfs_inode->lock, flags);

		set_page_writeback(page);
		SetPageUptodate(page);
		unlock_page(page);
		end_page_writeback(page);
		return(0);
	}

	/* At this point, we know we have a persistent area. */

	/* Do we have a backing store and are we using it? */
	if (!(backing_store && (file_p = amfs_inode->backing_store.file_p) &&
		wbc->for_reclaim && file_p->f_mapping &&
		amfs_inode->backing_store.active)){

		/* Getting here means we are keeping page in page cache. */
		read_unlock_irqrestore(&amfs_inode->lock, flags);
		set_page_dirty(page);
		unlock_page(page);
		return(0);
	}

	/* We do have a backing store.  Now write it out.  Release
	   lock at this point since the write could take a significant
	   amount of time.                                             */
	read_unlock_irqrestore(&amfs_inode->lock, flags);

	bs_page = grab_cache_page_write_begin(file_p->f_mapping, page->index,
						GFP_KERNEL);
	/* Add page to areas on backing store. */
	write_lock_irqsave(&amfs_inode->lock, flags);

	/* Add page to areas on backing store. */
	if (!(bs_page &&
		amfs_backing_store_activate(amfs_inode, &node.area))) {

		/* Failed to add page to backing store sreas... */
		write_unlock_irqrestore(&amfs_inode->lock, flags);

		if (bs_page) {
			SetPageUptodate(bs_page);
			unlock_page(bs_page);
			page_cache_release(bs_page);
		}
		set_page_dirty(page);
		unlock_page(page);
		return(0);
	}

	write_unlock_irqrestore(&amfs_inode->lock, flags);

	SetPageUptodate(bs_page);
	copy_highpage(bs_page, page);

	set_page_dirty(bs_page);
	unlock_page(bs_page);
	page_cache_release(bs_page);

	SetPageUptodate(page);
	unlock_page(page);
	return(0);
}


static void __exit
exit_amfs_fs(void)
{
	bdi_destroy(&amfs_bdi);
	unregister_filesystem(&amfs_fs);
	kmem_cache_destroy(amfs_persist_nodes);
}


static int __init
init_amfs_fs(void)
{
	int		ret_val;
	printk("AMFS loadable - init_amfs_fs.\n"); /* GYN */
	if (!(amfs_persist_nodes = kmem_cache_create("amfs_persist_nodes",
		sizeof(amfs_persist_node_t), 0, 0, NULL)))
		return -ENOMEM;

	if (!(ret_val = bdi_init(&amfs_bdi))){
		ret_val = register_filesystem(&amfs_fs);

		if (ret_val)
			bdi_destroy(&amfs_bdi);
	}

	if (ret_val)
		kmem_cache_destroy(amfs_persist_nodes);

	return(ret_val);
}


#else	/* CONFIG_AMFS */

static	void __exit	exit_amfs_fs(void);
static	int __init	init_amfs_fs(void);

static void __exit
exit_amfs_fs(void)
{
}

static int __init
init_amfs_fs(void)
{
	printk("AMFS is integrated into the kernel. "
		"AMFS loadable module is NOT used.\n");
	return 0;
}
#endif

module_init(init_amfs_fs)
module_exit(exit_amfs_fs)

MODULE_AUTHOR("Teradata Corporation");
MODULE_DESCRIPTION("Anonymous Memory File System");
MODULE_INFO(supported, "external");
MODULE_LICENSE("GPL");
