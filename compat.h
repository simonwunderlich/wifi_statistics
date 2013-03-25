/* 
 * Copyright (C) 2013 Simon Wunderlich <siwu@hrz.tu-chemnitz.de>
 * Copyright (C) 2013 Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/version.h>	/* LINUX_VERSION_CODE */

#ifndef IEEE80211_NUM_TIDS
#define IEEE80211_NUM_TIDS	16
#endif /*IEEE80211_NUM_TIDS */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
static inline int debug_open(struct inode *inode, struct file *file)
{
       file->private_data = inode->i_private;
       return 0;
}

#define simple_open	debug_open
#endif /* < KERNEL_VERSION(3, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)

#ifndef hlist_entry_safe
#define hlist_entry_safe(ptr, type, member) \
	(ptr) ? hlist_entry(ptr, type, member) : NULL
#endif

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	pos; \
	pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member) \
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
	typeof(*(pos)), member); \
	pos; \
	pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
	&(pos)->member)), typeof(*(pos)), member))

#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	pos && ({ n = pos->member.next; 1; }); \
	pos = hlist_entry_safe(n, typeof(*pos), member))

#endif /* < KERNEL_VERSION(3, 9, 0) */

