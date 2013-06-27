/*
 * Copyright (C) 2013:
 *	Simon Wunderlich <siwu@hrz.tu-chemnitz.de>
 *	Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
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

static inline u32 cfg80211_calculate_bitrate(struct rate_info *rate)
{
	int modulation, streams, bitrate;

	if (!(rate->flags & RATE_INFO_FLAGS_MCS))
		return rate->legacy;

	/* the formula below does only work for MCS values smaller than 32 */
	if (WARN_ON_ONCE(rate->mcs >= 32))
		return 0;

	modulation = rate->mcs & 7;
	streams = (rate->mcs >> 3) + 1;

	bitrate = (rate->flags & RATE_INFO_FLAGS_40_MHZ_WIDTH) ?
			13500000 : 6500000;

	if (modulation < 4)
		bitrate *= (modulation + 1);
	else if (modulation == 4)
		bitrate *= (modulation + 2);
	else
		bitrate *= (modulation + 3);

	bitrate *= streams;

	if (rate->flags & RATE_INFO_FLAGS_SHORT_GI)
		bitrate = (bitrate / 9) * 10;

	/* do NOT round down here */
	return (bitrate + 50000) / 100000;
}

#endif /* < KERNEL_VERSION(3, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
/**
 * eth_zero_addr - Assign zero address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Assign the zero address to the given address array.
 */
static inline void eth_zero_addr(u8 *addr)
{
	memset(addr, 0x00, ETH_ALEN);
}
#endif /* < KERNEL_VERSION(3, 7, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)

#ifndef hlist_entry_safe
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
		____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#endif

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member) \
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	pos; \
	pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member) \
	for (pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
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

