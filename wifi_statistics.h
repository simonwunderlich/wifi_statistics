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

#include <linux/module.h>       /* needed by all modules */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/average.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>
#include "compat.h"		/* remove if sending this upstream */

#define WIFI_STATISTICS_DRIVER_AUTHOR	"Simon Wunderlich <siwu@hrz.tu-chemnitz.de>"
#define WIFI_STATISTICS_DRIVER_DESC	"WiFi statistics"
#define WIFI_STATISTICS_DRIVER_DEVICE	"wifi_statistics"
#define WIFI_STATISTICS_SOURCE_VERSION 	"broken"

#define WS_HASH_SIZE		64
#define WS_EWMA_FACTOR		2
#define WS_EWMA_WEIGHT		2

#define NUM_UCAST_TID		IEEE80211_NUM_TIDS
#define BCAST_TID		NUM_UCAST_TID
#define NUM_TIDS		(NUM_UCAST_TID + 1)

struct ws_sta_detailed {
	int last, min, max, count, sum;
	u64 sum_square;
	struct ewma ewma;
};

struct ws_sta {
	u8 mac[ETH_ALEN];
	long unsigned int last_seen;
	u32 rx_packets;
	u64 rx_bytes;
	u32 bad_fcs;
	struct ws_sta_detailed signal;
	s16 last_seqno[NUM_TIDS];
	u8 last_dest[NUM_TIDS][ETH_ALEN];
	struct ws_sta_detailed seqno_diff[NUM_TIDS];
	spinlock_t lock;
	atomic_t refcount;
	struct rcu_head rcu;

	struct hlist_node hash_entry;
};

struct ws_hash {
	struct hlist_head table[WS_HASH_SIZE];
	spinlock_t list_locks[WS_HASH_SIZE];
};

/* hash */
int ws_hash_init(void);
int ws_hash_free(void);
struct ws_sta *ws_hash_get(u8 *mac);
extern struct ws_hash ws_hash;

/* station */
void ws_sta_free_ref(struct ws_sta *ws_sta);
void ws_sta_init(struct ws_sta *ws_sta);
int ws_sta_parse_ieee80211_hdr(struct ws_sta *ws_sta,
			       struct ieee80211_hdr *hdr, int len);
int ws_sta_parse_radiotap(struct ws_sta *ws_sta,
			  struct ieee80211_radiotap_header *rthdr, int len);
int ws_sta_seq_print(struct ws_sta *ws_sta, struct seq_file *seq, void *offset);

/* debugfs */
enum ws_mode {
	MODE_READ,
	MODE_RESET,
};

extern enum ws_mode ws_mode;

void ws_debugfs_init(void);
void ws_debugfs_destroy(void);
