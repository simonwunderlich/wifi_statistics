/*
 * Copyright (C) 2013:
 *	Simon Wunderlich <sw@simonwunderlich.de>
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

#include "wifi_statistics.h"

/* function prototypes and related defs are in include/net/cfg80211.h
 * This is a copy of the definition from radiotap.c for older kernels.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
static const struct radiotap_align_size rtap_namespace_sizes[] = {
	[IEEE80211_RADIOTAP_TSFT] = { .align = 8, .size = 8, },
	[IEEE80211_RADIOTAP_FLAGS] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RATE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_CHANNEL] = { .align = 2, .size = 4, },
	[IEEE80211_RADIOTAP_FHSS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DBM_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_LOCK_QUALITY] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_DBM_TX_POWER] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_ANTENNA] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTSIGNAL] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DB_ANTNOISE] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_RX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_TX_FLAGS] = { .align = 2, .size = 2, },
	[IEEE80211_RADIOTAP_RTS_RETRIES] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_DATA_RETRIES] = { .align = 1, .size = 1, },
	[IEEE80211_RADIOTAP_MCS] = { .align = 1, .size = 3, },
	[IEEE80211_RADIOTAP_AMPDU_STATUS] = { .align = 4, .size = 8, },
	[IEEE80211_RADIOTAP_VHT] = { .align = 2, .size = 12, },
	/*
	 * add more here as they are defined in radiotap.h
	 */
};

static const struct ieee80211_radiotap_namespace radiotap_ns = {
	.n_bits = ARRAY_SIZE(rtap_namespace_sizes),
	.align_size = rtap_namespace_sizes,
};
#endif


void ws_sta_free_ref(struct ws_sta *ws_sta)
{
	if (atomic_dec_and_test(&ws_sta->refcount))
		kfree_rcu(ws_sta, rcu);
}

void ws_sta_init_detail(struct ws_sta_detailed *detail)
{
	detail->min = INT_MAX;
	detail->max = INT_MIN;
	ewma_ewma_init(&detail->ewma);
}

void ws_sta_init(struct ws_sta *ws_sta)
{
	int i;

	for (i = 0; i < NUM_TIDS; i++) {
		ws_sta->last_seqno[i] = -1;
		eth_zero_addr(ws_sta->last_dest[i]);
		ws_sta_init_detail(&ws_sta->seqno_diff[i]);
	}

	ws_sta_init_detail(&ws_sta->signal);
	ws_sta_init_detail(&ws_sta->interval);
	ws_sta_init_detail(&ws_sta->rate);
}

static void ws_sta_print_detail(struct seq_file *seq,
				struct ws_sta_detailed *detail,
				char *tabs)
{
	seq_printf(seq, "\n%s{\n", tabs);
	seq_printf(seq, "%s\t\"last\": %d,\n", tabs, detail->last);
	seq_printf(seq, "%s\t\"min\": %d,\n", tabs, detail->min);
	seq_printf(seq, "%s\t\"max\": %d,\n", tabs, detail->max);
	seq_printf(seq, "%s\t\"count\": %d,\n", tabs, detail->count);
	seq_printf(seq, "%s\t\"sum\": %d,\n", tabs, detail->sum);
	seq_printf(seq, "%s\t\"sum_square\": %llu,\n", tabs,
		   detail->sum_square);
	seq_printf(seq, "%s\t\"ewma\": %d\n", tabs,
		   (int)(ewma_ewma_read(&detail->ewma) - (INT_MAX>>2)));
	seq_printf(seq, "%s}", tabs);
}

char *ws_sta_get_type(enum ws_sta_type type)
{
	switch (type) {
	case WS_TYPE_AP:
		return "Access Point";
	case WS_TYPE_CLIENT:
		return "Client";
	case WS_TYPE_IBSS:
		return "Ad-Hoc";
	default:
	case WS_TYPE_UNKNOWN:
		return "unknown";
	}
}

int ws_sta_seq_print_head(struct seq_file *seq)
{
	seq_puts(seq, "{\n\"stations\": [");
	return 0;
}

int ws_sta_seq_print_tail(struct seq_file *seq)
{
	seq_puts(seq, "\n\t]\n}\n");
	return 0;
}

int ws_sta_seq_print(struct ws_sta *ws_sta, struct seq_file *seq, void *offset)
{
	bool first = true;
	int i;

	seq_puts(seq, "\n\t{\n");
	seq_printf(seq, "\t\"mac\":\"%pM\",\n", ws_sta->mac);
	seq_puts(seq, "\t\"signal\": ");
	ws_sta_print_detail(seq, &ws_sta->signal, "\t");
	seq_puts(seq, ",\n");
	seq_puts(seq, "\t\"rate (100 kbps)\": ");
	ws_sta_print_detail(seq, &ws_sta->rate, "\t");
	seq_puts(seq, ",\n");
	seq_printf(seq, "\t\"bad fcs packets\": %d,\n", ws_sta->bad_fcs);
	seq_printf(seq, "\t\"total packets\": %d,\n", ws_sta->rx_packets);
	seq_printf(seq, "\t\"total bytes\": %llu,\n", ws_sta->rx_bytes);
	seq_printf(seq, "\t\"last seen (msec)\": %d,\n",
		   jiffies_to_msecs(jiffies - ws_sta->last_seen));
	if (ws_sta->interval.count > 0) {
		seq_puts(seq, "\t\"packet interval\": ");
		ws_sta_print_detail(seq, &ws_sta->interval, "\t");
		seq_puts(seq, ",\n");
	}
	seq_printf(seq, "\t\"BSSID\": \"%pM\",\n", ws_sta->bssid);
	seq_printf(seq, "\t\"type\": \"%s\",\n", ws_sta_get_type(ws_sta->type));
	seq_puts(seq, "\t\"seqno\": [\n");
	for (i = 0; i < NUM_TIDS; i++) {
		if (ws_sta->last_seqno[i] < 0)
			continue;
		if (!first)
			seq_puts(seq, ",\n");
		seq_puts(seq, "\t\t{\n");
		seq_printf(seq, "\t\t\t\"tid\": %d,\n", i);
		seq_printf(seq, "\t\t\t\"last seqno\": %d",
			   ws_sta->last_seqno[i]);
		if (ws_sta->seqno_diff[i].count > 0)  {
			seq_puts(seq, ",\n\t\t\t\"difference\": ");
			ws_sta_print_detail(seq, &ws_sta->seqno_diff[i],
					    "\t\t\t");
		}
		first = false;
		seq_puts(seq, "\n\t\t}");
	}
	seq_puts(seq, "\n\t\t]\n");
	seq_puts(seq, "\n\t}");
	return 0;
}

static void ws_sta_detailed_apply(struct ws_sta_detailed *detail, int value)
{
	detail->last = value;
	detail->min = min_t(int, value, detail->min);
	detail->max = max_t(int, value, detail->max);
	detail->count++;
	detail->sum += value;
	detail->sum_square += ((u64) value) * ((u64) value);
	ewma_ewma_add(&detail->ewma, value + (INT_MAX>>2));
}

int ws_sta_general(struct ws_sta *ws_sta, struct sk_buff *skb)
{
	int interval;

	if (ws_sta->rx_packets > 0) {
		interval = (int) (jiffies - ws_sta->last_seen);
		ws_sta_detailed_apply(&ws_sta->interval, interval);
	}
	ws_sta->last_seen = jiffies;
	ws_sta->rx_packets++;
	ws_sta->rx_bytes += skb->len;
	return 0;
}

int ws_sta_parse_ieee80211_hdr(struct ws_sta *ws_sta,
			       struct ieee80211_hdr *hdr, int len)
{
	int tid = 0;
	int seqno;
	bool is_data, is_mgmt;
	u8 *dest;


	is_data = ieee80211_is_data(hdr->frame_control);
	is_mgmt = ieee80211_is_mgmt(hdr->frame_control);

	/* only care about data and management frames for now ... */
	if (!is_data && !is_mgmt)
		return 0;


	if (is_mgmt) {
		/* bssid is always at addr3 for management frames. */
		memcpy(ws_sta->bssid, hdr->addr3, ETH_ALEN);
		/* TODO we could derive the type here too, for example
		 * by looking into beacon frames. */
	} else if (is_data) {
		switch (hdr->frame_control &
			(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
			case 0:
				/* APs also emit these type of frames */
				if (ws_sta->type != WS_TYPE_AP)
					ws_sta->type = WS_TYPE_IBSS;
				memcpy(ws_sta->bssid, hdr->addr3, ETH_ALEN);
				break;
			case IEEE80211_FCTL_FROMDS:
				ws_sta->type = WS_TYPE_AP;
				memcpy(ws_sta->bssid, hdr->addr2, ETH_ALEN);
				break;
			case IEEE80211_FCTL_TODS:
				ws_sta->type = WS_TYPE_CLIENT;
				memcpy(ws_sta->bssid, hdr->addr1, ETH_ALEN);
				break;
			default:
			case (IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS):
				/* no IBSS known, and device might act as an AP
				 * or station at the same time. just leave it.
				 */
				break;
		}
	}

	/* Find out the TID if it's an individually adressed QoS data frame,
	 * otherwise use the "general" counter for all other frames
	 * (multicasts, beacons, etc) which is called BCAST_TID here.
	 *
	 * see 802.11-2012 9.3.2.10 Duplicate detection and recovery
	 * for details.
	 */
	dest = hdr->addr1;
	if (is_multicast_ether_addr(dest)) {
		tid = BCAST_TID;
	} else if (ieee80211_is_data_qos(hdr->frame_control)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);
		tid = *qc & IEEE80211_QOS_CTL_TID_MASK;
	} else {
		tid = BCAST_TID;
	}

	/* Keeping track of all destinations of any station appears
	 * to be unreasonable overhead. Therefore, we use a best
	 * effort approach here and only track seqno differences
	 * if the destination is the same as last time on this TID.
	 */
	seqno = le16_to_cpu(hdr->seq_ctrl) >> 4;
	if (memcmp(ws_sta->last_dest[tid], dest, ETH_ALEN) == 0) {
		int diff;

		diff = (seqno - ws_sta->last_seqno[tid] + (1 << 12));
		diff %= (1 << 12);

		/* jumped backwards? */
		if (diff > (1 << 11))
			diff -= 1 << 12;

		ws_sta_detailed_apply(&ws_sta->seqno_diff[tid], diff);
	}

	memcpy(ws_sta->last_dest[tid], dest, ETH_ALEN);
	ws_sta->last_seqno[tid] = seqno;

	return 0;
}

int ws_sta_parse_radiotap(struct ws_sta *ws_sta,
			  struct ieee80211_radiotap_header *rthdr, int len)
{
	struct ieee80211_radiotap_iterator iterator;
	int ret;

	ret = ieee80211_radiotap_iterator_init(&iterator, rthdr, len, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	/* Overwrite the namespace with one that includes the VHT field. */
	iterator.current_namespace = &radiotap_ns;
#endif

	while (!ret) {
		ret = ieee80211_radiotap_iterator_next(&iterator);

		if (ret)
			continue;

		switch (iterator.this_arg_index) {
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: {
			ws_sta_detailed_apply(&ws_sta->signal,
					      (s8)*iterator.this_arg);
			break;
		}
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iterator.this_arg & (IEEE80211_RADIOTAP_F_BADFCS))
				ws_sta->bad_fcs++;
			break;
		case IEEE80211_RADIOTAP_RATE:
			ws_sta_detailed_apply(&ws_sta->rate,
					      ((u8)*iterator.this_arg) * 5);
			break;
		case IEEE80211_RADIOTAP_MCS: {
			/* 0 = mcs_details
			 * 1 = flags
			 * 2 = rate-index;
			 */
			u8 flags = *(iterator.this_arg + 1);
			u8 mcs_index = *(iterator.this_arg + 2);
			struct rate_info rate;
			int bitrate;

			rate.flags = 0;

			if (flags & IEEE80211_RADIOTAP_MCS_BW_40)
				rate.bw = RATE_INFO_BW_40;

			rate.mcs = mcs_index;
			rate.flags |= RATE_INFO_FLAGS_MCS;

			if (flags & IEEE80211_RADIOTAP_MCS_SGI)
				rate.flags |= RATE_INFO_FLAGS_SHORT_GI;

			bitrate = cfg80211_calculate_bitrate(&rate);
			/* might return 0 for MCS >= 32 */
			if (bitrate)
				ws_sta_detailed_apply(&ws_sta->rate, bitrate);
			break;
		}
		case IEEE80211_RADIOTAP_VHT: {
			u8 flags = *(iterator.this_arg + 2);
			u8 bandwidth = *(iterator.this_arg + 3);
			u8 mcs_nss = *(iterator.this_arg + 4);
			struct rate_info rate;
			int bitrate;

			rate.flags = RATE_INFO_FLAGS_VHT_MCS;
			if (flags & IEEE80211_RADIOTAP_VHT_FLAG_SGI)
				rate.flags |= RATE_INFO_FLAGS_SHORT_GI;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
			if (bandwidth == 1)
				rate.flags |= RATE_INFO_FLAGS_40_MHZ_WIDTH;
			else if (bandwidth == 4)
				rate.flags |= RATE_INFO_FLAGS_80_MHZ_WIDTH;
			else if (bandwidth == 11)
				rate.flags |= RATE_INFO_FLAGS_160_MHZ_WIDTH;
#else
			rate.bw = RATE_INFO_BW_20;
			if (bandwidth == 1)
				rate.bw = RATE_INFO_BW_40;
			else if (bandwidth == 4)
				rate.bw = RATE_INFO_BW_80;
			else if (bandwidth == 11)
				rate.bw = RATE_INFO_BW_160;
#endif

			rate.mcs = mcs_nss >> 4 & 0xf;
			rate.nss = mcs_nss & 0xf;

			bitrate = cfg80211_calculate_bitrate(&rate);
			/* might return 0 for MCS >= 32 */
			if (bitrate)
				ws_sta_detailed_apply(&ws_sta->rate, bitrate);
			break;
		}
		default:
			break;
		}
	}

	/* we did not stop because we parsed all fields */
	if (ret != -ENOENT)
		return ret;

	return 0;
}
