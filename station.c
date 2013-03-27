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

#include "wifi_statistics.h"

void ws_sta_free_ref(struct ws_sta *ws_sta)
{
	if (atomic_dec_and_test(&ws_sta->refcount))
		kfree_rcu(ws_sta, rcu);
}

void ws_sta_init(struct ws_sta *ws_sta)
{
	int i;
	spin_lock_init(&ws_sta->lock);
	for (i = 0; i < NUM_TIDS; i++) {
		ws_sta->last_seqno[i] = -1;
		memset(ws_sta->last_dest[i], 0, sizeof(ws_sta->last_dest[i]));
		ws_sta->seqno_diff[i].min = INT_MAX;
		ws_sta->seqno_diff[i].max = INT_MIN;
		ewma_init(&ws_sta->seqno_diff[i].ewma, WS_EWMA_FACTOR, WS_EWMA_WEIGHT);
	}

	ws_sta->signal.min = INT_MAX;
	ws_sta->signal.max = INT_MIN;
	ewma_init(&ws_sta->signal.ewma, WS_EWMA_FACTOR, WS_EWMA_WEIGHT);
}

static void ws_sta_print_detail(struct seq_file *seq,
				struct ws_sta_detailed *detail)
{
	seq_printf(seq, "{\n");
	seq_printf(seq, "\t\tlast: %d\n", detail->last);
	seq_printf(seq, "\t\tmin: %d\n", detail->min);
	seq_printf(seq, "\t\tmax: %d\n", detail->max);
	seq_printf(seq, "\t\tcount: %d\n", detail->count);
	seq_printf(seq, "\t\tsum: %d\n", detail->sum);
	seq_printf(seq, "\t\tsum_square: %llu\n", detail->sum_square);
	seq_printf(seq, "\t\tewma: %d\n",
		  (int)(ewma_read(&detail->ewma) - (INT_MAX>>2)));
	seq_printf(seq, "\t}\n");
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

int ws_sta_seq_print(struct ws_sta *ws_sta, struct seq_file *seq, void *offset)
{
	int i;

	seq_printf(seq, "station %pM {\n", ws_sta->mac);
	seq_printf(seq, "\tsignal: ");
	ws_sta_print_detail(seq, &ws_sta->signal);
	seq_printf(seq, "\tbad fcs packets: %d\n", ws_sta->bad_fcs);
	seq_printf(seq, "\ttotal packets: %d\n", ws_sta->rx_packets);
	seq_printf(seq, "\ttotal bytes: %llu\n", ws_sta->rx_bytes);
	seq_printf(seq, "\tlast seen (msec): %d\n", jiffies_to_msecs(jiffies - ws_sta->last_seen));
	seq_printf(seq, "\tBSSID: %pM\n", ws_sta->bssid);
	seq_printf(seq, "\ttype: %s\n", ws_sta_get_type(ws_sta->type));
	for (i = 0; i < NUM_TIDS; i++) {
		if (ws_sta->last_seqno[i] < 0)
			continue;
		seq_printf(seq, "\tlast_seqno[TID %d]: %d,\n", i, ws_sta->last_seqno[i]);
		if (ws_sta->seqno_diff[i].count > 0)  {
			seq_printf(seq, "\tseqno difference[TID %d]: ", i);
			ws_sta_print_detail(seq, &ws_sta->seqno_diff[i]);
		}
	}
	seq_printf(seq, "}\n");
	return 0;
}

static void ws_sta_detailed_apply(struct ws_sta_detailed *detail, int value)
{
	detail->last = value;
	detail->min = min((int)value, detail->min);
	detail->max = max((int)value, detail->max);
	detail->count++;
	detail->sum += value;
	detail->sum_square += value * value;
	ewma_add(&detail->ewma, value + (INT_MAX>>2));
}

int ws_sta_parse_ieee80211_hdr(struct ws_sta *ws_sta,
			       struct ieee80211_hdr *hdr, int len)
{
	int tid = 0;
	int seqno;
	u8 *dest;

	/* only care about data and management frames for now ... */
	if (!ieee80211_is_data(hdr->frame_control) &&
	    !ieee80211_is_mgmt(hdr->frame_control))
		return 0;

	switch (hdr->frame_control & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
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
			/* no IBSS known, and device might act as an AP or
			 * station at the same time. just leave it. */
			break;
	}

	/* Find out the TID if it's an individually adressed QoS data frame,
	 * otherwise use the "general" counter for all other frames
	 * (multicasts, beacons, etc) which is called BCAST_TID here.
	 *
	 * see 802.11-2012 9.3.2.10 Duplicate detection and recovery
	 * for details.
	 */
	dest = hdr->addr1;
	if (is_multicast_ether_addr(dest))
		tid = BCAST_TID;
	else if (ieee80211_is_data_qos(hdr->frame_control)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);
		tid = *qc & IEEE80211_QOS_CTL_TID_MASK;
	} else tid = BCAST_TID;

	/* Keeping track of all destinations of any station appears
	 * to be unreasonable overhead. Therefore, we use a best
	 * effort approach here and only track seqno differences
	 * if the destination is the same as last time on this TID.
	 */
	seqno = le16_to_cpu(hdr->seq_ctrl) >> 4;
	if (memcmp(ws_sta->last_dest[tid], dest, ETH_ALEN) == 0) {
		int diff;

		diff = (seqno - ws_sta->last_seqno[tid] + (1 << 12)) % (1 << 12);

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

	while (!ret) {
		ret = ieee80211_radiotap_iterator_next(&iterator);

		if (ret)
			continue;

		switch (iterator.this_arg_index) {
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: {
			ws_sta_detailed_apply(&ws_sta->signal, (s8) *iterator.this_arg);
			break;
		}
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iterator.this_arg & (IEEE80211_RADIOTAP_F_BADFCS))
				ws_sta->bad_fcs++;
		default:
			break;
		}
	}

	/* we did not stop because we parsed all fields */
	if (ret != -ENOENT)
		return ret;

	return 0;
}
