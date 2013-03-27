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
	for (i = 0; i < NUM_TIDS; i++)
		ws_sta->last_seqno[i] = -1;

	ws_sta->signal.min = INT_MAX;
	ws_sta->signal.max = INT_MIN;
}

int ws_sta_seq_print(struct ws_sta *ws_sta, struct seq_file *seq, void *offset)
{
	int i;

	seq_printf(seq, "station %pM {\n", ws_sta->mac);
	seq_printf(seq, "\tsignal: {\n");
	seq_printf(seq, "\t\tlast: %d\n", ws_sta->signal.last);
	seq_printf(seq, "\t\tmin: %d\n", ws_sta->signal.min);
	seq_printf(seq, "\t\tmax: %d\n", ws_sta->signal.max);
	seq_printf(seq, "\t\tcount: %d\n", ws_sta->signal.count);
	seq_printf(seq, "\t\tsum: %d\n", ws_sta->signal.sum);
	seq_printf(seq, "\t\tsum_square: %llu\n", ws_sta->signal.sum_square);
	seq_printf(seq, "\t}\n");
	seq_printf(seq, "\tbad fcs packets: %d\n", ws_sta->bad_fcs);
	seq_printf(seq, "\ttotal packets: %d\n", ws_sta->rx_packets);
	seq_printf(seq, "\ttotal bytes: %llu\n", ws_sta->rx_bytes);
	seq_printf(seq, "\tlast seen (msec): %d\n", jiffies_to_msecs(jiffies - ws_sta->last_seen));
	for (i = 0; i < NUM_TIDS; i++) {
		if (ws_sta->last_seqno[i] < 0)
			continue;
		seq_printf(seq, "\tlast_seqno[TID %d]: %d,\n", i, ws_sta->last_seqno[i]);
	}
	seq_printf(seq, "}\n");
	return 0;
}


int ws_sta_parse_ieee80211_hdr(struct ws_sta *ws_sta,
			       struct ieee80211_hdr *hdr, int len)
{
	int tid = 0;
	static char bcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	u8 *dest;

	/* only care about data and management frames for now ... */
	if (!ieee80211_is_data(hdr->frame_control) &&
	    !ieee80211_is_mgmt(hdr->frame_control))
		return 0;

	dest = ieee80211_get_DA(hdr);
	if (memcmp(dest, bcast, ETH_ALEN) == 0)
		tid = BCAST_TID;
	else if (ieee80211_is_data_qos(hdr->frame_control)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);
		tid = *qc & IEEE80211_QOS_CTL_TID_MASK;
	} else tid = 0;

        ws_sta->last_seqno[tid] = le16_to_cpu(hdr->seq_ctrl) >> 4;

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
			s8 signal = (s8) *iterator.this_arg;
			ws_sta->signal.last = signal;
			ws_sta->signal.min = min((int)signal, ws_sta->signal.min);
			ws_sta->signal.max = max((int)signal, ws_sta->signal.max);
			ws_sta->signal.count++;
			ws_sta->signal.sum += signal;
			ws_sta->signal.sum_square += signal * signal;
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
