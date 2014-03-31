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

struct list_head monif_list;

void ws_monif_free_rcu(struct rcu_head *head)
{
	struct ws_monif *monif;

	monif = container_of(head, struct ws_monif, rcu);
	dev_put(monif->net_dev);
	kfree(monif);
}

struct ws_monif *ws_monif_get(const struct net_device *net_dev)
{
	struct ws_monif *monif;

	rcu_read_lock();
	list_for_each_entry_rcu(monif, &monif_list, list) {
		if (monif->net_dev == net_dev &&
		    atomic_inc_not_zero(&monif->refcount))
			goto out;
	}
	monif = NULL;
out:
	rcu_read_unlock();
	return monif;
}


static inline void
ws_monif_free_ref(struct ws_monif *monif)
{
	if (atomic_dec_and_test(&monif->refcount))
		call_rcu(&monif->rcu, ws_monif_free_rcu);
}

bool ws_is_badfcs(struct ieee80211_radiotap_header *rthdr, int len)
{
	struct ieee80211_radiotap_iterator iterator;
	int ret;

	ret = ieee80211_radiotap_iterator_init(&iterator, rthdr, len, NULL);

	while (!ret) {
		ret = ieee80211_radiotap_iterator_next(&iterator);

		if (ret)
			continue;

		switch (iterator.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iterator.this_arg & (IEEE80211_RADIOTAP_F_BADFCS))
				return true;
			else
				return false;
			break;
		default:
			break;
		}
	}

	return false;
}

rx_handler_result_t ws_handle_frame(struct sk_buff **pskb)
{
	struct ieee80211_radiotap_header *rthdr;
	struct ieee80211_hdr *hdr;
	struct ws_sta *ws_sta = NULL;
	struct ws_monif *monif = NULL;
	struct sk_buff *skb = NULL;
	__le16 fc;
	int len, hdrlen;
	static u8 nullmac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0};
	u8 *mac;

	skb = skb_clone(*pskb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto end;

	monif = ws_monif_get(skb->dev);
	if (!monif)
		goto end;

	if (!atomic_read(&monif->active))
		goto end;

	if (unlikely(!pskb_may_pull(skb, sizeof(*rthdr))))
		goto end;

	len = ieee80211_get_radiotap_len(skb->data);
	rthdr = (struct ieee80211_radiotap_header *)skb->data;
	hdr = (struct ieee80211_hdr *)skb_pull(skb, len);

	if (unlikely(!pskb_may_pull(skb, sizeof(fc))))
		goto end;

	fc = hdr->frame_control;
	hdrlen = ieee80211_get_hdrlen_from_skb(skb);
	if (unlikely(!hdrlen))
		goto end;

	if (unlikely(!pskb_may_pull(skb, hdrlen)))
		goto end;

	if (ieee80211_is_cts(fc) || ieee80211_is_ack(fc)) {
		mac = nullmac;
	} else {
		/* transmitter address is always addr2:
		 *  * SA in an IBSS frame or To-AP frame
		 *  * BSSID in an in a From-AP frame
		 *  * TA in a 4 address frame
		 */
		mac = hdr->addr2;

		/* if the frame has a bad FCS, try to find the station
		 * in the hash, assuming that the source mac is still usable.
		 * If it can't be found, use the packet on the null source.
		 */
		if (ws_is_badfcs(rthdr, len)) {
			ws_sta = ws_hash_find(&monif->hash, mac);
			if (ws_sta)
				goto have_ws_sta;
			else
				mac = nullmac;
		}
	}

	ws_sta = ws_hash_get(&monif->hash, mac);

	if (!ws_sta)
		goto end;

have_ws_sta:
	ws_sta_general(ws_sta, skb);
	ws_sta_parse_radiotap(ws_sta, rthdr, len);
	ws_sta_parse_ieee80211_hdr(ws_sta, hdr, hdrlen);

	ws_sta_free_ref(ws_sta);
end:
	if (monif)
		ws_monif_free_ref(monif);

	kfree_skb(skb);

	return RX_HANDLER_PASS; /* continue processing */
}

/* caller must hold rtnl lock */
int ws_monif_activate(struct ws_monif *monif)
{
	int err = 0;
	void *p = NULL; /* own struct? */

	if (atomic_read(&monif->active))
		return -EBUSY;

	err = netdev_rx_handler_register(monif->net_dev, ws_handle_frame, p);
	if (err)
		return 0;

	err = ws_hash_init(&monif->hash);
	if (err)
		goto free_rx_handler;

	atomic_set(&monif->active, 1);

	return 0;

free_rx_handler:
	netdev_rx_handler_unregister(monif->net_dev);
	return err;
}

/* caller must hold rtnl lock */
int ws_monif_deactivate(struct ws_monif *monif)
{
	if (!atomic_read(&monif->active))
		return -EBUSY;

	netdev_rx_handler_unregister(monif->net_dev);
	ws_hash_free(&monif->hash);
	atomic_set(&monif->active, 0);

	return 0;
}

int ws_monif_register(struct net_device *net_dev)
{
	struct ws_monif *monif = NULL;

	if (!net_dev->ieee80211_ptr)
		return -EINVAL;

	if (net_dev->ieee80211_ptr->iftype != NL80211_IFTYPE_MONITOR)
		return -EINVAL;

	monif = kzalloc(sizeof(*monif), GFP_KERNEL);
	if (!monif)
		return -ENOMEM;

	dev_hold(net_dev);

	atomic_set(&monif->active, 0);
	monif->net_dev = net_dev;
	monif->ws_mode = MODE_RESET;
	atomic_set(&monif->refcount, 2);

	list_add_tail_rcu(&monif->list, &monif_list);
	/* add to list */
	ws_debugfs_monif_init(monif);

	return 0;
}


void ws_monif_unregister(struct ws_monif *monif)
{
	list_del_rcu(&monif->list);
	ws_monif_free_ref(monif); /* for list */

	/* deactivate */
	ws_monif_deactivate(monif);

	/* clean up */
	ws_debugfs_monif_clean(monif);
	ws_monif_free_ref(monif); /* for struct */
}


static int ws_if_notification(struct notifier_block *this,
			      unsigned long event, void *ptr)
{
	struct net_device *net_dev = ptr;
	struct ws_monif *monif;

	monif = ws_monif_get(net_dev);

	switch (event) {
	case NETDEV_REGISTER:
		if (!monif)
			ws_monif_register(net_dev);
		break;
	case NETDEV_UNREGISTER:
		if (monif)
			ws_monif_unregister(monif);
		break;
	default:
		break;
	}

	if (monif)
		ws_monif_free_ref(monif);

	return NOTIFY_DONE;
}

struct notifier_block if_notifier = {
	.notifier_call = ws_if_notification,
};

static int __init ws_init(void)
{
	INIT_LIST_HEAD(&monif_list);
	ws_debugfs_init();
	register_netdevice_notifier(&if_notifier);

	return 0;
}

static void __exit ws_exit(void)
{
	unregister_netdevice_notifier(&if_notifier);
	ws_debugfs_destroy();
	WARN_ON(!list_empty(&monif_list));

	rcu_barrier();
}

module_init(ws_init);
module_exit(ws_exit);

MODULE_LICENSE("GPL");

MODULE_AUTHOR(WIFI_STATS_DRIVER_AUTHOR);
MODULE_DESCRIPTION(WIFI_STATS_DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(WIFI_STATS_DRIVER_DEVICE);
MODULE_VERSION(WIFI_STATS_SOURCE_VERSION);

