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

struct net_device *dev = NULL;
static u8 nullmac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0};

rx_handler_result_t ws_handle_frame(struct sk_buff **pskb)
{
        struct ieee80211_radiotap_header *rthdr;
	struct ieee80211_hdr *hdr;
	struct ws_sta *ws_sta = NULL;
	struct sk_buff *skb;
	__le16 fc;
	int len, hdrlen;
	u8 *mac;

	skb = skb_clone(*pskb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto end;

        if (unlikely(!pskb_may_pull(skb, sizeof(*rthdr))))
		goto end;

	len = ieee80211_get_radiotap_len(skb->data);
	rthdr = (struct ieee80211_radiotap_header *) skb->data;
	hdr = (struct ieee80211_hdr *) skb_pull(skb, len);

        if (unlikely(!pskb_may_pull(skb, sizeof(fc))))
		goto end;

	fc = hdr->frame_control;
	hdrlen = ieee80211_get_hdrlen_from_skb(skb);
	if (unlikely(!hdrlen))
		goto end;

	if (ieee80211_is_cts(fc) || ieee80211_is_ack(fc))
		mac = nullmac;
	else
		/* transmitter address is always addr2:
		 *  * SA in an IBSS frame or To-AP frame
		 *  * BSSID in an in a From-AP frame
		 *  * TA in a 4 address frame
		 */
		mac = hdr->addr2;

	ws_sta = ws_hash_get(mac);

	if (!ws_sta)
		goto end;

	ws_sta->last_seen = jiffies;
	ws_sta->rx_packets++;
	ws_sta->rx_bytes += skb->len;
	ws_sta_parse_radiotap(ws_sta, rthdr, len);
	ws_sta_parse_ieee80211_hdr(ws_sta, hdr, hdrlen);

	ws_sta_free_ref(ws_sta);
end:
	kfree_skb(skb);

	return RX_HANDLER_PASS; /* continue processing */
}

static int __init ws_init(void)
{
	char *devname = "mon0";
	void *p = NULL; /* own struct? */
	int err = 0;

	rtnl_lock();
	dev = dev_get_by_name(&init_net, devname);
	if (!dev) {
		err = -EINVAL;
		goto unlock;
	}
	/* TODO: check for radiotap type! */

	err = netdev_rx_handler_register(dev, ws_handle_frame, p);
	if (err)
		goto free_dev;

	err = ws_hash_init();
	if (err)
		goto free_rx_handler;

	ws_debugfs_init();

	goto unlock;
free_rx_handler:
	netdev_rx_handler_unregister(dev);
free_dev:
	dev_put(dev);
	dev = NULL;

unlock:
	rtnl_unlock();
	return err;
}

static void __exit ws_exit(void)
{
	rtnl_lock();
	if (dev) {
		netdev_rx_handler_unregister(dev);
		dev_put(dev);
		dev = NULL;
	}
	rtnl_unlock();

	ws_debugfs_destroy();
	ws_hash_free();

	rcu_barrier();
}

module_init(ws_init);
module_exit(ws_exit);


MODULE_LICENSE("GPL");      

MODULE_AUTHOR(WIFI_STATISTICS_DRIVER_AUTHOR);
MODULE_DESCRIPTION(WIFI_STATISTICS_DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(WIFI_STATISTICS_DRIVER_DEVICE);
MODULE_VERSION(WIFI_STATISTICS_SOURCE_VERSION);

