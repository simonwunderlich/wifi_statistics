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

static inline u32 ws_hash_choose(void *mac)
{
	u32 hash = 0;
	const u8 *key = mac;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	return (hash % WS_HASH_SIZE);
}

/* try to find an element in the hash, return NULL if not found */
struct ws_sta *ws_hash_find(struct ws_hash *hash, u8 *mac)
{
	struct ws_sta *res = NULL, *tmp_sta;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct hlist_head *head;
	u32 index;

	index = ws_hash_choose(mac);
	head = &hash->table[index];
	list_lock = &hash->list_locks[index];

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp_sta, head, hash_entry) {
		if (memcmp(mac, tmp_sta->mac, ETH_ALEN))
			continue;

		if (!atomic_inc_not_zero(&tmp_sta->refcount))
			continue;

		res = tmp_sta;
		break;
	}
	rcu_read_unlock();

	return res;
}


/* like hash_find, but assigns a new element if not present yet */
struct ws_sta *ws_hash_get(struct ws_hash *hash, u8 *mac)
{
	struct ws_sta *ws_sta;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct hlist_head *head;
	u32 index;
	
	ws_sta = ws_hash_find(hash, mac);
	if (ws_sta)
		return ws_sta;

	ws_sta = kzalloc(sizeof(*ws_sta), GFP_ATOMIC);
	if (!ws_sta)
		return NULL;

	ws_sta_init(ws_sta);
	memcpy(ws_sta->mac, mac, ETH_ALEN);

	/* add new element */
	index = ws_hash_choose(mac);
	head = &hash->table[index];
	list_lock = &hash->list_locks[index];

	/* one for the hash, one for returning */
	atomic_set(&ws_sta->refcount, 2);

	spin_lock_bh(list_lock);
	hlist_add_head_rcu(&ws_sta->hash_entry, head);
	spin_unlock_bh(list_lock);

	return ws_sta;
}

int ws_hash_free(struct ws_hash *hash)
{
	struct ws_sta *ws_sta;
	struct hlist_node *node;
	struct hlist_head *head;
	spinlock_t *list_lock;	/* protects write access to the hash lists */
	int i;

	for (i = 0; i < WS_HASH_SIZE; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(ws_sta, node, head, hash_entry) {
			hlist_del_rcu(&ws_sta->hash_entry);
			ws_sta_free_ref(ws_sta);
		}
		spin_unlock_bh(list_lock);
	}

	return 0;
}

int ws_hash_init(struct ws_hash *hash)
{
	int i;

	for (i = 0; i < WS_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&hash->table[i]);
		spin_lock_init(&hash->list_locks[i]);
	}
	return 0;
}
