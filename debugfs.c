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

static struct dentry *ws_debugfs;
enum ws_mode ws_mode;

int ws_sta_seq_read(struct seq_file *seq, void *offset)
{
	struct ws_hash *hash = &ws_hash;
	struct hlist_head *head;
	struct ws_sta *ws_sta;
	int i;

	for (i = 0; i < WS_HASH_SIZE; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(ws_sta, head, hash_entry)
			ws_sta_seq_print(ws_sta, seq, offset);
		rcu_read_unlock();
	}
	return 0;
}

int ws_sta_seq_read_reset(struct seq_file *seq, void *offset)
{
	struct ws_hash *hash = &ws_hash;
	struct hlist_head *head;
	struct hlist_node *node;
	spinlock_t *list_lock;	/* protects write access to the hash lists */
	struct ws_sta *ws_sta;
	int i;

	for (i = 0; i < WS_HASH_SIZE; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		/* TODO: can we write while doing spinlocks?! */
		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(ws_sta, node, head, hash_entry) {
			ws_sta_seq_print(ws_sta, seq, offset);
			ws_sta_free_ref(ws_sta);
			hlist_del_rcu(node);
		}
		spin_unlock_bh(list_lock);
	}
	return 0;
}


static int ws_sta_debug_open(struct inode *inode, struct file *file)
{
	/* TODO: might be racy? */
	switch (ws_mode) {
	case MODE_READ:
		return single_open(file, ws_sta_seq_read, NULL);
	default:
	case MODE_RESET:
		return single_open(file, ws_sta_seq_read_reset, NULL);
	}
}

struct file_operations stats_fops = {
	.owner = THIS_MODULE,
	.open = ws_sta_debug_open,
	.read = seq_read,
	.llseek= seq_lseek,
	.release = single_release,
};

static ssize_t read_file_mode(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	char *mode;
	ssize_t len;

	switch (ws_mode) {
	case MODE_READ:
		mode = "read";
		break;
	case MODE_RESET:
		mode = "reset";
		break;
	default:
		mode = "unknown";
		break;
	}

	len = strlen(mode);
	return simple_read_from_buffer(user_buf, count, ppos, mode, len);
}


static ssize_t write_file_mode(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';

	if (strncmp("read", buf, 4) == 0) {
		ws_mode = MODE_READ;
	} else if (strncmp("reset", buf, 4) == 0) {
		ws_mode = MODE_RESET;
	} else {
		return -EINVAL;
	}

	return count;
}


struct file_operations mode_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = write_file_mode,
	.read = read_file_mode,
	.llseek = default_llseek,
};


void ws_debugfs_init(void)
{
        struct dentry *file;

	ws_mode = MODE_RESET;

	ws_debugfs = debugfs_create_dir("wifi_statistics", NULL);
	if (ws_debugfs == ERR_PTR(-ENODEV))
		ws_debugfs = NULL;

	if (!ws_debugfs)
		goto err;

	file = debugfs_create_file("stats",
				   S_IFREG | S_IRUGO, ws_debugfs, NULL,
				   &stats_fops);
	if (!file)
		goto err;

	file = debugfs_create_file("mode",
				   S_IFREG | S_IRUGO | S_IWUGO, ws_debugfs, NULL,
				   &mode_fops);
	if (!file)
		goto err;


	return;
err:
	debugfs_remove_recursive(ws_debugfs);

}

void ws_debugfs_destroy(void)
{
        debugfs_remove_recursive(ws_debugfs);
        ws_debugfs = NULL;
}


