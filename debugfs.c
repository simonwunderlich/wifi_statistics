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

static struct dentry *ws_debugfs;

static ssize_t read_debug_active(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct ws_monif *monif = (struct ws_monif *)file->private_data;
	char buf[32];
	ssize_t len;

	len = sprintf(buf, "%d\n", atomic_read(&monif->active));
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}


static ssize_t write_debug_active(struct file *file,
				  const char __user *user_buf, size_t count,
				  loff_t *ppos)
{
	struct ws_monif *monif = (struct ws_monif *)file->private_data;
	char buf[32];
	ssize_t len;
	unsigned long old, active;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoul(buf, 0, &active))
		return -EINVAL;

	active = !!active;

	rtnl_lock();
	old = atomic_read(&monif->active);
	if (old != active) {
		if (active)
			ws_monif_activate(monif);
		else
			ws_monif_deactivate(monif);
	}
	rtnl_unlock();

	return count;
}

const struct file_operations active_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = write_debug_active,
	.read = read_debug_active,
	.llseek = default_llseek,
};

int ws_sta_seq_read(struct seq_file *seq, void *offset)
{
	struct ws_monif *monif = (struct ws_monif *)seq->private;
	struct ws_hash *hash = &monif->hash;
	struct hlist_head *head;
	struct ws_sta *ws_sta;
	bool first = true;
	int i;

	if (!atomic_read(&monif->active))
		return -1;

	ws_sta_seq_print_head(seq);
	for (i = 0; i < WS_HASH_SIZE; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(ws_sta, head, hash_entry) {
			if (!first)
				seq_puts(seq, ",");
			ws_sta_seq_print(ws_sta, seq, offset);
			first = false;
		}
		rcu_read_unlock();
	}
	ws_sta_seq_print_tail(seq);
	return 0;
}

int ws_sta_seq_read_reset(struct seq_file *seq, void *offset)
{
	struct ws_monif *monif = (struct ws_monif *)seq->private;
	struct ws_hash *hash = &monif->hash;
	struct hlist_head *head;
	struct hlist_node *node;
	spinlock_t *list_lock;	/* protects write access to the hash lists */
	struct ws_sta *ws_sta;
	int i;
	bool first = true;

	if (!atomic_read(&monif->active))
		return -1;

	ws_sta_seq_print_head(seq);
	for (i = 0; i < WS_HASH_SIZE; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		/* TODO: can we write while doing spinlocks?! */
		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(ws_sta, node, head, hash_entry) {
			if (!first)
				seq_puts(seq, ",");
			ws_sta_seq_print(ws_sta, seq, offset);
			hlist_del_rcu(&ws_sta->hash_entry);
			ws_sta_free_ref(ws_sta);
			first = false;
		}
		spin_unlock_bh(list_lock);
	}
	ws_sta_seq_print_tail(seq);
	return 0;
}

static int ws_sta_debug_open(struct inode *inode, struct file *file)
{
	struct ws_monif *monif = (struct ws_monif *)inode->i_private;

	if (!atomic_read(&monif->active))
		return -1;

	switch (monif->ws_mode) {
	case MODE_READ:
		return single_open(file, ws_sta_seq_read, monif);
	default:
	case MODE_RESET:
		return single_open(file, ws_sta_seq_read_reset, monif);
	}
}

const struct file_operations stats_fops = {
	.owner = THIS_MODULE,
	.open = ws_sta_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t read_file_mode(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct ws_monif *monif = (struct ws_monif *)file->private_data;
	char *mode;
	ssize_t len;

	switch (monif->ws_mode) {
	case MODE_READ:
		mode = "read\n";
		break;
	case MODE_RESET:
		mode = "reset\n";
		break;
	default:
		mode = "unknown\n";
		break;
	}

	len = strlen(mode);
	return simple_read_from_buffer(user_buf, count, ppos, mode, len);
}

static ssize_t write_file_mode(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct ws_monif *monif = (struct ws_monif *)file->private_data;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';

	if (strncmp("read", buf, 4) == 0)
		monif->ws_mode = MODE_READ;
	else if (strncmp("reset", buf, 4) == 0)
		monif->ws_mode = MODE_RESET;
	else
		return -EINVAL;

	return count;
}

const struct file_operations mode_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = write_file_mode,
	.read = read_file_mode,
	.llseek = default_llseek,
};

void ws_debugfs_monif_init(struct ws_monif *monif)
{
	struct dentry *file;

	monif->dir = debugfs_create_dir(monif->net_dev->name, ws_debugfs);
	if (monif->dir == ERR_PTR(-ENODEV))
		monif->dir = NULL;

	if (!monif->dir)
		goto err;

	file = debugfs_create_file("stats",
				   S_IFREG | S_IRUGO, monif->dir, monif,
				   &stats_fops);
	if (!file)
		goto err;

	file = debugfs_create_file("active",
				   S_IFREG | S_IRUGO | S_IWUGO, monif->dir,
				   monif, &active_fops);
	if (!file)
		goto err;

	file = debugfs_create_file("mode",
				   S_IFREG | S_IRUGO | S_IWUGO, monif->dir,
				   monif, &mode_fops);
	if (!file)
		goto err;

	return;
err:
	debugfs_remove_recursive(monif->dir);
}

void ws_debugfs_monif_clean(struct ws_monif *monif)
{
	debugfs_remove_recursive(monif->dir);
	monif->dir = NULL;
}

void ws_debugfs_init(void)
{
	ws_debugfs = debugfs_create_dir("wifi_statistics", NULL);
	if (ws_debugfs == ERR_PTR(-ENODEV))
		ws_debugfs = NULL;

	if (!ws_debugfs)
		debugfs_remove_recursive(ws_debugfs);
}

void ws_debugfs_destroy(void)
{
	debugfs_remove_recursive(ws_debugfs);
	ws_debugfs = NULL;
}
