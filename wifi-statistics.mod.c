#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x568fba06, "module_layout" },
	{ 0x5a5e7ea3, "simple_read_from_buffer" },
	{ 0xd5f8162f, "debugfs_create_dir" },
	{ 0x9b5b51b2, "single_open" },
	{ 0x60a13e90, "rcu_barrier" },
	{ 0xfd492070, "single_release" },
	{ 0x4d884691, "malloc_sizes" },
	{ 0x34ec54de, "netdev_rx_handler_register" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0x1637ff0f, "_raw_spin_lock_bh" },
	{ 0xb53c5051, "skb_clone" },
	{ 0xfa1d0ed8, "dev_get_by_name" },
	{ 0x21a7d814, "seq_printf" },
	{ 0xc63f1b81, "ieee80211_radiotap_iterator_next" },
	{ 0xc2a3e73d, "debugfs_create_file" },
	{ 0x60152b00, "debugfs_remove_recursive" },
	{ 0xcb49c52f, "seq_read" },
	{ 0x7d11c268, "jiffies" },
	{ 0x760a4192, "__pskb_pull_tail" },
	{ 0x8bfe7988, "default_llseek" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0x2fa5a500, "memcmp" },
	{ 0x982e6b6d, "ieee80211_radiotap_iterator_init" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x85abc85f, "strncmp" },
	{ 0x86856070, "skb_pull" },
	{ 0x3775290c, "init_net" },
	{ 0xba63339c, "_raw_spin_unlock_bh" },
	{ 0xb6251ac0, "netdev_rx_handler_unregister" },
	{ 0xbb0ebf03, "kfree_skb" },
	{ 0x7a172b67, "kmem_cache_alloc_trace" },
	{ 0xa4b3ff06, "ieee80211_get_hdrlen_from_skb" },
	{ 0x10166945, "seq_lseek" },
	{ 0x50f5e532, "call_rcu_sched" },
	{ 0x77e2f33, "_copy_from_user" },
	{ 0x6e720ff2, "rtnl_unlock" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=cfg80211";


MODULE_INFO(srcversion, "2D50C255DD87C856632A707");
