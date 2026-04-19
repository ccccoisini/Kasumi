/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS LKM - Loadable Kernel Module for filesystem path manipulation.
 *
 * All hooks use kprobes or ftrace (fallback to kprobe).
 * GET_FD: kprobe+kretprobe on ni_syscall. VFS: try ftrace (entry) + kretprobe
 *   (exit) for vfs_getattr, d_path, iterate_dir, vfs_getxattr; else kprobe.
 * Works on CONFIG_STRICT_KERNEL_RWX kernels. Syscall nr passed at insmod (hymo_syscall_nr=).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>
/* EROFS_SUPER_MAGIC may be missing in older kernel uapi headers */
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "hymofs_lkm.h"
#include "hymofs_iop_override.h"
#include "hymofs_ftrace.h"
#include "hymofs_tracepoint.h"
#include "hymofs_uname.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("HymoFS LKM");
#ifndef HYMOFS_VERSION
#define HYMOFS_VERSION "0.1.0-dev"
#endif
MODULE_VERSION(HYMOFS_VERSION);
MODULE_SOFTDEP("pre: kernelsu");

/*
 * Set to 1 to register VFS kprobes (path/stat/dir hooks). Set to 0 for GET_FD only
 * if the LKM causes bootloop on your kernel.
 * Build with -DHYMOFS_VFS_KPROBES=0 to disable if needed.
 */
#ifndef HYMOFS_VFS_KPROBES
#define HYMOFS_VFS_KPROBES 1
#endif

static bool hymofs_enabled;
static atomic_t hymo_rule_count = ATOMIC_INIT(0);
static atomic_t hymo_hide_count = ATOMIC_INIT(0);

/* vmalloc-based per-CPU data to avoid percpu allocator exhaustion on 6.6 Qualcomm. */
struct hymo_percpu {
	unsigned int kprobe_reent;
	int iterate_did_swap;
	int in_populate_inject;
	int override_fd;
	int override_active;
#if defined(__aarch64__) || defined(__x86_64__)
	struct {
		char __user *buf;
		size_t count;
		int active;
	} cmdline_ctx;
#endif
};
static struct hymo_percpu *hymo_percpu_base;

static inline struct hymo_percpu *hymo_this_cpu(void)
{
	return hymo_percpu_base + smp_processor_id();
}

/* vmalloc-based per-CPU path buffers */
static char *hymo_getname_buf_base;
static char *hymo_iterate_buf_base;

static atomic_long_t hymo_ioctl_tgid = ATOMIC_LONG_INIT(0);
static atomic_long_t hymo_xattr_source_tgid = ATOMIC_LONG_INIT(0);

static struct kmem_cache *hymo_filldir_cache;

/* Offset base for injected entries (filldir pos); must not collide with real inode offsets. */
#define HYMO_MAGIC_POS 0x1000000000000000ULL

/* ======================================================================
 * Part 2: Symbol Resolution via kallsyms + kprobes (no kernel export needed)
 * ====================================================================== */

/* Resolved once at init via kprobe; then we use it for all lookups. */
static unsigned long (*hymofs_kallsyms_lookup_name)(const char *name);

/* Validate that a kernel address is in valid range (prevents NULL and invalid ptr) */
static bool hymofs_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	/* Check for common error values that can be returned */
	if (IS_ERR_VALUE(addr))
		return false;
	/*
	 * On ARM64 with KASLR (GKI 5.15+), kernel addresses are in the high half
	 * of the address space. Just check that top bits are set (kernel space).
	 * Be permissive - let the kernel's own checks catch truly invalid addresses.
	 */
#if defined(CONFIG_64BIT)
	/* Any address with top bit set is in kernel space on 64-bit */
	return (addr & (1UL << 63)) != 0;
#else
	/* 32-bit kernel space */
	return addr >= PAGE_OFFSET;
#endif
}

/*
 * Resolve kernel symbol by name. We do NOT rely on the kernel exporting
 * anything: first try to get kallsyms_lookup_name itself via kprobe, then
 * use it for fast lookup; else fall back to per-symbol kprobe resolution.
 */
HYMO_NOCFI unsigned long hymofs_lookup_name(const char *name)
{
	if (hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name(name);
		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}
	/* Fallback: kprobe on the target symbol gives us its address */
	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_alert("HymoFS: kprobe %s failed: %d\n", name, ret);
			return 0;
		}
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		/* Just check for NULL and error values, trust kernel kprobe result */
		if (!addr || IS_ERR_VALUE(addr)) {
			pr_alert("HymoFS: symbol %s returned invalid addr 0x%lx\n", name, addr);
			return 0;
		}
		return addr;
	}
}

/* Call once at init to steal kallsyms_lookup_name via kprobe. */
static void hymofs_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	pr_alert("HymoFS: resolving kallsyms_lookup_name...\n");
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_alert("HymoFS: kprobe kallsyms_lookup_name failed: %d, using per-symbol kprobe\n", ret);
		return;
	}
	if (!hymofs_valid_kernel_addr((unsigned long)kp.addr)) {
		pr_alert("HymoFS: kallsyms_lookup_name returned invalid address: 0x%lx\n",
			(unsigned long)kp.addr);
		unregister_kprobe(&kp);
		return;
	}
	hymofs_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_alert("HymoFS: kallsyms_lookup_name resolved @ 0x%lx\n",
		(unsigned long)hymofs_kallsyms_lookup_name);
}

/* Constants & data structures are in hymofs_lkm.h */

/* ======================================================================
 * Part 5: Global State
 * ====================================================================== */

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_XARRAY(hymo_allow_uids_xa);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);

/* ------------------------------------------------------------------ */
/* spoof_kstat: explicit per-path/per-ino kstat overrides (api15)     */
/* ------------------------------------------------------------------ */
struct hymo_spoof_kstat_entry {
	char *target_pathname;             /* may be NULL when only ino-keyed */
	u32 path_hash;
	unsigned long target_ino;          /* 0 = unresolved, look up by path only */
	unsigned long target_dev;          /* 0 = match any */

	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int  spoofed_nlink;
	long long     spoofed_size;
	long spoofed_atime_sec;
	long spoofed_atime_nsec;
	long spoofed_mtime_sec;
	long spoofed_mtime_nsec;
	long spoofed_ctime_sec;
	long spoofed_ctime_nsec;
	unsigned long      spoofed_blksize;
	unsigned long long spoofed_blocks;
	int is_static;

	struct hlist_node path_node;
	struct hlist_node ino_node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(hymo_spoof_kstat_path, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_spoof_kstat_ino,  HYMO_HASH_BITS);
static atomic_t hymo_spoof_kstat_count = ATOMIC_INIT(0);

static DEFINE_MUTEX(hymo_config_mutex);

/* Maps spoof rules (read buffer filter for /proc/pid/maps); used by ioctl and filter. */
struct hymo_maps_rule_entry {
	struct list_head list;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	char spoofed_pathname[HYMO_MAX_LEN_PATHNAME];
};
static LIST_HEAD(hymo_maps_rules);
static DEFINE_MUTEX(hymo_maps_mutex);

static bool hymo_allowlist_loaded;

/* Real-time allowlist: __ksu_is_allow_uid_for_current(uid) handles uid 0 via is_ksu_domain */
typedef bool (*hymo_ksu_is_allow_uid_fn)(uid_t uid);
static hymo_ksu_is_allow_uid_fn hymo_ksu_is_allow_uid_ptr;

/* hymofs_enabled declared above (used by hooks) */
bool hymo_debug_enabled;
static bool hymo_stealth_enabled = true;

static char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
static char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
static char *hymo_current_mirror_path = hymo_mirror_path_buf;
static char *hymo_current_mirror_name = hymo_mirror_name_buf;

/* uname spoofing now lives in hymofs_uname.{c,h} — direct utsname memory writes,
 * no per-syscall hooks. See there for global and scoped (per-task uts_ns) modes. */

/* cmdline spoofing: RCU-protected (wrapper has rcu_head for kfree_rcu) */
struct hymo_cmdline_rcu {
	struct rcu_head rcu;
	char cmdline[HYMO_FAKE_CMDLINE_SIZE];
};
static struct hymo_cmdline_rcu __rcu *hymo_spoof_cmdline_ptr;
static bool hymo_cmdline_spoof_active;

static pid_t hymo_daemon_pid;

/* Kprobe registration flags (used by GET_FEATURES before their definitions) */
static int hymo_cmdline_kprobe_registered;
static int hymo_cmdline_kretprobe_registered;
static int hymo_getxattr_kprobe_registered;
static int hymo_mount_hide_vfsmnt_registered;
static int hymo_mount_hide_mountinfo_registered;
static int hymo_mount_hide_read_fallback_registered;
static int hymo_maps_seq_read_registered;

/* Per-feature enable mask: 1 = enabled. Default all enabled. */
static int hymo_feature_enabled_mask = 0xFFFFFFFF;
static int hymo_statfs_kretprobe_registered;

/* Forward declarations for hymo_export_hooks_status (HYMO_IOC_GET_HOOKS) */
static int hymo_ni_kprobe_registered;
static int hymo_reboot_kprobe_registered;
int hymo_syscall_nr_param = 142;
static bool hymo_getname_kprobe_registered;
static bool hymo_vfs_use_ftrace;

static DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
static DECLARE_BITMAP(hymo_hide_bloom, HYMO_BLOOM_SIZE);
/* hymo_rule_count and hymo_hide_count declared above */

/* /system partition device number for stat spoofing on redirected files */
static dev_t hymo_system_dev;

/* VFS symbols resolved at init; forward-declared for use in merge/inject before init. */
static int (*hymo_kern_path)(const char *, unsigned int, struct path *);
static int (*hymo_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
static struct file *(*hymo_dentry_open)(const struct path *, int, const struct cred *);
/* Bypass d_path kprobe to avoid recursion when we need path inside iterate_dir/d_path handlers */
static char *(*hymo_d_absolute_path)(const struct path *, char *, int);
static char *(*hymo_dentry_path_raw)(const struct dentry *, char *, int);
static char *(*hymo_d_path)(const struct path *, char *, int);
static struct dentry *(*hymo_d_hash_and_lookup)(struct dentry *, const struct qstr *);
/* d_real_inode: get real (e.g. lower) inode for overlay; used for statfs f_type passthrough.
 * d_real_inode is static inline in kernel, not in kallsyms. Use d_op->d_real when DCACHE_OP_REAL. */
#ifndef D_REAL_DATA
#define D_REAL_DATA 0
#endif
static struct inode *hymo_d_real_inode_impl(struct dentry *dentry)
{
	struct dentry *real;

	if (unlikely(dentry->d_flags & DCACHE_OP_REAL) && dentry->d_op && dentry->d_op->d_real) {
		real = dentry->d_op->d_real(dentry, D_REAL_DATA);
		return real && real->d_inode ? real->d_inode : dentry->d_inode;
	}
	return dentry->d_inode;
}
/* path_put, dput, dget, iput, iterate_dir: use kernel exports directly (EXPORT_SYMBOL), no lookup */

/* vfs_getxattr addr for resolving source path's SELinux context (set when xattr kretprobe registered) */
static void *hymo_vfs_getxattr_addr;

/* hymo_log macro is in hymofs_lkm.h */

/* ======================================================================
 * Part 6: RCU Free Callbacks
 * ====================================================================== */

static void hymo_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_entry *e = container_of(head, struct hymo_entry, rcu);
	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

static void hymo_hide_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_hide_entry *e = container_of(head, struct hymo_hide_entry, rcu);
	kfree(e->path);
	kfree(e);
}

static void hymo_inject_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_inject_entry *e = container_of(head, struct hymo_inject_entry, rcu);
	kfree(e->dir);
	kfree(e);
}

static void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_xattr_sb_entry *e = container_of(head, struct hymo_xattr_sb_entry, rcu);
	kfree(e);
}

static void hymo_merge_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_entry *e = container_of(head, struct hymo_merge_entry, rcu);
	if (e->target_dentry)
		dput(e->target_dentry);
	kfree(e->src);
	kfree(e->target);
	kfree(e->resolved_src);
	kfree(e);
}

static void hymo_spoof_kstat_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_spoof_kstat_entry *e =
		container_of(head, struct hymo_spoof_kstat_entry, rcu);
	kfree(e->target_pathname);
	kfree(e);
}

/* RCU-safe lookups. Caller must hold rcu_read_lock(). */
static struct hymo_spoof_kstat_entry *
hymofs_spoof_kstat_lookup_by_path(const char *path_str)
{
	struct hymo_spoof_kstat_entry *e;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(e,
		&hymo_spoof_kstat_path[hash_min(hash, HYMO_HASH_BITS)], path_node) {
		if (e->path_hash == hash && e->target_pathname &&
		    strcmp(e->target_pathname, path_str) == 0)
			return e;
	}
	return NULL;
}

static struct hymo_spoof_kstat_entry *
hymofs_spoof_kstat_lookup_by_ino(unsigned long ino, unsigned long dev)
{
	struct hymo_spoof_kstat_entry *e;

	if (!ino)
		return NULL;
	hlist_for_each_entry_rcu(e,
		&hymo_spoof_kstat_ino[hash_min(ino, HYMO_HASH_BITS)], ino_node) {
		if (e->target_ino == ino &&
		    (e->target_dev == 0 || dev == 0 || e->target_dev == dev))
			return e;
	}
	return NULL;
}

/* ======================================================================
 * Part 7: Inode Marking
 * ====================================================================== */

static inline void hymofs_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

static inline bool hymofs_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

/* Mark directory inode as having inject/merge rules (fast path for iterate_dir).
 * Call from process context only; kern_path can sleep. */
static void hymofs_mark_dir_has_inject(const char *path_str)
{
	struct path p;

	if (!path_str || !hymo_kern_path)
		return;
	if (hymo_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		set_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT, &d_inode(p.dentry)->i_mapping->flags);
	path_put(&p);
}

/* ======================================================================
 * Part 9: Cleanup
 * ====================================================================== */

static void hymo_clear_inode_flags_for_path(const char *path_str, unsigned int bit)
{
	struct path p;
	if (!path_str || !hymo_kern_path)
		return;
	if (hymo_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		clear_bit(bit, &d_inode(p.dentry)->i_mapping->flags);
	path_put(&p);
}

static void hymo_cleanup_locked(void)
{
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_xattr_sb_entry *sb_entry;
	struct hymo_merge_entry *merge_entry;
	struct hlist_node *tmp;
	int bkt;

	hymofs_enabled = false;

	hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
		hymo_clear_inode_flags_for_path(entry->src, AS_FLAGS_HYMO_HIDE);
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, hymo_entry_free_rcu);
	}
	hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
		hymo_clear_inode_flags_for_path(hide_entry->path, AS_FLAGS_HYMO_HIDE);
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
	}
	xa_destroy(&hymo_allow_uids_xa);
	hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
		hymo_clear_inode_flags_for_path(inject_entry->dir,
						AS_FLAGS_HYMO_DIR_HAS_INJECT);
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
	}
	hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, hymo_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		call_rcu(&merge_entry->rcu, hymo_merge_entry_free_rcu);
	}
	{
		struct hymo_spoof_kstat_entry *sk_entry;

		hash_for_each_safe(hymo_spoof_kstat_path, bkt, tmp, sk_entry, path_node) {
			hlist_del_rcu(&sk_entry->path_node);
			if (sk_entry->target_ino)
				hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, hymo_spoof_kstat_entry_free_rcu);
		}
		/* Sweep ino-only entries (no path). */
		hash_for_each_safe(hymo_spoof_kstat_ino, bkt, tmp, sk_entry, ino_node) {
			hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, hymo_spoof_kstat_entry_free_rcu);
		}
		atomic_set(&hymo_spoof_kstat_count, 0);
	}

	bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
	bitmap_zero(hymo_hide_bloom, HYMO_BLOOM_SIZE);
	atomic_set(&hymo_rule_count, 0);
	atomic_set(&hymo_hide_count, 0);
	hymo_allowlist_loaded = false;
}

/* ======================================================================
 * Part 10: Inject Rule Helper
 * ====================================================================== */

static void hymofs_add_inject_rule(char *dir)
{
	struct hymo_inject_entry *ie;
	u32 hash;
	bool found = false;

	if (!dir)
		return;

	hash = full_name_hash(NULL, dir, strlen(dir));
	hlist_for_each_entry(ie, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(ie->dir, dir) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		ie = kmalloc(sizeof(*ie), GFP_KERNEL);
		if (ie) {
			ie->dir = dir;
			hlist_add_head_rcu(&ie->node,
				&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_rule_count);
		} else {
			kfree(dir);
		}
	} else {
		kfree(dir);
	}
}

/* ======================================================================
 * Part 10b: Inject - populate list for merge/add rule dirs
 * ====================================================================== */

struct hymo_merge_ctx {
	struct dir_context ctx;
	struct list_head *head;
	const char *dir_path;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE hymo_merge_filldir(struct dir_context *ctx, const char *name,
					int namlen, loff_t offset, u64 ino,
					unsigned int d_type)
{
	struct hymo_merge_ctx *mctx = container_of(ctx, struct hymo_merge_ctx, ctx);
	struct hymo_name_list *item;

	if (namlen == 1 && name[0] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 2 && name[0] == '.' && name[1] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 8 && strncmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	/* Skip whiteout (char dev 0:0) */
	if (d_type == DT_CHR && mctx->dir_path && hymo_vfs_getattr) {
		char *path = kasprintf(GFP_KERNEL, "%s/%.*s", mctx->dir_path, namlen, name);
		if (path) {
			struct path p;
			if (hymo_kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
				struct kstat stat;
				if (hymo_vfs_getattr(&p, &stat, STATX_TYPE, AT_STATX_SYNC_AS_STAT) == 0 &&
				    S_ISCHR(stat.mode) && stat.rdev == 0) {
					path_put(&p);
					kfree(path);
					return HYMO_FILLDIR_CONTINUE;
				}
				path_put(&p);
			}
			kfree(path);
		}
	}

	/* Skip duplicates */
	{
		struct hymo_name_list *pos;
		list_for_each_entry(pos, mctx->head, list) {
			if ((size_t)namlen == strlen(pos->name) &&
			    strncmp(pos->name, name, namlen) == 0)
				return HYMO_FILLDIR_CONTINUE;
		}
	}

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (item) {
		item->name = kstrndup(name, namlen, GFP_KERNEL);
		item->type = (unsigned char)d_type;
		if (item->name)
			list_add(&item->list, mctx->head);
		else
			kfree(item);
	}
	return HYMO_FILLDIR_CONTINUE;
}

static HYMO_NOCFI void hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
					  struct list_head *head)
{
	struct hymo_entry *entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_merge_entry *merge_entry;
	struct hymo_name_list *item;
	struct hymo_merge_target_node *target_node, *tmp_node;
	struct list_head merge_targets;
	const char *match_src = NULL;
	size_t match_src_len = 0;
	u32 hash;
	int bkt;
	bool should_inject = false;
	size_t dir_len;
	/* d_path-resolved form of dir_path for matching rules stored via d_path.
	 * iterate_dir gives us d_absolute_path output, but ADD_RULE/ADD_MERGE_RULE
	 * store paths using d_path. These can differ (e.g. /product/overlay vs
	 * /system/product/overlay) due to bind mounts / symlinks. */
	char *dpath_buf = NULL;
	const char *dpath_dir = NULL;
	size_t dpath_dir_len = 0;
	u32 dpath_hash = 0;

	if (unlikely(!hymofs_enabled || !dir_path))
		return;
	if (atomic_read(&hymo_rule_count) == 0)
		return;

	INIT_LIST_HEAD(&merge_targets);
	dir_len = strlen(dir_path);
	hash = full_name_hash(NULL, dir_path, dir_len);

	/* Resolve the d_path form of this directory. We're in filldir callback
	 * (process context), so d_path is safe to call. Our d_path kretprobe
	 * won't interfere since this directory is not a redirect target. */
	if (parent) {
		if (hymo_kern_path) {
			struct path resolved;
			if (hymo_kern_path(dir_path, LOOKUP_FOLLOW, &resolved) == 0) {
				dpath_buf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (dpath_buf && hymo_d_path) {
					char *p = hymo_d_path(&resolved, dpath_buf, PATH_MAX);
					if (!IS_ERR(p) && p[0] == '/' &&
					    strcmp(p, dir_path) != 0) {
						dpath_dir = p;
						dpath_dir_len = strlen(p);
						dpath_hash = full_name_hash(NULL, p, dpath_dir_len);
					}
				}
				path_put(&resolved);
			}
		}
	}

	rcu_read_lock();

	/* Try both d_absolute_path form and d_path form for inject_dirs */
	hlist_for_each_entry_rcu(inject_entry,
		&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(inject_entry->dir, dir_path) == 0) {
			should_inject = true;
			break;
		}
	}
	if (!should_inject && dpath_dir) {
		hlist_for_each_entry_rcu(inject_entry,
			&hymo_inject_dirs[hash_min(dpath_hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, dpath_dir) == 0) {
				should_inject = true;
				break;
			}
		}
	}

	/* Scan all merge entries to match both src and resolved_src against
	 * both path forms. */
	hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
		if (strcmp(merge_entry->src, dir_path) == 0 ||
		    (merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dir_path) == 0) ||
		    (dpath_dir && strcmp(merge_entry->src, dpath_dir) == 0) ||
		    (dpath_dir && merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dpath_dir) == 0)) {
			if (!match_src) {
				match_src = merge_entry->src;
				match_src_len = strlen(match_src);
			}
			target_node = kmalloc(sizeof(*target_node), GFP_ATOMIC);
			if (target_node) {
				target_node->target = kstrdup(merge_entry->target, GFP_ATOMIC);
				target_node->target_dentry = NULL;
				if (target_node->target)
					list_add_tail(&target_node->list, &merge_targets);
				else
					kfree(target_node);
			}
			should_inject = true;
		}
	}

	if (should_inject && match_src) {
		/* Only scan hymo_paths when a merge rule matched. For simple
		 * ADD_RULE redirects the source is hidden and getname_flags
		 * handles the redirect transparently — no injection needed. */
		const char *pfx = match_src;
		size_t pfx_len = match_src_len;

		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (strncmp(entry->src, pfx, pfx_len) != 0)
				continue;
			{
				char *name = NULL;
				if (pfx_len == 1 && pfx[0] == '/')
					name = (char *)entry->src + 1;
				else if (entry->src[pfx_len] == '/')
					name = (char *)entry->src + pfx_len + 1;

				if (name && *name && !strchr(name, '/')) {
					struct hymo_name_list *pos;
					list_for_each_entry(pos, head, list) {
						if (strcmp(pos->name, name) == 0)
							goto next_entry;
					}
					item = kmalloc(sizeof(*item), GFP_ATOMIC);
					if (item) {
						item->name = kstrdup(name, GFP_ATOMIC);
						item->type = entry->type;
						if (item->name)
							list_add(&item->list, head);
						else
							kfree(item);
					}
				}
			}
next_entry:
			;
		}
	}
	rcu_read_unlock();

	list_for_each_entry_safe(target_node, tmp_node, &merge_targets, list) {
		if (target_node->target && hymo_kern_path && hymo_dentry_open) {
			char *replace_path = kasprintf(GFP_KERNEL, "%s/.replace", target_node->target);
			if (replace_path) {
				struct path rp;
				if (hymo_kern_path(replace_path, LOOKUP_FOLLOW, &rp) == 0) {
					hymo_log("replace mode enabled for %s (found %s)\n", dir_path, replace_path);
					path_put(&rp);
				}
				kfree(replace_path);
			}
			{
			struct path path;
			if (hymo_kern_path(target_node->target, LOOKUP_FOLLOW, &path) == 0) {
				const struct cred *cred = get_task_cred(&init_task);
				struct file *f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY,
								cred);
				if (!IS_ERR(f)) {
					struct hymo_merge_ctx mctx = {
						.ctx.actor = hymo_merge_filldir,
						.head = head,
						.dir_path = target_node->target,
					};
					hymo_this_cpu()->in_populate_inject = 1;
					iterate_dir(f, &mctx.ctx);
					hymo_this_cpu()->in_populate_inject = 0;
					fput(f);
				}
				put_cred(cred);
				path_put(&path);
			}
			}
		}
		kfree(target_node->target);
		list_del(&target_node->list);
		kfree(target_node);
	}
	kfree(dpath_buf);
}

/* ======================================================================
 * Part 10c: Materialize merge rule into individual hymo_paths entries
 *
 * Called from HYMO_IOC_ADD_MERGE_RULE ioctl (process context, can sleep).
 * Recursively scans the merge target directory and creates exact-match
 * redirect rules so getname_flags works without blind trie redirect.
 * ====================================================================== */

static void hymofs_materialize_merge(const char *src_prefix,
				     const char *target_dir, int depth);

static void hymofs_add_path_entry(const char *src, const char *tgt,
				  unsigned char type)
{
	struct hymo_entry *e;
	u32 hash = full_name_hash(NULL, src, strlen(src));
	bool found = false;

	hlist_for_each_entry(e, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (e->src_hash == hash && strcmp(e->src, src) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (e) {
			e->src = kstrdup(src, GFP_KERNEL);
			e->target = kstrdup(tgt, GFP_KERNEL);
			e->type = type;
			e->src_hash = hash;
			if (e->src && e->target) {
				unsigned long h1, h2;

				hlist_add_head_rcu(&e->node,
					&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
				hlist_add_head_rcu(&e->target_node,
					&hymo_targets[hash_min(
						full_name_hash(NULL, e->target,
							strlen(e->target)),
						HYMO_HASH_BITS)]);
				h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
				h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
				set_bit(h1, hymo_path_bloom);
				set_bit(h2, hymo_path_bloom);
				atomic_inc(&hymo_rule_count);
			} else {
				kfree(e->src);
				kfree(e->target);
				kfree(e);
			}
		}
	}
}

/* Register a nested merge_entry from within materialize (process context).
 * Mirrors the ADD_MERGE_RULE ioctl's entry construction. Returns true when
 * a new entry was inserted. Does not take ownership of src_str/target_str.
 *
 * Used so that DT_DIR children discovered while materializing a parent merge
 * become their own merge rules, instead of being registered as DT_DIR
 * entries in hymo_paths. The latter would cause getname_flags to
 * wholesale-redirect any lookup of that subdir to the module's (typically
 * incomplete) copy, destroying real subdir content. A nested merge rule, by
 * contrast, keeps the real subdir intact and only performs iterate_dir-time
 * injection of the module's contents on top.
 */
static bool hymofs_register_nested_merge(const char *src_str,
					 const char *target_str)
{
	struct hymo_merge_entry *me, *existing;
	char *resolved_src = NULL;
	struct dentry *tgt_dentry = NULL;
	struct path mpath;
	u32 hash;
	bool created = false;

	if (!src_str || !target_str)
		return false;
	if (!hymo_kern_path)
		return false;

	if (hymo_kern_path(src_str, LOOKUP_FOLLOW, &mpath) == 0) {
		char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (rbuf && hymo_d_path) {
			char *res = hymo_d_path(&mpath, rbuf, PATH_MAX);
			if (!IS_ERR(res) && res[0] == '/' &&
			    strcmp(res, src_str) != 0)
				resolved_src = kstrdup(res, GFP_KERNEL);
		}
		kfree(rbuf);
		path_put(&mpath);
	}
	if (hymo_kern_path(target_str, LOOKUP_FOLLOW, &mpath) == 0) {
		tgt_dentry = dget(mpath.dentry);
		path_put(&mpath);
	}

	hash = full_name_hash(NULL, src_str, strlen(src_str));
	mutex_lock(&hymo_config_mutex);
	hlist_for_each_entry(existing,
		&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(existing->src, src_str) == 0 &&
		    strcmp(existing->target, target_str) == 0) {
			mutex_unlock(&hymo_config_mutex);
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			return false;
		}
	}
	me = kmalloc(sizeof(*me), GFP_KERNEL);
	if (me) {
		me->src = kstrdup(src_str, GFP_KERNEL);
		me->target = kstrdup(target_str, GFP_KERNEL);
		me->resolved_src = resolved_src;
		me->target_dentry = tgt_dentry;
		if (me->src && me->target) {
			hlist_add_head_rcu(&me->node,
				&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			resolved_src = NULL;
			tgt_dentry = NULL;
			created = true;
		} else {
			kfree(me->src);
			kfree(me->target);
			kfree(me);
		}
	}
	mutex_unlock(&hymo_config_mutex);

	if (created) {
		hymofs_add_inject_rule(kstrdup(src_str, GFP_KERNEL));
		if (me->resolved_src)
			hymofs_add_inject_rule(kstrdup(me->resolved_src,
						       GFP_KERNEL));
		hymofs_mark_dir_has_inject(src_str);
		if (me->resolved_src)
			hymofs_mark_dir_has_inject(me->resolved_src);
	}

	kfree(resolved_src);
	if (tgt_dentry)
		dput(tgt_dentry);
	return created;
}

struct hymo_mat_ctx {
	struct dir_context ctx;
	const char *src_prefix;
	const char *target_dir;
	int depth;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE
hymo_mat_filldir(struct dir_context *ctx, const char *name,
		 int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymo_mat_ctx *mc = container_of(ctx, struct hymo_mat_ctx, ctx);
	char *src_path, *tgt_path, *inj_dir;

	(void)offset; (void)ino;

	if (namlen <= 2 && name[0] == '.') {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			return HYMO_FILLDIR_CONTINUE;
	}
	if (namlen == 8 && memcmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	src_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->src_prefix, namlen, name);
	tgt_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->target_dir, namlen, name);
	if (!src_path || !tgt_path) {
		kfree(src_path);
		kfree(tgt_path);
		return HYMO_FILLDIR_CONTINUE;
	}

	/* For DT_DIR: register a nested merge_entry and recurse. Do NOT add a
	 * DT_DIR entry to hymo_paths — hymofs_resolve_target() matches it by
	 * exact strcmp in getname_flags, which would wholesale-redirect every
	 * lookup of this subdir (e.g. an open of /product/overlay/foo would
	 * resolve against the module's incomplete foo, hiding all real
	 * siblings). The nested merge_entry gives this subdir its own
	 * iterate_dir-time injection instead, so the real subdir contents stay
	 * visible.
	 *
	 * For non-directory children we still register an exact redirect in
	 * hymo_paths so open() of that file routes to the module backing.
	 */
	if (d_type == DT_DIR) {
		if (mc->depth < 8) {
			hymofs_register_nested_merge(src_path, tgt_path);
			hymofs_materialize_merge(src_path, tgt_path,
						 mc->depth + 1);
		}
	} else {
		hymofs_add_path_entry(src_path, tgt_path, d_type);
	}

	inj_dir = kstrdup(mc->src_prefix, GFP_KERNEL);
	if (inj_dir)
		hymofs_add_inject_rule(inj_dir);
	hymofs_mark_dir_has_inject(mc->src_prefix);

	kfree(src_path);
	kfree(tgt_path);
	return HYMO_FILLDIR_CONTINUE;
}

static HYMO_NOCFI void hymofs_materialize_merge(const char *src_prefix,
						const char *target_dir,
						int depth)
{
	struct path path;
	struct file *f;
	struct hymo_mat_ctx mctx;

	if (!hymo_kern_path || !hymo_dentry_open || depth > 8)
		return;
	if (hymo_kern_path(target_dir, LOOKUP_FOLLOW, &path) != 0)
		return;

	f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY, current_cred());
	if (IS_ERR(f)) {
		path_put(&path);
		return;
	}

	mctx.ctx.actor = hymo_mat_filldir;
	mctx.ctx.pos = 0;
	mctx.src_prefix = src_prefix;
	mctx.target_dir = target_dir;
	mctx.depth = depth;

	iterate_dir(f, &mctx.ctx);

	fput(f);
	path_put(&path);
}

/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

static inline bool hymo_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return true;
	return false;
}

static bool hymo_uid_in_allowlist(uid_t uid)
{
	void *p;

	if (!READ_ONCE(hymo_allowlist_loaded))
		return false;
	rcu_read_lock();
	p = xa_load(&hymo_allow_uids_xa, uid);
	rcu_read_unlock();
	return p != NULL;
}

bool hymo_should_apply_hide_rules(void)
{
	uid_t uid = __kuid_val(current_uid());

	/* uid 0 (root) always sees hidden - bypasses is_ksu_domain edge cases */
	if (unlikely(uid == 0))
		return false;

	/* Prefer real-time KSU check when available (always up-to-date with allowlist) */
	if (hymo_ksu_is_allow_uid_ptr)
		return !hymo_ksu_is_allow_uid_ptr(uid);

	/* Fallback: cached list from ksu_get_allow_list or file */
	if (!hymo_allowlist_loaded)
		return true;
	if (xa_empty(&hymo_allow_uids_xa))
		return true;
	return !hymo_uid_in_allowlist(uid);
}

/* Simplified KSU allowlist reload */
static bool hymo_should_umount_profile(const struct hymo_app_profile *p)
{
	if (p->allow_su)
		return false;
	if (p->nrp_config.use_default)
		return true;
	return p->nrp_config.profile.umount_modules;
}

static void hymo_add_allow_uid(uid_t uid)
{
	xa_store(&hymo_allow_uids_xa, uid, HYMO_UID_ALLOW_MARKER, GFP_KERNEL);
}

/*
 * GKI kernels protect many VFS symbols behind namespaces or don't export
 * them at all. We resolve ALL problematic VFS symbols via kprobe at init
 * time, so the module has zero direct VFS symbol dependencies.
 */
static struct file *(*hymo_filp_open)(const char *, int, umode_t);
static int (*hymo_filp_close)(struct file *, fl_owner_t);
static ssize_t (*hymo_kernel_read)(struct file *, void *, size_t, loff_t *);
/* hymo_kern_path, hymo_vfs_getattr, hymo_dentry_open declared above (merge/inject) */
static char *(*hymo_strndup_user)(const char __user *, long);
static struct filename *(*hymo_getname_kernel)(const char *);
static void (*hymo_ihold)(struct inode *);

/* KSU allowlist API (YukiSU/KernelSU PR #3093): bool ksu_get_allow_list(int *, u16, u16 *, u16 *, bool) */
typedef bool (*hymo_ksu_get_allow_list_fn)(int *array, u16 length, u16 *out_length,
					   u16 *out_total, bool allow);
static hymo_ksu_get_allow_list_fn hymo_ksu_get_allow_list_ptr;

static HYMO_NOCFI bool hymo_reload_ksu_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic = 0, version = 0;
	ssize_t ret;
	struct hymo_app_profile profile;
	int count = 0;

	if (!mutex_trylock(&hymo_config_mutex))
		return false;

	/* Prefer __ksu_is_allow_uid_for_current (handles uid 0 via is_ksu_domain) over __ksu_is_allow_uid */
	if (!hymo_ksu_is_allow_uid_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("__ksu_is_allow_uid_for_current");
		if (addr && hymofs_valid_kernel_addr(addr)) {
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
		}
	}
	if (!hymo_ksu_is_allow_uid_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("__ksu_is_allow_uid");
		if (addr && hymofs_valid_kernel_addr(addr)) {
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
		}
	}
	if (hymofs_kallsyms_lookup_name && !hymo_ksu_get_allow_list_ptr) {
		unsigned long addr = hymofs_kallsyms_lookup_name("ksu_get_allow_list");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_get_allow_list_ptr = (hymo_ksu_get_allow_list_fn)addr;
	}
	/* When KSU allowlist API available, use it for real-time check; skip cached list */
	if (hymo_ksu_is_allow_uid_ptr) {
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = true;
		mutex_unlock(&hymo_config_mutex);
		return true;
	}
	if (hymo_ksu_get_allow_list_ptr) {
		int *arr = kmalloc(HYMO_ALLOWLIST_UID_MAX * sizeof(int), GFP_KERNEL);

		if (arr) {
			u16 out_len = 0, out_total = 0;
			bool ok = hymo_ksu_get_allow_list_ptr(arr,
							     (u16)HYMO_ALLOWLIST_UID_MAX,
							     &out_len, &out_total, true);

			if (ok) {
				xa_destroy(&hymo_allow_uids_xa);
				hymo_allowlist_loaded = true;
				for (count = 0; count < out_len && count < HYMO_ALLOWLIST_UID_MAX; count++)
					if (arr[count] > 0)
						hymo_add_allow_uid((uid_t)arr[count]);
				if (out_len < out_total)
					hymo_log("allowlist truncated at %u (total %u)\n",
						 out_len, out_total);
				kfree(arr);
				mutex_unlock(&hymo_config_mutex);
				return true;
			}
			kfree(arr);
		}
	}

	/* Fallback: read allowlist from file (VFS symbols required) */
	if (!hymo_filp_open || !hymo_kernel_read) {
		mutex_unlock(&hymo_config_mutex);
		return false;
	}

	fp = hymo_filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = false;
		mutex_unlock(&hymo_config_mutex);
		return false;
	}

	ret = hymo_kernel_read(fp, &magic, sizeof(magic), &off);
	if (ret != sizeof(magic) || magic != HYMO_KSU_ALLOWLIST_MAGIC)
		goto bad;
	ret = hymo_kernel_read(fp, &version, sizeof(version), &off);
	if (ret != sizeof(version))
		goto bad;

	hymo_log("allowlist version %u\n", version);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = true;

	while (hymo_kernel_read(fp, &profile, sizeof(profile), &off) == sizeof(profile)) {
		if (!hymo_should_umount_profile(&profile) && profile.current_uid > 0) {
			hymo_add_allow_uid((uid_t)profile.current_uid);
			if (++count >= HYMO_ALLOWLIST_UID_MAX) {
				hymo_log("allowlist truncated at %d\n", count);
				break;
			}
		}
	}

	if (hymo_filp_close)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	mutex_unlock(&hymo_config_mutex);
	return true;

bad:
	pr_warn("HymoFS: allowlist load failed (magic/version or read error)\n");
	if (hymo_filp_close)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = false;
	mutex_unlock(&hymo_config_mutex);
	return false;
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

static char * __maybe_unused hymofs_resolve_target(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return NULL;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return NULL;

	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	/* Fast path: atomic + bloom before rcu_read_lock */
	if (atomic_read(&hymo_rule_count) == 0)
		return NULL;
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);
		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return NULL;
	}

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash &&
		    strcmp(entry->src, pathname) == 0) {
			target = kstrdup(entry->target, GFP_ATOMIC);
			rcu_read_unlock();
			return target;
		}
	}
	/*
	 * Merge trie is NOT consulted here for path redirect. Merge rules
	 * only affect directory listing (inject via iterate_dir). Individual
	 * file redirects are materialized into hymo_paths at ADD_MERGE_RULE
	 * time, so the bloom+hash exact match above handles them.
	 *
	 * The KPM version validated merge targets with kern_path() before
	 * redirecting. In LKM kprobe context we cannot sleep, so blind
	 * merge-trie redirect would send EVERY path under the merge prefix
	 * to the module dir — including original system files that don't
	 * exist there — breaking PMS and causing bootloop.
	 */

	rcu_read_unlock();
	return target;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

static bool __maybe_unused hymofs_should_hide(const char *pathname)
{
	struct hymo_hide_entry *he;
	u32 hash;
	size_t len;

	if (unlikely(!hymofs_enabled || !pathname || !*pathname))
		return false;
	if (unlikely(hymo_is_privileged_process()))
		return false;

	len = strlen(pathname);

	/* Stealth: always hide the mirror device */
	if (likely(hymo_stealth_enabled)) {
		size_t name_len = strlen(hymo_current_mirror_name);
		size_t path_len = strlen(hymo_current_mirror_path);

		if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
		    (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0))
			return true;
	}

	if (!hymo_should_apply_hide_rules())
		return false;

	/* Bloom fast-path */
	if (atomic_read(&hymo_hide_count) == 0)
		return false;

	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_hide_bloom) || !test_bit(bh2, hymo_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(he,
		&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool __maybe_unused hymofs_should_replace(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return false;
	if (atomic_read(&hymo_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use HYMO_IOC_* from hymo_magic.h)
 * GET_FD is syscall-only -> hymofs_get_anon_fd()
 * ====================================================================== */

static int hymo_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct hymo_syscall_arg req;
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (cmd == HYMO_IOC_CLEAR_ALL) {
		mutex_lock(&hymo_config_mutex);
		hymo_cleanup_locked();
		strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
		strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		mutex_unlock(&hymo_config_mutex);
		rcu_barrier();
		return 0;
	}

	if (cmd == HYMO_IOC_GET_VERSION) {
		int ver = HYMO_PROTOCOL_VERSION;
		if (copy_to_user(arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_debug_enabled = !!val;
		hymo_log("debug mode %s\n", hymo_debug_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == HYMO_IOC_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_stealth_enabled = !!val;
		hymo_log("stealth mode %s\n", hymo_stealth_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == HYMO_IOC_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = !!val;
		mutex_unlock(&hymo_config_mutex);
		hymo_log("HymoFS %s\n", hymofs_enabled ? "enabled" : "disabled");
		if (hymofs_enabled)
			hymo_reload_ksu_allowlist();
		return 0;
	}

	if (cmd == HYMO_IOC_REORDER_MNT_ID) {
		/* struct mnt_namespace/mount not exposed to LKM; only KPM (built-in) supports this */
		return -EOPNOTSUPP;
	}

	if (cmd == HYMO_IOC_LIST_RULES) {
		struct hymo_syscall_list_arg list_arg;
		struct hymo_xattr_sb_entry *sb_entry;
		struct hymo_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 64 * 1024)
			buf_size = 64 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);
		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->type);
		}
		hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s\n", hide_entry->path);
		}
		hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		/* Feature rules: mount_hide, maps_spoof, statfs_spoof, stealth */
		if (hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "mount_hide enabled\n");
		}
		if (hymo_feature_enabled_mask & HYMO_FEATURE_MAPS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "maps_spoof enabled\n");
		}
		if (hymo_feature_enabled_mask & HYMO_FEATURE_STATFS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "statfs_spoof enabled\n");
		}
		if (hymo_stealth_enabled) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "stealth enabled\n");
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MIRROR_PATH) {
		char *new_path, *new_name, *slash;
		size_t len;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (!req.src)
			return -EINVAL;
		new_path = hymo_strndup_user(req.src, PATH_MAX);
		if (IS_ERR(new_path))
			return PTR_ERR(new_path);

		len = strlen(new_path);
		if (len > 1 && new_path[len - 1] == '/')
			new_path[len - 1] = '\0';

		slash = strrchr(new_path, '/');
		new_name = kstrdup(slash ? slash + 1 : new_path, GFP_KERNEL);
		if (!new_name) {
			kfree(new_path);
			return -ENOMEM;
		}

		mutex_lock(&hymo_config_mutex);
		strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
		strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		mutex_unlock(&hymo_config_mutex);

		hymo_log("setting mirror path to: %s\n", hymo_mirror_path_buf);
		kfree(new_path);
		kfree(new_name);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_UNAME) {
		/* Scoped mode: stored config is applied per-task on first syscall
		 * from a hidden-uid process by unsharing CLONE_NEWUTS and writing
		 * the fake fields into the task's private uts_ns. */
		struct hymo_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		return hymofs_uname_set_scoped_config(&u);
	}

	if (cmd == HYMO_IOC_SET_UNAME_GLOBAL) {
		/* Global mode: rewrite init_uts_ns in place. All-empty struct
		 * restores originals. */
		struct hymo_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		if (u.sysname[0] || u.nodename[0] || u.release[0] ||
		    u.version[0] || u.machine[0] || u.domainname[0])
			return hymofs_uname_apply_global(&u);
		return hymofs_uname_restore_global();
	}

	if (cmd == HYMO_IOC_SET_CMDLINE) {
		struct hymo_spoof_cmdline *c = kmalloc(sizeof(*c), GFP_KERNEL);
		struct hymo_cmdline_rcu *new_cmdline, *old_cmdline;

		if (!c)
			return -ENOMEM;
		if (copy_from_user(c, arg, sizeof(*c))) {
			kfree(c);
			return -EFAULT;
		}
		new_cmdline = kmalloc(sizeof(*new_cmdline), GFP_KERNEL);
		if (!new_cmdline) {
			kfree(c);
			return -ENOMEM;
		}
		strscpy(new_cmdline->cmdline, c->cmdline, sizeof(new_cmdline->cmdline));
		mutex_lock(&hymo_config_mutex);
		old_cmdline = rcu_dereference_protected(hymo_spoof_cmdline_ptr,
							lockdep_is_held(&hymo_config_mutex));
		rcu_assign_pointer(hymo_spoof_cmdline_ptr, new_cmdline);
		mutex_unlock(&hymo_config_mutex);
		if (old_cmdline)
			kfree_rcu(old_cmdline, rcu);
		hymo_cmdline_spoof_active = (c->cmdline[0] != '\0');
		kfree(c);
		if (hymo_cmdline_spoof_active)
			hymo_log("cmdline: spoofed\n");
		return 0;
	}

	if (cmd == HYMO_IOC_ADD_SPOOF_KSTAT || cmd == HYMO_IOC_UPDATE_SPOOF_KSTAT) {
		struct hymo_spoof_kstat __user *u = (struct hymo_spoof_kstat __user *)arg;
		struct hymo_spoof_kstat *k;
		struct hymo_spoof_kstat_entry *e, *existing = NULL;
		size_t plen;
		u32 phash = 0;
		bool have_path;
		struct path resolved;
		unsigned long auto_ino = 0;

		k = kmalloc(sizeof(*k), GFP_KERNEL);
		if (!k)
			return -ENOMEM;
		if (copy_from_user(k, u, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		k->target_pathname[HYMO_MAX_LEN_PATHNAME - 1] = '\0';
		have_path = (k->target_pathname[0] != '\0');

		/* Auto-resolve target_ino from path if userspace did not supply one. */
		if (have_path && k->target_ino == 0 && hymo_kern_path) {
			if (hymo_kern_path(k->target_pathname, LOOKUP_FOLLOW, &resolved) == 0) {
				if (resolved.dentry && d_inode(resolved.dentry))
					auto_ino = (unsigned long)d_inode(resolved.dentry)->i_ino;
				path_put(&resolved);
			}
			if (auto_ino)
				k->target_ino = auto_ino;
		}

		if (!have_path && !k->target_ino) {
			k->err = -EINVAL;
			(void)copy_to_user(u, k, sizeof(*k));
			kfree(k);
			return -EINVAL;
		}

		if (have_path) {
			plen = strlen(k->target_pathname);
			phash = full_name_hash(NULL, k->target_pathname, plen);
		}

		mutex_lock(&hymo_config_mutex);

		/* Look for existing entry by path, then by ino. */
		if (have_path) {
			hlist_for_each_entry(e,
				&hymo_spoof_kstat_path[hash_min(phash, HYMO_HASH_BITS)], path_node) {
				if (e->path_hash == phash && e->target_pathname &&
				    strcmp(e->target_pathname, k->target_pathname) == 0) {
					existing = e;
					break;
				}
			}
		}
		if (!existing && k->target_ino) {
			hlist_for_each_entry(e,
				&hymo_spoof_kstat_ino[hash_min(k->target_ino, HYMO_HASH_BITS)],
				ino_node) {
				if (e->target_ino == k->target_ino &&
				    e->target_dev == 0) {
					existing = e;
					break;
				}
			}
		}

		if (existing && cmd == HYMO_IOC_ADD_SPOOF_KSTAT) {
			/* Idempotent ADD: treat as UPDATE. */
		}

		if (!existing) {
			e = kzalloc(sizeof(*e), GFP_KERNEL);
			if (!e) {
				mutex_unlock(&hymo_config_mutex);
				k->err = -ENOMEM;
				(void)copy_to_user(u, k, sizeof(*k));
				kfree(k);
				return -ENOMEM;
			}
			if (have_path) {
				e->target_pathname = kstrdup(k->target_pathname, GFP_KERNEL);
				if (!e->target_pathname) {
					kfree(e);
					mutex_unlock(&hymo_config_mutex);
					k->err = -ENOMEM;
					(void)copy_to_user(u, k, sizeof(*k));
					kfree(k);
					return -ENOMEM;
				}
				e->path_hash = phash;
			}
			e->target_ino = k->target_ino;
			e->target_dev = 0;
			e->spoofed_ino     = k->spoofed_ino;
			e->spoofed_dev     = k->spoofed_dev;
			e->spoofed_nlink   = k->spoofed_nlink;
			e->spoofed_size    = k->spoofed_size;
			e->spoofed_atime_sec  = k->spoofed_atime_sec;
			e->spoofed_atime_nsec = k->spoofed_atime_nsec;
			e->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			e->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			e->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			e->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			e->spoofed_blksize = k->spoofed_blksize;
			e->spoofed_blocks  = k->spoofed_blocks;
			e->is_static       = k->is_static;

			if (have_path)
				hlist_add_head_rcu(&e->path_node,
					&hymo_spoof_kstat_path[hash_min(phash, HYMO_HASH_BITS)]);
			if (e->target_ino)
				hlist_add_head_rcu(&e->ino_node,
					&hymo_spoof_kstat_ino[hash_min(e->target_ino, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_spoof_kstat_count);
			hymo_log("spoof_kstat: add path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 e->target_ino, e->spoofed_ino);
		} else {
			/* Update fields in place; readers may see torn values
			 * briefly, acceptable for stat() spoof. */
			existing->spoofed_ino     = k->spoofed_ino;
			existing->spoofed_dev     = k->spoofed_dev;
			existing->spoofed_nlink   = k->spoofed_nlink;
			existing->spoofed_size    = k->spoofed_size;
			existing->spoofed_atime_sec  = k->spoofed_atime_sec;
			existing->spoofed_atime_nsec = k->spoofed_atime_nsec;
			existing->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			existing->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			existing->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			existing->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			existing->spoofed_blksize = k->spoofed_blksize;
			existing->spoofed_blocks  = k->spoofed_blocks;
			existing->is_static       = k->is_static;

			/* If newly-resolved ino became available, link into ino table. */
			if (existing->target_ino == 0 && k->target_ino) {
				existing->target_ino = k->target_ino;
				hlist_add_head_rcu(&existing->ino_node,
					&hymo_spoof_kstat_ino[hash_min(k->target_ino, HYMO_HASH_BITS)]);
			}
			hymo_log("spoof_kstat: update path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 existing->target_ino, existing->spoofed_ino);
		}

		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);

		k->err = 0;
		if (copy_to_user(u, k, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		kfree(k);
		return 0;
	}

	if (cmd == HYMO_IOC_ADD_MAPS_RULE) {
		struct hymo_maps_rule __user *u = (struct hymo_maps_rule __user *)arg;
		struct hymo_maps_rule k;
		struct hymo_maps_rule_entry *e;

		if (copy_from_user(&k, u, sizeof(k)))
			return -EFAULT;
		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (!e) {
			k.err = -ENOMEM;
			if (copy_to_user(u, &k, sizeof(k)))
				return -EFAULT;
			return -ENOMEM;
		}
		e->target_ino = k.target_ino;
		e->target_dev = k.target_dev;
		e->spoofed_ino = k.spoofed_ino;
		e->spoofed_dev = k.spoofed_dev;
		strscpy(e->spoofed_pathname, k.spoofed_pathname, sizeof(e->spoofed_pathname));
		k.err = 0;
		if (copy_to_user(u, &k, sizeof(k))) {
			kfree(e);
			return -EFAULT;
		}
		mutex_lock(&hymo_maps_mutex);
		list_add_tail(&e->list, &hymo_maps_rules);
		mutex_unlock(&hymo_maps_mutex);
		return 0;
	}

	if (cmd == HYMO_IOC_CLEAR_MAPS_RULES) {
		struct hymo_maps_rule_entry *e, *tmp;

		mutex_lock(&hymo_maps_mutex);
		list_for_each_entry_safe(e, tmp, &hymo_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&hymo_maps_mutex);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MOUNT_HIDE) {
		struct hymo_mount_hide_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_MOUNT_HIDE;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_MOUNT_HIDE;
		/* path_pattern reserved for future custom hide rules */
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MAPS_SPOOF) {
		struct hymo_maps_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_MAPS_SPOOF;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_MAPS_SPOOF;
		/* reserved for future inline rule */
		return 0;
	}

	if (cmd == HYMO_IOC_SET_STATFS_SPOOF) {
		struct hymo_statfs_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_STATFS_SPOOF;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_STATFS_SPOOF;
		/* path/spoof_f_type reserved for future custom mappings */
		return 0;
	}

	if (cmd == HYMO_IOC_GET_FEATURES) {
		int features = 0;
		if (hymofs_uname_capable())
			features |= HYMO_FEATURE_UNAME_SPOOF;
		if (hymo_cmdline_kprobe_registered || hymo_cmdline_kretprobe_registered ||
		    (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered()))
			features |= HYMO_FEATURE_CMDLINE_SPOOF;
		features |= HYMO_FEATURE_KSTAT_SPOOF;
		features |= HYMO_FEATURE_MERGE_DIR;
		if (hymo_getxattr_kprobe_registered)
			features |= HYMO_FEATURE_SELINUX_BYPASS;
		if (hymo_mount_hide_vfsmnt_registered || hymo_mount_hide_mountinfo_registered ||
		    hymo_mount_hide_read_fallback_registered)
			features |= HYMO_FEATURE_MOUNT_HIDE;
		if (hymo_mount_hide_read_fallback_registered || hymo_maps_seq_read_registered)
			features |= HYMO_FEATURE_MAPS_SPOOF;
		if (hymo_statfs_kretprobe_registered)
			features |= HYMO_FEATURE_STATFS_SPOOF;
		if (copy_to_user(arg, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_GET_HOOKS) {
		struct hymo_syscall_list_arg list_arg;
		char *kbuf;
		size_t buf_size, written = 0;
		int n;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 2048)
			buf_size = 2048;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		/* GET_FD */
		if (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered())
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: tracepoint (sys_enter/sys_exit)\n");
		else if (hymo_ni_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (ni_syscall nr=%d)\n", hymo_syscall_nr_param);
		else if (hymo_reboot_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (reboot nr=%d)\n", hymo_syscall_nr_param);
		else
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: none\n");
		written += n;

		/* Path redirect */
		if (hymofs_tracepoint_path_registered())
			n = scnprintf(kbuf + written, buf_size - written, "path: tracepoint (sys_enter)\n");
		else if (hymo_getname_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "path: kprobe (getname_flags)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "path: none\n");
		written += n;

		/* VFS hooks */
		if (hymo_vfs_use_ftrace)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: ftrace+kretprobe\n");
		else
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: kprobe+kretprobe\n");
		written += n;

		/* uname */
		{
			const char *mode = "none";
			bool g = hymofs_uname_global_active();
			bool s = hymofs_uname_scoped_active();
			if (g && s)       mode = "utsname (global+scoped)";
			else if (g)        mode = "utsname (global)";
			else if (s)        mode = "utsname (scoped/uts_ns)";
			n = scnprintf(kbuf + written, buf_size - written,
				     "uname: %s\n", mode);
			written += n;
		}

		/* cmdline */
		if (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered())
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: tracepoint (sys_enter/sys_exit)\n");
		else if (hymo_cmdline_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kretprobe (read)\n");
		else if (hymo_cmdline_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kprobe (cmdline_proc_show)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: none\n");
		written += n;

		/* mountinfo/mounts hide */
		if (hymo_mount_hide_vfsmnt_registered && hymo_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kprobe (show_mountinfo, show_vfsmnt)\n");
		else if (hymo_mount_hide_vfsmnt_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mounts: kprobe (show_vfsmnt)\n");
		else if (hymo_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo: kprobe (show_mountinfo)\n");
		else if (hymo_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (read syscall buffer filter)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "mountinfo/mounts: none\n");
		written += n;

		/* maps spoof (read kretprobe or seq_read fallback) */
		if (hymo_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (read buffer filter)\n");
		else if (hymo_maps_seq_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (seq_read fallback)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "maps: none\n");
		written += n;
		if (hymo_statfs_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "statfs: kretprobe (f_type spoof for INCONSISTENT_MOUNT)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "statfs: none\n");
		written += n;

		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		if (written && copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	/* Commands that use hymo_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.src) {
		src = hymo_strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = hymo_strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	switch (cmd) {
	case HYMO_IOC_ADD_MERGE_RULE: {
		struct hymo_merge_entry *me;
		char *mat_src = NULL, *mat_tgt = NULL;

		if (!src || !target) { ret = -EINVAL; break; }

		/* Resolve symlinks: d_absolute_path in iterate_dir returns
		 * canonical paths (e.g. /product/overlay), while userspace sends
		 * symlink paths (e.g. /system/product/overlay). Store the
		 * canonical form as resolved_src for iterate_dir matching. */
		{
			char *resolved_src = NULL;
			struct dentry *tgt_dentry = NULL;
			struct path mpath;

			if (hymo_kern_path(src, LOOKUP_FOLLOW, &mpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && hymo_d_path) {
					char *res = hymo_d_path(&mpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/' &&
					    strcmp(res, src) != 0)
						resolved_src = kstrdup(res, GFP_KERNEL);
					kfree(rbuf);
				}
				path_put(&mpath);
			}
			if (hymo_kern_path(target, LOOKUP_FOLLOW, &mpath) == 0) {
				tgt_dentry = dget(mpath.dentry);
				path_put(&mpath);
			}

			hash = full_name_hash(NULL, src, strlen(src));
			mutex_lock(&hymo_config_mutex);

			hlist_for_each_entry(me,
				&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
				if (strcmp(me->src, src) == 0 &&
				    strcmp(me->target, target) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				me = kmalloc(sizeof(*me), GFP_KERNEL);
				if (me) {
					mat_src = kstrdup(src, GFP_KERNEL);
					mat_tgt = kstrdup(target, GFP_KERNEL);
					me->src = src;
					me->target = target;
					me->resolved_src = resolved_src;
					me->target_dentry = tgt_dentry;
					resolved_src = NULL;
					tgt_dentry = NULL;
					hlist_add_head_rcu(&me->node,
						&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
					src = NULL;
					target = NULL;
				} else {
					ret = -ENOMEM;
				}
			} else {
				ret = -EEXIST;
			}
			mutex_unlock(&hymo_config_mutex);
			if (!found && !ret) {
				hymo_log("add merge rule: src=%s, target=%s\n", me->src, me->target);
				hymofs_add_inject_rule(kstrdup(me->src, GFP_KERNEL));
				if (me->resolved_src)
					hymofs_add_inject_rule(kstrdup(me->resolved_src, GFP_KERNEL));
				hymofs_mark_dir_has_inject(me->src);
				if (me->resolved_src)
					hymofs_mark_dir_has_inject(me->resolved_src);
				if (mat_src && mat_tgt)
					hymofs_materialize_merge(mat_src, mat_tgt, 0);
			}
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			kfree(mat_src);
			kfree(mat_tgt);
		}
		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct path path;
		struct inode *src_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src || !target) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		/* Try to resolve full path */
		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res)) {
				resolved_src = kstrdup(res, GFP_KERNEL);
				{
					char *ls = strrchr(res, '/');
					if (ls) {
						if (ls == res)
							parent_dir = kstrdup("/", GFP_KERNEL);
						else {
							size_t l = ls - res;
							parent_dir = kmalloc(l + 1, GFP_KERNEL);
							if (parent_dir) {
								memcpy(parent_dir, res, l);
								parent_dir[l] = '\0';
							}
						}
					}
				}
			}
			if (d_inode(path.dentry)) {
				src_inode = d_inode(path.dentry);
				hymo_ihold(src_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		} else {
			char *ls = strrchr(src, '/');
			if (ls && ls != src) {
				size_t l = ls - src;
				char *p_str = kmalloc(l + 1, GFP_KERNEL);
				if (p_str) {
					memcpy(p_str, src, l);
					p_str[l] = '\0';
					if (hymo_kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
						char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
						if (!IS_ERR(res)) {
							size_t rl = strlen(res);
							size_t nl = strlen(ls);
							resolved_src = kmalloc(rl + nl + 1, GFP_KERNEL);
							if (resolved_src) {
								strcpy(resolved_src, res);
								strcat(resolved_src, ls);
							}
							parent_dir = kstrdup(res, GFP_KERNEL);
						}
						path_put(&path);
					}
					kfree(p_str);
				}
			}
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				char *old_t = entry->target;
				char *new_t = kstrdup(target, GFP_KERNEL);
				if (new_t) {
					hlist_del_rcu(&entry->target_node);
					rcu_assign_pointer(entry->target, new_t);
					entry->type = req.type;
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, new_t, strlen(new_t)),
							HYMO_HASH_BITS)]);
					kfree(old_t);
				}
				found = true;
				break;
			}
		}
		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (entry) {
				entry->src = kstrdup(src, GFP_KERNEL);
				entry->target = kstrdup(target, GFP_KERNEL);
				entry->type = req.type;
				entry->src_hash = hash;
				if (entry->src && entry->target) {
					unsigned long h1, h2;
					hlist_add_head_rcu(&entry->node,
						&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, entry->target,
								strlen(entry->target)),
							HYMO_HASH_BITS)]);
					h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_path_bloom);
					set_bit(h2, hymo_path_bloom);
					atomic_inc(&hymo_rule_count);
					hymo_log("add rule: src=%s, target=%s, type=%d\n", src, target, req.type);
				} else {
					kfree(entry->src);
					kfree(entry->target);
					kfree(entry);
				}
			}
		}
		mutex_unlock(&hymo_config_mutex);

		if (parent_dir) {
			hymofs_add_inject_rule(parent_dir);
			hymofs_mark_dir_has_inject(parent_dir);
		}

		/* Do not mark redirect source as hidden: we do not inject a virtual
		 * entry for simple ADD_RULE, so hiding would make the file disappear
		 * from the listing. Open of the path is still redirected via getname. */
		if (src_inode)
			iput(src_inode);
		if (parent_inode)
			iput(parent_inode);

		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_HIDE_RULE: {
		char *resolved_src = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res))
				resolved_src = kstrdup(res, GFP_KERNEL);
			if (d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				hymo_ihold(target_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		if (target_inode) {
			hymofs_mark_inode_hidden(target_inode);
			iput(target_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			hide_entry = kmalloc(sizeof(*hide_entry), GFP_KERNEL);
			if (hide_entry) {
				hide_entry->path = kstrdup(src, GFP_KERNEL);
				hide_entry->path_hash = hash;
				if (hide_entry->path) {
					unsigned long h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					unsigned long h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_hide_bloom);
					set_bit(h2, hymo_hide_bloom);
					atomic_inc(&hymo_hide_count);
					hlist_add_head_rcu(&hide_entry->node,
						&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hymo_log("hide rule: src=%s\n", src);
				} else {
					kfree(hide_entry);
				}
			}
		}
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_HIDE_OVERLAY_XATTRS: {
		struct path path;
		struct hymo_xattr_sb_entry *sb_entry;
		bool xfound = false;

		if (!src) { ret = -EINVAL; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			struct super_block *sb = path.dentry->d_sb;

			mutex_lock(&hymo_config_mutex);
			hlist_for_each_entry(sb_entry,
				&hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)], node) {
				if (sb_entry->sb == sb) {
					xfound = true;
					break;
				}
			}
			if (!xfound) {
				sb_entry = kmalloc(sizeof(*sb_entry), GFP_KERNEL);
				if (sb_entry) {
					sb_entry->sb = sb;
					hlist_add_head_rcu(&sb_entry->node,
						&hymo_xattr_sbs[hash_min((unsigned long)sb,
							HYMO_HASH_BITS)]);
					hymo_log("hide xattrs for sb %p (path: %s)\n", sb, src);
				}
			}
			hymofs_enabled = true;
			mutex_unlock(&hymo_config_mutex);
			path_put(&path);
		} else {
			ret = -ENOENT;
		}
		break;
	}

	case HYMO_IOC_DEL_RULE: {
		struct inode *del_inode = NULL;
		struct inode *del_parent_inode = NULL;

		if (!src) { ret = -EINVAL; break; }

		/* Resolve symlinks so the path matches what ADD_RULE stored */
		if (hymo_kern_path) {
			struct path dpath;
			if (hymo_kern_path(src, LOOKUP_FOLLOW, &dpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && hymo_d_path) {
					char *res = hymo_d_path(&dpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/') {
						char *resolved = kstrdup(res, GFP_KERNEL);
						if (resolved) {
							kfree(src);
							src = resolved;
						}
					}
				}
				if (d_inode(dpath.dentry)) {
					del_inode = d_inode(dpath.dentry);
					hymo_ihold(del_inode);
				}
				if (dpath.dentry->d_parent &&
				    d_inode(dpath.dentry->d_parent)) {
					del_parent_inode = d_inode(dpath.dentry->d_parent);
					hymo_ihold(del_parent_inode);
				}
				kfree(rbuf);
				path_put(&dpath);
			}
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&hymo_rule_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&entry->rcu, hymo_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				hlist_del_rcu(&hide_entry->node);
				atomic_dec(&hymo_hide_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(inject_entry,
			&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, src) == 0) {
				hlist_del_rcu(&inject_entry->node);
				atomic_dec(&hymo_rule_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
				goto del_done;
			}
		}
del_done:
		mutex_unlock(&hymo_config_mutex);
		if (del_inode) {
			if (del_inode->i_mapping)
				clear_bit(AS_FLAGS_HYMO_HIDE,
					  &del_inode->i_mapping->flags);
			iput(del_inode);
		}
		if (del_parent_inode) {
			iput(del_parent_inode);
		}
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	kfree(src);
	kfree(target);
	return ret;
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

static HYMO_NOCFI long hymofs_dev_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	long ret;

	atomic_long_set(&hymo_ioctl_tgid, (long)task_tgid_vnr(current));
	switch (cmd) {
	case HYMO_IOC_GET_VERSION:
	case HYMO_IOC_SET_ENABLED:
	case HYMO_IOC_ADD_RULE:
	case HYMO_IOC_DEL_RULE:
	case HYMO_IOC_HIDE_RULE:
	case HYMO_IOC_CLEAR_ALL:
	case HYMO_IOC_LIST_RULES:
	case HYMO_IOC_SET_DEBUG:
	case HYMO_IOC_REORDER_MNT_ID:
	case HYMO_IOC_SET_STEALTH:
	case HYMO_IOC_HIDE_OVERLAY_XATTRS:
	case HYMO_IOC_ADD_MERGE_RULE:
	case HYMO_IOC_SET_MIRROR_PATH:
	case HYMO_IOC_GET_HOOKS:
	case HYMO_IOC_SET_UNAME:
	case HYMO_IOC_SET_UNAME_GLOBAL:
	case HYMO_IOC_ADD_MAPS_RULE:
	case HYMO_IOC_CLEAR_MAPS_RULES:
	case HYMO_IOC_GET_FEATURES:
	case HYMO_IOC_SET_MOUNT_HIDE:
	case HYMO_IOC_SET_MAPS_SPOOF:
	case HYMO_IOC_SET_STATFS_SPOOF:
	case HYMO_IOC_ADD_SPOOF_KSTAT:
	case HYMO_IOC_UPDATE_SPOOF_KSTAT:
		ret = hymo_dispatch_cmd(cmd, (void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	atomic_long_set(&hymo_ioctl_tgid, 0);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; syscall returns this fd)
 * ====================================================================== */

static const struct file_operations hymo_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = hymofs_dev_ioctl,
	.compat_ioctl   = hymofs_dev_ioctl,
	.llseek         = noop_llseek,
};

/**
 * hymofs_get_anon_fd - Create and return anonymous fd for HymoFS.
 * Returns fd on success, negative errno on failure.
 */
int hymofs_get_anon_fd(void)
{
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	fd = anon_inode_getfd("hymo", &hymo_anon_fops, NULL, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;
	pid = task_tgid_vnr(current);
	WRITE_ONCE(hymo_daemon_pid, pid);
	hymo_log("Daemon PID auto-registered: %d\n", pid);
	return fd;
}
EXPORT_SYMBOL_GPL(hymofs_get_anon_fd);

/* GET_FD via kprobe on ni_syscall (unused nr) or __arm64_sys_reboot (142). Default 142 = SYS_reboot for 5.10 compat. */
module_param_named(hymo_syscall_nr, hymo_syscall_nr_param, int, 0600);
MODULE_PARM_DESC(hymo_syscall_nr, "For ni_syscall path: unused syscall nr (e.g. 448). Primary path is SYS_reboot(142) via __arm64_sys_reboot kprobe.");

/* Force skip sys_enter tracepoint (use kprobe). 1=skip, 0=try tracepoint first. */
static int hymo_no_tracepoint_param;
module_param_named(hymo_no_tracepoint, hymo_no_tracepoint_param, int, 0600);
MODULE_PARM_DESC(hymo_no_tracepoint, "1=skip sys_enter tracepoint, use kprobe. 0=try tracepoint first (default).");

/* Debug: skip various initialization stages to isolate crash */
static int hymo_skip_vfs_param;
module_param_named(hymo_skip_vfs, hymo_skip_vfs_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_vfs, "1=skip VFS hooks (ftrace+kprobes). For debugging crash.");

static int hymo_skip_extra_kprobes_param;
module_param_named(hymo_skip_extra_kprobes, hymo_skip_extra_kprobes_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_extra_kprobes, "1=skip extra kprobes (reboot,prctl,uname,cmdline). For debugging.");

static int hymo_skip_getfd_param;
module_param_named(hymo_skip_getfd, hymo_skip_getfd_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_getfd, "1=skip GET_FD kprobe/tracepoint. For debugging crash.");

static int hymo_skip_kallsyms_param;
module_param_named(hymo_skip_kallsyms, hymo_skip_kallsyms_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_kallsyms, "1=skip kallsyms resolution, use per-symbol kprobe. For GKI compatibility.");

/* Dummy mode: exit immediately after first log - for testing module loading */
static int hymo_dummy_mode_param;
module_param_named(hymo_dummy_mode, hymo_dummy_mode_param, int, 0600);
MODULE_PARM_DESC(hymo_dummy_mode, "1=exit immediately after init starts (for testing).");

/* override_fd/override_active and cmdline_ctx now in hymo_percpu_base */

static int hymo_ni_syscall_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	unsigned long nr = regs->regs[8];
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
#elif defined(__x86_64__)
	unsigned long nr = regs->orig_ax;
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
#else
	unsigned long nr = 0, a0 = 0, a1 = 0, a2 = 0;
#endif
	if (nr != (unsigned long)hymo_syscall_nr_param)
		return 0;
	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		if (fd < 0)
			return 0;
		hymo_this_cpu()->override_fd = fd;
		hymo_this_cpu()->override_active = 1;
	}
	return 0;
}

/*
 * kretprobe handler: replace function return value (x0) with our fd.
 *
 * On aarch64 >= 4.16 the call chain is:
 *   invoke_syscall() {
 *       ret = __arm64_sys_reboot(regs);  // <-- kretprobe fires here
 *       regs->regs[0] = ret;             // stores ret into user pt_regs
 *   }
 * So we MUST modify the kretprobe's own regs->regs[0] (= function return value x0).
 * invoke_syscall will then copy our fd into the user's pt_regs.
 * Writing to real_regs directly would be overwritten by invoke_syscall.
 */
static int hymo_ni_syscall_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!hymo_this_cpu()->override_active)
		return 0;
#if defined(__aarch64__)
	regs->regs[0] = hymo_this_cpu()->override_fd;
#elif defined(__x86_64__)
	regs->ax = hymo_this_cpu()->override_fd;
#endif
	hymo_this_cpu()->override_active = 0;
	return 0;
}

static struct kprobe hymo_kp_ni = {
	.pre_handler = hymo_ni_syscall_pre,
};
static struct kretprobe hymo_krp_ni = {
	.handler = hymo_ni_syscall_ret,
};

/*
 * GET_FD via kprobe on __arm64_sys_reboot (same as susfs/KernelSU old kprobes).
 * When userspace calls SYS_reboot(142) with our magic, we intercept and return fd in kretprobe.
 * Real reboot sees invalid magic and returns -EINVAL; we overwrite return value with fd.
 * Compatible with 5.10+; use this when ni_syscall path is not available.
 */
static int hymo_reboot_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * On aarch64 4.16+, __arm64_sys_reboot is a wrapper: first arg (regs->regs[0])
	 * is the pointer to the real syscall pt_regs. Read magic from there.
	 *
	 * We use the KernelSU approach: write fd to userspace via put_user on the
	 * 4th syscall argument (a user pointer). This avoids kretprobe return value
	 * issues entirely — invoke_syscall would overwrite any kretprobe changes.
	 *
	 * Userspace: int fd = -1; syscall(SYS_reboot, M1, M2, CMD, &fd);
	 */
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long a0, a1, a2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	a0 = real_regs->regs[0];
	a1 = real_regs->regs[1];
	a2 = real_regs->regs[2];

	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = hymofs_get_anon_fd();
	if (fd < 0)
		return 0;

	/* Write fd to userspace via 4th arg pointer (like KernelSU) */
	fd_ptr = (int __user *)(unsigned long)real_regs->regs[3];
	if (fd_ptr)
		put_user(fd, fd_ptr);
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;

	if (a0 != HYMO_MAGIC1 || a1 != HYMO_MAGIC2 || a2 != (unsigned long)HYMO_CMD_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		if (fd < 0)
			return 0;
		hymo_this_cpu()->override_fd = fd;
		hymo_this_cpu()->override_active = 1;
	}
#endif
	return 0;
}

static struct kprobe hymo_kp_reboot = {
	.pre_handler = hymo_reboot_pre,
};
static struct kretprobe hymo_krp_reboot = {
	.handler = hymo_ni_syscall_ret, /* same: replace return with fd */
};

/*
 * GET_FD via prctl (SECCOMP-safe). option=HYMO_PRCTL_GET_FD, arg2=(int *) for fd.
 * No kretprobe: we put_user(fd, arg2) in pre_handler; syscall return value ignored.
 */
static int hymo_prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__aarch64__)
	struct pt_regs *real_regs;
	unsigned long option;
	unsigned long arg2;
	int __user *fd_ptr;
	int fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	real_regs = (struct pt_regs *)regs->regs[0];
#else
	real_regs = regs;
#endif
	option = real_regs->regs[0];
	arg2 = real_regs->regs[1];

	if (option != (unsigned long)HYMO_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;

	fd = hymofs_get_anon_fd();
	if (fd < 0)
		return 0;

	fd_ptr = (int __user *)(unsigned long)arg2;
	if (fd_ptr && put_user(fd, fd_ptr) != 0)
		pr_err("HymoFS: prctl GET_FD put_user failed\n");
#elif defined(__x86_64__)
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;

	if (option != (unsigned long)HYMO_PRCTL_GET_FD)
		return 0;
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	{
		int fd = hymofs_get_anon_fd();
		int __user *fd_ptr;

		if (fd < 0)
			return 0;
		fd_ptr = (int __user *)(unsigned long)arg2;
		if (fd_ptr && put_user(fd, fd_ptr) != 0)
			pr_err("HymoFS: prctl GET_FD put_user failed\n");
	}
#endif
	return 0;
}

static struct kprobe hymo_kp_prctl = {
	.pre_handler = hymo_prctl_pre,
};
static int hymo_prctl_kprobe_registered;

/* ======================================================================
 * cmdline spoofing: kprobe pre_handler on cmdline_proc_show
 * When spoof active, write fake cmdline to seq_file and skip original.
 * ====================================================================== */

static int hymo_cmdline_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct seq_file *m;
	bool did_spoof = false;
	pid_t pid;

	if (!READ_ONCE(hymo_cmdline_spoof_active))
		return 0;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return 0;

#if defined(__aarch64__)
	m = (struct seq_file *)regs->regs[0];
#elif defined(__x86_64__)
	m = (struct seq_file *)regs->di;
#else
	return 0;
#endif

	rcu_read_lock();
	{
		struct hymo_cmdline_rcu *c = rcu_dereference(hymo_spoof_cmdline_ptr);
		if (c && c->cmdline[0]) {
			seq_puts(m, c->cmdline);
			seq_putc(m, '\n');
			did_spoof = true;
		}
	}
	rcu_read_unlock();

	if (!did_spoof)
		return 0;

	/* Skip original: set PC to return address, return value 0 */
#if defined(__aarch64__)
	instruction_pointer_set(regs, regs->regs[30]);
	regs->regs[0] = 0;
#elif defined(__x86_64__)
	instruction_pointer_set(regs, *(unsigned long *)regs->sp);
	regs->sp += sizeof(unsigned long);
	regs->ax = 0;
#endif
	return 1;
}

static struct kprobe hymo_kp_cmdline = {
	.pre_handler = hymo_cmdline_pre,
};

/* ======================================================================
 * /proc mount map hiding: kprobe pre_handler on show_vfsmnt / show_mountinfo
 * Hide overlay mounts so /proc/mounts and /proc/pid/mountinfo show no overlay.
 * Defeats "OverlayFS detected but no overlay in mountinfo" style detectors.
 * ====================================================================== */

static int hymo_mount_hide_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct vfsmount *mnt;
	struct super_block *sb;
	struct file_system_type *fstype;

	if (!(hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE))
		return 0;

#if defined(__aarch64__)
	mnt = (struct vfsmount *)regs->regs[1];
#elif defined(__x86_64__)
	mnt = (struct vfsmount *)regs->si;
#else
	return 0;
#endif
	if (!mnt || !hymofs_valid_kernel_addr((unsigned long)mnt))
		return 0;
	sb = mnt->mnt_sb;
	if (!sb || !hymofs_valid_kernel_addr((unsigned long)sb))
		return 0;
	fstype = sb->s_type;
	if (!fstype || !hymofs_valid_kernel_addr((unsigned long)fstype) || !fstype->name)
		return 0;
	if (strcmp(fstype->name, "overlay") != 0)
		return 0;

	/* Skip this line: do not call original, return 0 */
#if defined(__aarch64__)
	instruction_pointer_set(regs, regs->regs[30]);
	regs->regs[0] = 0;
#elif defined(__x86_64__)
	instruction_pointer_set(regs, *(unsigned long *)regs->sp);
	regs->sp += sizeof(unsigned long);
	regs->ax = 0;
#endif
	return 1;
}

static struct kprobe hymo_kp_show_vfsmnt = {
	.pre_handler = hymo_mount_hide_pre,
};
static struct kprobe hymo_kp_show_mountinfo = {
	.pre_handler = hymo_mount_hide_pre,
};

/* Preferred path: filter overlay lines from read() when fd is /proc/.../mountinfo or /proc/mounts.
 * Uses syscall kretprobe only (less overhead, can share with other syscall handling). */
#define HYMO_READ_MOUNT_FILTER_BUF 65536
static char *hymo_read_filter_buf;
static DEFINE_MUTEX(hymo_read_filter_mutex);

struct hymo_read_mount_ri_data {
	int fd;
	void __user *buf;
	size_t count;
};

static int hymo_read_mount_filter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_read_mount_ri_data *d = (struct hymo_read_mount_ri_data *)ri->data;
#if defined(__aarch64__)
	d->fd = (int)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->count = (size_t)regs->regs[2];
#elif defined(__x86_64__)
	d->fd = (int)regs->di;
	d->buf = (void __user *)regs->si;
	d->count = (size_t)regs->dx;
#else
	d->fd = -1;
	d->buf = NULL;
	d->count = 0;
#endif
	return 0;
}

/* Remove lines containing " overlay " (mountinfo/mounts format); in-place, return new length */
static size_t hymo_filter_overlay_lines(char *kbuf, size_t len)
{
	size_t out = 0;
	size_t i = 0;

	while (i < len) {
		size_t line_start = i;
		while (i < len && kbuf[i] != '\n')
			i++;
		if (i > line_start) {
			size_t line_len = i - line_start;
			/* Skip line if it contains " overlay " (space-padded to avoid false hits) */
			bool is_overlay = false;
			size_t j;
			for (j = line_start; j + 8 <= line_start + line_len; j++) {
				if (kbuf[j] == ' ' && kbuf[j+1] == 'o' && kbuf[j+2] == 'v' &&
				    kbuf[j+3] == 'e' && kbuf[j+4] == 'r' && kbuf[j+5] == 'l' &&
				    kbuf[j+6] == 'a' && kbuf[j+7] == 'y' &&
				    (j + 8 == line_start + line_len || kbuf[j+8] == ' ' || kbuf[j+8] == '\n')) {
					is_overlay = true;
					break;
				}
			}
			if (!is_overlay) {
				if (out != line_start)
					memmove(kbuf + out, kbuf + line_start, line_len);
				out += line_len;
				if (i < len) {
					kbuf[out++] = '\n';
					i++;
				}
			} else if (i < len) {
				i++; /* skip newline of the dropped overlay line */
			}
		} else {
			if (i < len)
				i++;
		}
	}
	return out;
}

/* Parse one maps line; return 0 on success. Fills in start,end,flags,pgoff,dev,ino,pathname.
 * Maps line format: start-end flags pgoff major:minor ino pathname */
static int hymo_parse_maps_line(const char *line, size_t line_len,
		unsigned long *start, unsigned long *end, char *flags,
		unsigned long *pgoff, unsigned long *dev, unsigned long *ino,
		const char **pathname)
{
	unsigned int ma, mi;
	const char *p = line;
	char *endptr;

	if (line_len < 45) /* min "xxxxxxxx-xxxxxxxx xxxx xxxxxxxx xx:xx x \n" */
		return -1;
	*start = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != '-')
		return -1;
	p = endptr + 1;
	*end = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != ' ')
		return -1;
	p = endptr + 1;
	flags[0] = p[0]; flags[1] = p[1]; flags[2] = p[2]; flags[3] = p[3];
	flags[4] = '\0';
	p += 4;
	if (*p != ' ')
		return -1;
	*pgoff = simple_strtoul(p + 1, &endptr, 16);
	p = endptr;
	if (*p != ' ')
		return -1;
	ma = (unsigned int)simple_strtoul(p + 1, &endptr, 16);
	if (*endptr != ':')
		return -1;
	mi = (unsigned int)simple_strtoul(endptr + 1, &endptr, 16);
	*dev = (unsigned long)MKDEV(ma, mi);
	p = endptr;
	if (*p != ' ')
		return -1;
	*ino = simple_strtoul(p + 1, &endptr, 10);
	p = endptr;
	while (*p == ' ')
		p++;
	*pathname = p;
	return 0;
}

/* Filter /proc/pid/maps buffer: replace lines matching a rule with spoofed ino/dev/pathname.
 * In-place; spoofed line must not exceed original line length (pathname truncated if needed).
 * Returns new length. */
static size_t hymo_filter_maps_lines(char *kbuf, size_t len)
{
	size_t in = 0, out = 0;
	struct hymo_maps_rule_entry *r;
	const char *pathname;
	char flags[5];
	unsigned long start, end, pgoff, dev, ino;
	unsigned long spoof_ino, spoof_dev;
	const char *spoof_name;
	size_t path_len, max_path;
	int n;

	if (list_empty(&hymo_maps_rules))
		return len;

	while (in < len) {
		size_t line_start;
		size_t line_len;

		line_start = in;
		while (in < len && kbuf[in] != '\n')
			in++;
		if (in <= line_start) {
			if (in < len)
				in++;
			continue;
		}
		line_len = in - line_start;
		if (kbuf[in] == '\n')
			line_len++;
		if (hymo_parse_maps_line(kbuf + line_start, line_len,
					 &start, &end, flags, &pgoff, &dev, &ino, &pathname) != 0) {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
			in += (in < len && kbuf[in] == '\n') ? 1 : 0;
			continue;
		}
		spoof_ino = ino;
		spoof_dev = dev;
		spoof_name = pathname;
		mutex_lock(&hymo_maps_mutex);
		list_for_each_entry(r, &hymo_maps_rules, list) {
			if (r->target_ino != ino)
				continue;
			if (r->target_dev != 0 && r->target_dev != dev)
				continue;
			spoof_ino = r->spoofed_ino;
			spoof_dev = r->spoofed_dev;
			spoof_name = r->spoofed_pathname;
			break;
		}
		mutex_unlock(&hymo_maps_mutex);
		if (spoof_ino != ino || spoof_dev != dev || spoof_name != pathname) {
			/* Format new line; must not exceed line_len. */
			max_path = line_len;
			if (max_path > 1)
				max_path -= 1; /* \n */
			/* Reserve "%08lx-%08lx %s %08lx %02x:%02x %lu " = 8+1+8+1+4+1+8+1+5+1+max(ino)=20 ~56 */
			if (max_path > 56)
				max_path -= 56;
			else
				max_path = 0;
			n = scnprintf(kbuf + out, len - out, "%08lx-%08lx %s %08lx %02x:%02x %lu ",
				      start, end, flags, pgoff,
				      (unsigned int)MAJOR(spoof_dev), (unsigned int)MINOR(spoof_dev),
				      spoof_ino);
			path_len = strnlen(spoof_name, max_path);
			if ((size_t)line_len > n + 1 && n + path_len + 1 > line_len)
				path_len = (size_t)line_len - n - 1;
			if (path_len > 0)
				memcpy(kbuf + out + n, spoof_name, path_len);
			n += path_len;
			if (n < len - out)
				kbuf[out + n] = '\n';
			n++;
			out += n;
		} else {
			if (out != line_start)
				memmove(kbuf + out, kbuf + line_start, line_len);
			out += line_len;
		}
		if (in < len && kbuf[in] == '\n')
			in++;
	}
	return out;
}

static int hymo_read_mount_filter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
	struct hymo_read_mount_ri_data *d = (struct hymo_read_mount_ri_data *)ri->data;
	struct file *f;
	char *path_buf;
	size_t new_len;

	/* Fast path: skip when both mount_hide and maps_spoof are disabled */
	if (!(hymo_feature_enabled_mask & (HYMO_FEATURE_MOUNT_HIDE | HYMO_FEATURE_MAPS_SPOOF)))
		return 0;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret <= 0 || d->fd < 0 || !d->buf || ret > HYMO_READ_MOUNT_FILTER_BUF)
		return 0;
	if (!hymo_read_filter_buf)
		return 0;

	f = fget(d->fd);
	if (!f)
		return 0;
	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf) {
		fput(f);
		return 0;
	}
	path_buf[0] = '\0';
	d_path(&f->f_path, path_buf, PAGE_SIZE);
	fput(f);

	mutex_lock(&hymo_read_filter_mutex);
	if (copy_from_user(hymo_read_filter_buf, d->buf, (size_t)ret)) {
		mutex_unlock(&hymo_read_filter_mutex);
		return 0;
	}

	/* /proc/.../mountinfo or /proc/mounts: filter overlay lines */
	if ((hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) &&
	    strncmp(path_buf, "/proc/", 6) == 0 &&
	    (strstr(path_buf, "mountinfo") || strstr(path_buf, "/mounts"))) {
		free_page((unsigned long)path_buf);
		new_len = hymo_filter_overlay_lines(hymo_read_filter_buf, (size_t)ret);
		if (new_len < (size_t)ret) {
			if (copy_to_user(d->buf, hymo_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&hymo_read_filter_mutex);
		return 0;
	}

	/* /proc/.../maps or .../smaps: spoof ino/dev/pathname by rule */
	if ((hymo_feature_enabled_mask & HYMO_FEATURE_MAPS_SPOOF) &&
	    strncmp(path_buf, "/proc/", 6) == 0 &&
	    (strstr(path_buf, "/maps") || strstr(path_buf, "/smaps"))) {
		free_page((unsigned long)path_buf);
		new_len = hymo_filter_maps_lines(hymo_read_filter_buf, (size_t)ret);
		if (new_len != (size_t)ret) {
			if (copy_to_user(d->buf, hymo_read_filter_buf, new_len) == 0) {
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
				regs->ax = (unsigned long)new_len;
#endif
			}
		}
		mutex_unlock(&hymo_read_filter_mutex);
		return 0;
	}

	free_page((unsigned long)path_buf);
	mutex_unlock(&hymo_read_filter_mutex);
	return 0;
}

static struct kretprobe hymo_krp_read_mount_filter = {
	.entry_handler = hymo_read_mount_filter_entry,
	.handler = hymo_read_mount_filter_ret,
	.data_size = sizeof(struct hymo_read_mount_ri_data),
	.maxactive = 64,
};

/* Maps spoof fallback when read syscall path unavailable: kretprobe on seq_read.
 * seq_read(file,buf,size,ppos) is used by /proc/pid/maps. Filter only maps/smaps paths. */
static char *hymo_maps_spoof_buf;
static DEFINE_MUTEX(hymo_maps_spoof_mutex);

struct hymo_seq_read_ri_data {
	struct file *file;
	void __user *buf;
	size_t size;
};

static int hymo_seq_read_maps_filter_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_seq_read_ri_data *d = (struct hymo_seq_read_ri_data *)ri->data;
#if defined(__aarch64__)
	d->file = (struct file *)regs->regs[0];
	d->buf = (void __user *)regs->regs[1];
	d->size = (size_t)regs->regs[2];
#elif defined(__x86_64__)
	d->file = (struct file *)regs->di;
	d->buf = (void __user *)regs->si;
	d->size = (size_t)regs->dx;
#else
	d->file = NULL;
	d->buf = NULL;
	d->size = 0;
#endif
	return 0;
}

static int hymo_seq_read_maps_filter_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
	struct hymo_seq_read_ri_data *d = (struct hymo_seq_read_ri_data *)ri->data;
	char *path_buf;
	size_t new_len;

	if (!(hymo_feature_enabled_mask & HYMO_FEATURE_MAPS_SPOOF))
		return 0;
	if (!d->file || !d->buf || !hymo_maps_spoof_buf || !hymo_d_path)
		return 0;

#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret <= 0 || ret > HYMO_READ_MOUNT_FILTER_BUF)
		return 0;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf)
		return 0;
	path_buf[0] = '\0';
	hymo_d_path(&d->file->f_path, path_buf, PAGE_SIZE);
	if (path_buf[0] != '/' || strncmp(path_buf, "/proc/", 6) != 0 ||
	    (!strstr(path_buf, "/maps") && !strstr(path_buf, "/smaps"))) {
		free_page((unsigned long)path_buf);
		return 0;
	}
	free_page((unsigned long)path_buf);

	mutex_lock(&hymo_maps_spoof_mutex);
	if (copy_from_user(hymo_maps_spoof_buf, d->buf, (size_t)ret)) {
		mutex_unlock(&hymo_maps_spoof_mutex);
		return 0;
	}
	new_len = hymo_filter_maps_lines(hymo_maps_spoof_buf, (size_t)ret);
	if (new_len != (size_t)ret) {
		if (copy_to_user(d->buf, hymo_maps_spoof_buf, new_len) == 0) {
#if defined(__aarch64__)
			regs->regs[0] = (unsigned long)new_len;
#elif defined(__x86_64__)
			regs->ax = (unsigned long)new_len;
#endif
		}
	}
	mutex_unlock(&hymo_maps_spoof_mutex);
	return 0;
}

static struct kretprobe hymo_krp_seq_read_maps = {
	.entry_handler = hymo_seq_read_maps_filter_entry,
	.handler = hymo_seq_read_maps_filter_ret,
	.data_size = sizeof(struct hymo_seq_read_ri_data),
	.maxactive = 64,
};

/* statfs f_type spoof: make direct (statfs) match resolved (mountinfo) to avoid INCONSISTENT_MOUNT.
 * We resolve the real (lower) fs type at statfs entry via d_real_inode and pass it through in ret.
 * OVERLAYFS_SUPER_MAGIC from uapi/linux/magic.h so we use the running kernel's definition. */

struct hymo_statfs_ri_data {
	void __user *buf;
	unsigned long spoof_f_type; /* real (lower) s_magic; 0 = do not spoof */
};

static int hymo_statfs_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_statfs_ri_data *d = (struct hymo_statfs_ri_data *)ri->data;
	const char __user *pathname;
#if defined(__aarch64__)
	d->buf = (void __user *)regs->regs[1];
	pathname = (const char __user *)regs->regs[0];
#elif defined(__x86_64__)
	d->buf = (void __user *)regs->si;
	pathname = (const char __user *)regs->di;
#else
	d->buf = NULL;
	pathname = NULL;
#endif
	d->spoof_f_type = 0;
	if (!(hymo_feature_enabled_mask & HYMO_FEATURE_STATFS_SPOOF) ||
	    !pathname || !hymo_kern_path)
		return 0;
	{
		char path_buf[HYMO_MAX_LEN_PATHNAME];
		struct path p;
		struct inode *real_ino;
		unsigned int n;

		n = copy_from_user(path_buf, pathname, sizeof(path_buf) - 1);
		path_buf[sizeof(path_buf) - 1] = '\0';
		if (n != 0)
			return 0;
		if (hymo_kern_path(path_buf, 0, &p) != 0)
			return 0;
		if ((unsigned long)p.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC) {
			real_ino = hymo_d_real_inode_impl(p.dentry);
			if (real_ino && real_ino->i_sb != p.dentry->d_sb)
				d->spoof_f_type = (unsigned long)real_ino->i_sb->s_magic;
			else
				d->spoof_f_type = (unsigned long)EROFS_SUPER_MAGIC;
		}
		path_put(&p);
	}
	return 0;
}

static int hymo_statfs_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret < 0)
		return 0;
	{
		struct hymo_statfs_ri_data *d = (struct hymo_statfs_ri_data *)ri->data;
		void __user *buf = d->buf;
		u64 f_type;

		if (!buf || d->spoof_f_type == 0)
			return 0;
		if (copy_from_user(&f_type, buf, sizeof(f_type)))
			return 0;
		if ((f_type & 0xffffffffUL) == OVERLAYFS_SUPER_MAGIC) {
			f_type = (f_type & 0xffffffff00000000UL) | (d->spoof_f_type & 0xffffffffUL);
			/* best-effort spoof; ignore write failure (kretprobe cannot change syscall return) */
			if (copy_to_user(buf, &f_type, sizeof(f_type)))
				(void)0;
		}
	}
	return 0;
}

static struct kretprobe hymo_krp_statfs = {
	.entry_handler = hymo_statfs_entry,
	.handler = hymo_statfs_ret,
	.data_size = sizeof(struct hymo_statfs_ri_data),
	.maxactive = 64,
};

/* kretprobe fallback for cmdline when tracepoint unavailable */
static int hymo_cmdline_read_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	hymofs_handle_sys_enter_cmdline(regs, __NR_read);
	return 0;
}

static int hymo_cmdline_read_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	ret = 0;
#endif
	hymofs_handle_sys_exit_cmdline(regs, ret);
	return 0;
}

static struct kretprobe hymo_krp_cmdline_read = {
	.entry_handler = hymo_cmdline_read_entry,
	.handler = hymo_cmdline_read_ret,
	.maxactive = 64,
};

/* ======================================================================
 * iterate_dir: filldir filter (runs in fs callback context, not kprobe)
 * ====================================================================== */

HYMO_NOCFI HYMO_FILLDIR_RET_TYPE
hymofs_filldir_filter(struct dir_context *ctx, const char *name,
		      int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymofs_filldir_wrapper *w =
		container_of(ctx, struct hymofs_filldir_wrapper, wrap_ctx);
	HYMO_FILLDIR_RET_TYPE ret;

	/* Inject phase: before first real entry, emit entries from merge targets
	 * and hymo_paths into the directory listing. */
	if (w->dir_has_inject && !w->inject_done && w->dir_path && w->parent_dentry) {
		struct list_head head;
		struct hymo_name_list *item, *tmp;
		loff_t inj_pos = HYMO_MAGIC_POS;

		w->inject_done = true;
		INIT_LIST_HEAD(&head);
		hymofs_populate_injected_list(w->dir_path, w->parent_dentry, &head);

		list_for_each_entry_safe(item, tmp, &head, list) {
			int nlen = strlen(item->name);
			if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
				break;
			ret = w->orig_ctx->actor(w->orig_ctx, item->name, nlen,
						 inj_pos, 1, item->type);
			list_del(&item->list);
			kfree(item->name);
			kfree(item);
			if (ret != HYMO_FILLDIR_CONTINUE) {
				list_for_each_entry_safe(item, tmp, &head, list) {
					list_del(&item->list);
					kfree(item->name);
					kfree(item);
				}
				return ret;
			}
			inj_pos++;
		}
	}

	if (unlikely(namlen <= 2 && name[0] == '.')) {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			goto passthrough;
	}

	if (hymo_stealth_enabled && w->dir_path_len == 4) {
		size_t mlen = strlen(hymo_current_mirror_name);
		if ((unsigned int)namlen == mlen &&
		    memcmp(name, hymo_current_mirror_name, namlen) == 0)
			return HYMO_FILLDIR_CONTINUE;
	}

	/* Hide real entries that also exist in merge targets. This prevents
	 * duplicates: the injected version (from populate_injected_list)
	 * replaces the original, just like original hymofs.c does.
	 * Skip when merge target IS the dir we're listing (e.g. target path
	 * resolved to same inode via symlink) - otherwise we'd hide everything.
	 * Must respect allowlist: privileged/allowlist processes see real files. */
	if (hymo_d_hash_and_lookup && w->merge_target_count > 0 && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		int i;
		for (i = 0; i < w->merge_target_count; i++) {
			struct dentry *tgt = w->merge_target_dentries[i];
			if (!tgt || tgt == w->parent_dentry)
				continue;
			if (d_inode(tgt) && d_inode(tgt) == d_inode(w->parent_dentry))
				continue;
			{
				struct dentry *child = hymo_d_hash_and_lookup(tgt,
					&(struct qstr)QSTR_INIT(name, namlen));
				if (child) {
					dput(child);
					return HYMO_FILLDIR_CONTINUE;
				}
			}
		}
	}

	if (hymo_d_hash_and_lookup && w->dir_has_hidden && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		struct dentry *child;

		child = hymo_d_hash_and_lookup(w->parent_dentry,
				&(struct qstr)QSTR_INIT(name, namlen));
		if (child) {
			struct inode *cinode = d_inode(child);
			if (cinode && cinode->i_mapping &&
			    test_bit(AS_FLAGS_HYMO_HIDE,
				     &cinode->i_mapping->flags)) {
				dput(child);
				return HYMO_FILLDIR_CONTINUE;
			}
			dput(child);
		}
	}

passthrough:
	if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
		return HYMO_FILLDIR_CONTINUE;
	return w->orig_ctx->actor(w->orig_ctx, name, namlen, offset, ino, d_type);
}

/* ======================================================================
 * Kprobe pre_handlers (modify regs / user path only; return 0 to run original)
 * ====================================================================== */

#if defined(__aarch64__)
#define HYMO_REG0(regs)		((regs)->regs[0])
#define HYMO_REG1(regs)		((regs)->regs[1])
#define HYMO_REG2(regs)		((regs)->regs[2])
#define HYMO_REG3(regs)		((regs)->regs[3])
#define HYMO_REG4(regs)		((regs)->regs[4])
#define HYMO_LR(regs)		((regs)->regs[30])
#define HYMO_POP_STACK(regs)	do { } while (0)
#elif defined(__x86_64__)
#define HYMO_REG0(regs)		((regs)->di)
#define HYMO_REG1(regs)		((regs)->si)
#define HYMO_REG2(regs)		((regs)->dx)
#define HYMO_REG3(regs)		((regs)->cx)
#define HYMO_REG4(regs)		((regs)->r8)
#define HYMO_LR(regs)		(*(unsigned long *)(regs)->sp)
#define HYMO_POP_STACK(regs)	do { (regs)->sp += 8; } while (0)
#elif defined(__arm__)
/* ARM32: pt_regs uses uregs[] (r0=0, r1=1, ..., lr=14, pc=15) */
#define HYMO_REG0(regs)		((regs)->uregs[0])
#define HYMO_REG1(regs)		((regs)->uregs[1])
#define HYMO_REG2(regs)		((regs)->uregs[2])
#define HYMO_REG3(regs)		((regs)->uregs[3])
#define HYMO_REG4(regs)		((regs)->uregs[4])
#define HYMO_LR(regs)		((regs)->uregs[14])
#define HYMO_POP_STACK(regs)	do { } while (0)
#else
#define HYMO_REG0(regs)		(0)
#define HYMO_REG1(regs)		(0)
#define HYMO_REG2(regs)		(0)
#define HYMO_REG3(regs)		(0)
#define HYMO_REG4(regs)		(0)
#define HYMO_LR(regs)		(0)
#define HYMO_POP_STACK(regs)	do { } while (0)
#endif

/* Path register pointer for syscall tracepoint (avoids u64* vs unsigned long* across archs) */
#if defined(__aarch64__) || defined(__x86_64__)
#define HYMO_PATH_REG_PTR(regs, id)  ((u64 *)((id) == __NR_execve ? &HYMO_REG0(regs) : &HYMO_REG1(regs)))
#define HYMO_PATH_REG_VAL(p)         ((u64)(uintptr_t)(p))
#else
#define HYMO_PATH_REG_PTR(regs, id)  ((unsigned long *)((id) == __NR_execve ? &HYMO_REG0(regs) : &HYMO_REG1(regs)))
#define HYMO_PATH_REG_VAL(p)         ((unsigned long)(uintptr_t)(p))
#endif

/*
 * vfs_getattr / vfs_getxattr argument positions.
 *
 * Upstream Linux added an idmap arg to vfs_getattr in 5.12, but Android GKI
 * kernels (verified across 5.10/5.15/6.1/6.6/6.12) keep the original 4-arg
 * signature `vfs_getattr(path, stat, mask, flags)`. So the upstream version
 * gate was wrong for every Android target — always shifted args by one and
 * silently early-exited on `!p->dentry`. Hardcode the 4-arg layout instead.
 */
#define HYMO_GETATTR_PATH_REG(regs) HYMO_REG0(regs)
#define HYMO_GETATTR_STAT_REG(regs) HYMO_REG1(regs)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG1(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG2(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG3(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG4(regs)
#else
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG0(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG1(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG2(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG3(regs)
#endif

/*
 * Atomic-safe user access for kprobe pre-handler (cannot sleep).
 * copy_from_user/copy_to_user may sleep on page fault -> use nofault variants.
 * Resolved dynamically via kallsyms (not exported on GKI).
 */
static long (*hymo_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);

#include <linux/sched/task_stack.h>

#define HYMO_HIDE_PATH "/.hymo_hidden_placeholder"

static char __user *hymo_userspace_stack_buffer(const char *data, size_t len)
{
	char __user *p;

	if (!current->mm)
		return NULL;
	p = (void __user *)current_user_stack_pointer() - len;
	return copy_to_user(p, data, len) ? NULL : p;
}

static inline bool hymo_tp_check_path_syscall(long id)
{
	switch (id) {
	case __NR_openat:
	case __NR_faccessat:
#ifdef __NR_newfstatat
	case __NR_newfstatat:
#endif
	case __NR_execve:
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_openat2
	case __NR_openat2:
#endif
		return true;
	default:
		return false;
	}
}

void hymofs_handle_sys_enter_getfd(struct pt_regs *regs, long id)
{
#if defined(__aarch64__)
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
	unsigned long a3 = regs->regs[3];
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
	unsigned long a3 = regs->r10;
#elif defined(__arm__)
	unsigned long a0 = regs->uregs[0];
	unsigned long a1 = regs->uregs[1];
	unsigned long a2 = regs->uregs[2];
	unsigned long a3 = regs->uregs[3];
#else
	return;
#endif
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return;

	/* reboot: magic + put_user via 4th arg */
	if (id == __NR_reboot && a0 == HYMO_MAGIC1 && a1 == HYMO_MAGIC2 && a2 == (unsigned long)HYMO_CMD_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a3;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* prctl: option=HYMO_PRCTL_GET_FD, arg2=fd_ptr */
	if (id == __NR_prctl && a0 == (unsigned long)HYMO_PRCTL_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a1;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* ni_syscall: set per-cpu for sys_exit to replace return value */
	if (id == (long)hymo_syscall_nr_param && a0 == HYMO_MAGIC1 && a1 == HYMO_MAGIC2 && a2 == (unsigned long)HYMO_CMD_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			hymo_this_cpu()->override_fd = fd;
			hymo_this_cpu()->override_active = 1;
		}
	}
}

void hymofs_handle_sys_exit_getfd(struct pt_regs *regs, long ret)
{
	(void)ret;
	if (!hymo_this_cpu()->override_active)
		return;
#if defined(__aarch64__)
	regs->regs[0] = hymo_this_cpu()->override_fd;
#elif defined(__x86_64__)
	regs->ax = hymo_this_cpu()->override_fd;
#elif defined(__arm__)
	regs->uregs[0] = hymo_this_cpu()->override_fd;
#endif
	hymo_this_cpu()->override_active = 0;
}

#if defined(__aarch64__) || defined(__x86_64__)
/* Cmdline spoof: check if fd refers to /proc/cmdline (tracepoint + kretprobe path) */
static bool hymo_fd_is_proc_cmdline(int fd)
{
	struct file *file;
	struct dentry *dentry, *parent;
	bool is_cmdline = false;

	file = fget(fd);
	if (!file)
		return false;
	dentry = file->f_path.dentry;
	parent = dentry ? dentry->d_parent : NULL;
	if (dentry && dentry->d_name.len == 7 &&
	    memcmp(dentry->d_name.name, "cmdline", 7) == 0 && parent) {
		/* Parent is "proc" dir or proc root (empty name) */
		if ((parent->d_name.len == 5 && memcmp(parent->d_name.name, "proc", 5) == 0) ||
		    parent->d_name.len == 0)
			is_cmdline = true;
	}
	fput(file);
	return is_cmdline;
}
#endif

void hymofs_handle_sys_enter_cmdline(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	unsigned long fd, buf, count;

	if (!hymo_cmdline_spoof_active)
		return;
	if (id != __NR_read)
		return;
	if (READ_ONCE(hymo_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(hymo_daemon_pid))
		return;

#if defined(__aarch64__)
	fd = regs->regs[0];
	buf = regs->regs[1];
	count = regs->regs[2];
#else
	fd = regs->di;
	buf = regs->si;
	count = regs->dx;
#endif

	if (!hymo_fd_is_proc_cmdline((int)fd))
		return;

	hymo_this_cpu()->cmdline_ctx.buf = (char __user *)buf;
	hymo_this_cpu()->cmdline_ctx.count = (size_t)count;
	hymo_this_cpu()->cmdline_ctx.active = 1;
#endif
}

void hymofs_handle_sys_exit_cmdline(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct hymo_percpu *pcpu = hymo_this_cpu();
	size_t spoof_len, write_len;

	if (!pcpu->cmdline_ctx.active || ret <= 0)
		goto out;
	pcpu->cmdline_ctx.active = 0;

	if (!READ_ONCE(hymo_cmdline_spoof_active))
		goto out;

	rcu_read_lock();
	{
		struct hymo_cmdline_rcu *c = rcu_dereference(hymo_spoof_cmdline_ptr);
		if (!c || !c->cmdline[0]) {
			rcu_read_unlock();
			goto out;
		}
		spoof_len = strnlen(c->cmdline, sizeof(c->cmdline) - 1);
		/* Original cmdline ends with \n; match that */
		write_len = spoof_len + 1; /* +1 for \n */
		if (write_len > pcpu->cmdline_ctx.count)
			write_len = pcpu->cmdline_ctx.count;
		if (write_len > 0) {
			size_t n = (spoof_len < write_len) ? spoof_len : write_len - 1;
			if (copy_to_user(pcpu->cmdline_ctx.buf, c->cmdline, n) == 0) {
				if (n < write_len && copy_to_user(pcpu->cmdline_ctx.buf + n, "\n", 1) == 0)
					write_len = n + 1;
				else
					write_len = n;
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)write_len;
#else
				regs->ax = (unsigned long)write_len;
#endif
			}
		}
	}
	rcu_read_unlock();
out:
	(void)0;
#endif
}

void hymofs_handle_sys_enter_path(struct pt_regs *regs, long id)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	char __user *new_path;

	if (!hymo_tp_check_path_syscall(id))
		return;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return;
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return;
	/* Fast path: no rules/hide -> skip copy_from_user (O(1) vs 3×hash_empty) */
	if (likely(atomic_read(&hymo_rule_count) == 0 &&
		   atomic_read(&hymo_hide_count) == 0))
		return;

	filename_user = (const char __user *)(uintptr_t)*HYMO_PATH_REG_PTR(regs, id);
	if (!filename_user)
		return;

	buf = hymo_getname_buf_base + (smp_processor_id() * HYMO_PATH_BUF);
	if (hymo_strncpy_from_user_nofault) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (long)(HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	if (unlikely(hymofs_should_hide(buf))) {
		new_path = hymo_userspace_stack_buffer(HYMO_HIDE_PATH, sizeof(HYMO_HIDE_PATH));
		if (new_path)
			*HYMO_PATH_REG_PTR(regs, id) = HYMO_PATH_REG_VAL(new_path);
		return;
	}

	if (buf[0] != '/')
		return;
	target = hymofs_resolve_target(buf);
	if (!target)
		return;
	{
		size_t tlen = strlen(target) + 1;
		if (tlen > HYMO_PATH_BUF) {
			kfree(target);
			return;
		}
		new_path = hymo_userspace_stack_buffer(target, tlen);
		kfree(target);
		if (new_path)
			*HYMO_PATH_REG_PTR(regs, id) = HYMO_PATH_REG_VAL(new_path);
	}
}

/* getname_flags pre-handler: only modify user path and regs; return 0 to run original. */
static HYMO_NOCFI int hymo_kp_getname_flags_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename_user;
	char *buf;
	char *target;

	(void)p;

	if (hymo_this_cpu()->kprobe_reent)
		return 0;
	/* Skip when current is in ioctl path resolution (avoids reent / deadlock with metamount+hymod). */
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	/* Skip when resolving source path for xattr spoofing (need unredirected path). */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;
	/* Fast path: no rules/hide -> skip copy_from_user (O(1) vs 3×hash_empty) */
	if (likely(atomic_read(&hymo_rule_count) == 0 &&
		   atomic_read(&hymo_hide_count) == 0))
		return 0;

	filename_user = (const char __user *)HYMO_REG0(regs);
	if (!filename_user)
		return 0;

	buf = hymo_getname_buf_base + (smp_processor_id() * HYMO_PATH_BUF);
	if (hymo_strncpy_from_user_nofault) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return 0;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return 0;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	/* Hide: skip original and return error (no putname needed) */
	if (unlikely(hymofs_should_hide(buf))) {
		hymo_this_cpu()->kprobe_reent = 1;
		HYMO_REG0(regs) = (unsigned long)ERR_PTR(-ENOENT);
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
#if defined(__x86_64__)
		regs->ax = (unsigned long)ERR_PTR(-ENOENT);
#endif
		hymo_this_cpu()->kprobe_reent = 0;
		return 1;
	}

	/* Redirect: use getname_kernel to build a struct filename from the target
	 * path, then skip the original getname_flags entirely.  This avoids
	 * writing back to user memory (which may be read-only, too small, or
	 * cause PAN/MTE faults in atomic context). */
	if (buf[0] != '/')
		return 0;
	target = hymofs_resolve_target(buf);
	if (!target)
		return 0;
	if (hymo_getname_kernel) {
		struct filename *fname;

		hymo_this_cpu()->kprobe_reent = 1;
		fname = hymo_getname_kernel(target);
		hymo_this_cpu()->kprobe_reent = 0;
		kfree(target);
		if (IS_ERR(fname))
			return 0;
		HYMO_REG0(regs) = (unsigned long)fname;
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
		return 1;
	}
	kfree(target);
	return 0;
}

/* vfs_getattr kprobe pre: nop (stat spoofing is done in kretprobe entry/ret). */
static int hymo_kp_vfs_getattr_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * Reverse-lookup helper: check if a resolved path is a redirect target.
 * Returns the matching hymo_entry (under rcu_read_lock) or NULL.
 * Caller must hold rcu_read_lock.
 */
static struct hymo_entry *hymofs_reverse_lookup_target(const char *path_str)
{
	struct hymo_entry *entry;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(entry,
		&hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
		if (strcmp(entry->target, path_str) == 0)
			return entry;
	}
	return NULL;
}

/*
 * vfs_getattr kretprobe entry: resolve path, check hymo_targets.
 * Uses ri->data (migration-safe) instead of per-CPU storage.
 */
HYMO_NOCFI int hymo_krp_vfs_getattr_entry(struct kretprobe_instance *ri,
						  struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	const struct path *p;
	char buf[256];
	char *dp;

	d->is_target = false;
	d->stat = NULL;
	d->mapping = NULL;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (hymo_this_cpu()->in_populate_inject)
		return 0;
	if (atomic_read(&hymo_rule_count) == 0 &&
	    atomic_read(&hymo_spoof_kstat_count) == 0)
		return 0;

	p = (const struct path *)HYMO_GETATTR_PATH_REG(regs);
	d->stat = (struct kstat *)HYMO_GETATTR_STAT_REG(regs);

	if (!p || !p->dentry || !d->stat)
		return 0;

	if (d_inode(p->dentry) && d_inode(p->dentry)->i_mapping)
		d->mapping = d_inode(p->dentry)->i_mapping;

	/* Fast path: inode already marked from a previous redirect match */
	if (d->mapping && test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &d->mapping->flags)) {
		/* If shadow i_op is installed, it will spoof inline — skip the
		 * ret handler entirely to avoid redundant work. */
		if (test_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &d->mapping->flags))
			return -1;
		d->is_target = true;
		return 0;
	}

	dp = ERR_PTR(-ENOENT);
	if (hymo_d_absolute_path)
		dp = hymo_d_absolute_path(p, buf, sizeof(buf));
	if (IS_ERR(dp) && hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(p->dentry, buf, sizeof(buf));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	if (hymofs_reverse_lookup_target(dp) ||
	    hymofs_spoof_kstat_lookup_by_path(dp))
		d->is_target = true;
	if (!d->is_target && d_inode(p->dentry)) {
		struct inode *ino = d_inode(p->dentry);
		if (hymofs_spoof_kstat_lookup_by_ino(
			(unsigned long)ino->i_ino,
			ino->i_sb ? (unsigned long)ino->i_sb->s_dev : 0))
			d->is_target = true;
	}
	rcu_read_unlock();

	return 0;
}

/*
 * vfs_getattr kretprobe ret: spoof kstat for redirect targets.
 * Makes the file appear to belong to /system with root ownership.
 */
/*
 * Apply kstat spoofing in place. Shared by:
 *   - vfs_getattr kretprobe ret handler (legacy slow path)
 *   - hymo_shadow_getattr in hymofs_iop_override.c (fast path after install)
 *
 * Note: `inode` may be NULL for the legacy path (we still have stat / mapping
 * via the kretprobe ri data); the shadow path always provides it.
 */
void hymo_apply_kstat_spoof(struct inode *inode, struct kstat *stat)
{
	struct hymo_spoof_kstat_entry *e = NULL;

	if (!stat)
		return;

	/* Explicit per-inode spoof rule (api15) takes precedence. */
	if (inode && atomic_read(&hymo_spoof_kstat_count) > 0) {
		rcu_read_lock();
		e = hymofs_spoof_kstat_lookup_by_ino((unsigned long)inode->i_ino,
						     (unsigned long)stat->dev);
		if (e) {
			if (e->spoofed_dev)        stat->dev = e->spoofed_dev;
			if (e->spoofed_ino)        stat->ino = e->spoofed_ino;
			if (e->spoofed_nlink)      stat->nlink = e->spoofed_nlink;
			if (e->spoofed_size)       stat->size = e->spoofed_size;
			if (e->spoofed_blksize)    stat->blksize = e->spoofed_blksize;
			if (e->spoofed_blocks)     stat->blocks = e->spoofed_blocks;
			if (e->spoofed_atime_sec || e->spoofed_atime_nsec) {
				stat->atime.tv_sec  = e->spoofed_atime_sec;
				stat->atime.tv_nsec = e->spoofed_atime_nsec;
			}
			if (e->spoofed_mtime_sec || e->spoofed_mtime_nsec) {
				stat->mtime.tv_sec  = e->spoofed_mtime_sec;
				stat->mtime.tv_nsec = e->spoofed_mtime_nsec;
			}
			if (e->spoofed_ctime_sec || e->spoofed_ctime_nsec) {
				stat->ctime.tv_sec  = e->spoofed_ctime_sec;
				stat->ctime.tv_nsec = e->spoofed_ctime_nsec;
			}
		}
		rcu_read_unlock();
	}

	if (!e) {
		/* Generic fallback: piggyback on add_rule redirect targets. */
		if (hymo_system_dev)
			stat->dev = hymo_system_dev;
		stat->ino = (u64)jhash(stat, sizeof(stat->ino), 0x48594D4F) | 0x100000ULL;
		if (S_ISREG(stat->mode))
			stat->nlink = 1;
	}

	stat->uid = GLOBAL_ROOT_UID;
	stat->gid = GLOBAL_ROOT_GID;

	hymo_log("kstat: spoofed ino %lu (explicit=%d)\n",
		 (unsigned long)stat->ino, e ? 1 : 0);

	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags);
}

int hymo_krp_vfs_getattr_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	int ret_val;

	if (!d->is_target || !d->stat)
		return 0;

#if defined(__aarch64__)
	ret_val = (int)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (int)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val != 0)
		return 0;

	{
		struct inode *inode = d->mapping ? d->mapping->host : NULL;
		hymo_apply_kstat_spoof(inode, d->stat);
		/*
		 * Lookup-time i_op install: after first successful spoof,
		 * install a shadow inode_operations so future stat()s go
		 * through an indirect call instead of trapping into this
		 * kprobe. Safe to call repeatedly (idempotent).
		 */
		if (inode)
			hymofs_iop_install(inode);
	}

	return 0;
}

/*
 * Get SELinux context from a path (used for source path when spoofing).
 * Bypass must be set (hymo_xattr_source_tgid) so path resolution is not redirected.
 * Returns length of context string (excl. NUL) or negative on error.
 */
static HYMO_NOCFI ssize_t hymo_get_selinux_ctx_from_path(struct path *path, char *buf, size_t buflen)
{
	if (!hymo_vfs_getxattr_addr || buflen < 2)
		return -ENOENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_idmap(path->mnt), path->dentry, "security.selinux", buf, buflen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_user_ns(path->mnt), path->dentry, "security.selinux", buf, buflen);
#else
	return ((ssize_t (*)(struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		path->dentry, "security.selinux", buf, buflen);
#endif
}

/*
 * vfs_getxattr kretprobe entry: check if querying security.selinux on a
 * redirect target.  Resolves source path and reads its actual SELinux context
 * from the mounted directory (no hardcoding).
 */
HYMO_NOCFI int hymo_krp_vfs_getxattr_entry(struct kretprobe_instance *ri,
						   struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	struct dentry *dentry;
	const char *xattr_name;
	struct inode *inode;
	char *tmp;  /* heap to avoid arm32 frame-larger-than=1024 */
	char *dp;
	struct hymo_entry *entry;
	struct path src_path;
	ssize_t ret;

	d->spoof_selinux = false;
	d->value_buf = NULL;
	d->value_size = 0;
	d->src_ctx[0] = '\0';
	d->src_ctx_len = 0;

	/* Skip when we're in the inner call (resolving source path's context) */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	xattr_name = (const char *)HYMO_GETXATTR_NAME_REG(regs);
	if (!xattr_name)
		return 0;
	if (strcmp(xattr_name, "security.selinux") != 0)
		return 0;

	dentry = (struct dentry *)HYMO_GETXATTR_DENTRY_REG(regs);
	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode || !inode->i_mapping)
		return 0;
	if (!test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags))
		return 0;

	tmp = kmalloc(256 + 256 + 256 + 256 + 512, GFP_KERNEL);
	if (!tmp)
		return 0;

	/* Resolve target path for reverse lookup. dentry_path_raw gives path
	 * relative to fs root; try full path and /data + rel for common Android layout. */
	dp = ERR_PTR(-ENOENT);
	if (hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(dentry, tmp, 256);
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		goto out_free;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (!entry && dp[0] == '/' && dp[1] != '\0') {
		if (snprintf(tmp + 256, 256, "/data%s", dp) < 256)
			entry = hymofs_reverse_lookup_target(tmp + 256);
	}
	rcu_read_unlock();
	if (!entry || !entry->src)
		goto out_free;

	/* Resolve source path (bypass redirect) and get its actual SELinux context.
	 * When source file doesn't exist (e.g. overlay dir is empty), try parent
	 * directories. Use d_absolute_path on resolved parent to get symlink-resolved
	 * path (e.g. /system/product -> /product), then try resolved+remainder. */
	atomic_long_set(&hymo_xattr_source_tgid, (long)task_tgid_vnr(current));
	if (hymo_kern_path) {
		char *parent = tmp + 512;
		char *resolved = tmp + 768;
		char *alt = tmp + 1024;
		const char *try_path = entry->src;
		size_t len = strlen(entry->src);
		size_t parent_len;

		while (try_path && len > 1) {
			/* Try logical path (LOOKUP_FOLLOW resolves symlinks) */
			if (hymo_kern_path(try_path, LOOKUP_FOLLOW, &src_path) == 0) {
				ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
				path_put(&src_path);
				if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			/* Logical path failed: try parent, get resolved path via d_absolute_path,
			 * then try resolved+remainder (handles any symlink, not just /system/product). */
			if (len >= 256)
				break;
			memcpy(parent, try_path, len + 1);
			{
				char *slash = strrchr(parent, '/');
				if (!slash || slash == parent)
					break;
				*slash = '\0';
				parent_len = slash - parent;
			}
			if (hymo_kern_path(parent, LOOKUP_FOLLOW, &src_path) == 0) {
				char *res = NULL;
				bool got_ctx = false;
				if (hymo_d_absolute_path)
					res = hymo_d_absolute_path(&src_path, resolved, 256);
				if (IS_ERR_OR_NULL(res) && hymo_dentry_path_raw)
					res = hymo_dentry_path_raw(src_path.dentry, resolved, 256);
				if (res && !IS_ERR(res) && res[0] == '/' &&
				    parent_len < len && try_path[parent_len] == '/') {
					const char *remainder = try_path + parent_len;
					if (snprintf(alt, 512, "%s%s", res, remainder) < 512 &&
					    strcmp(alt, try_path) != 0) {
						struct path alt_path;
						if (hymo_kern_path(alt, LOOKUP_FOLLOW, &alt_path) == 0) {
							ret = hymo_get_selinux_ctx_from_path(&alt_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
							path_put(&alt_path);
							if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
								got_ctx = true;
						}
					}
				}
				if (!got_ctx) {
					ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
					if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
						got_ctx = true;
				}
				path_put(&src_path);
				if (got_ctx) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			try_path = parent;
			len = parent_len;
		}
	}
	atomic_long_set(&hymo_xattr_source_tgid, 0);

	d->value_buf = (void *)HYMO_GETXATTR_VALUE_REG(regs);
	d->value_size = (size_t)HYMO_GETXATTR_SIZE_REG(regs);

out_free:
	kfree(tmp);
	return 0;
}

/*
 * vfs_getxattr kretprobe ret: overwrite value buffer with source path's
 * actual SELinux context (from entry handler) and fix return value.
 */
int hymo_krp_vfs_getxattr_ret(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	long ret_val;
	size_t ctx_len;

	if (!d->spoof_selinux || !d->value_buf || !d->src_ctx_len)
		return 0;

#if defined(__aarch64__)
	ret_val = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (long)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val <= 0)
		return 0;

	ctx_len = d->src_ctx_len + 1; /* include NUL */
	if (d->value_size < ctx_len)
		return 0;
	memcpy(d->value_buf, d->src_ctx, ctx_len);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)d->src_ctx_len;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)d->src_ctx_len;
#endif

	return 0;
}

/* d_path: kprobe pre now a nop; entry handler below does the real work. */
static int hymo_kp_d_path_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * d_path kretprobe entry: save buf/buflen from regs, resolve the struct path
 * to see if it's a redirect target.  d_path signature:
 *   char *d_path(const struct path *path, char *buf, int buflen)
 */
HYMO_NOCFI int hymo_krp_d_path_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	const struct path *p;
	char tmp[256];
	char *dp;
	struct hymo_entry *entry;

	d->is_target = false;
	d->buf = (char *)HYMO_REG1(regs);
	d->buflen = (int)HYMO_REG2(regs);
	d->src_path[0] = '\0';

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	p = (const struct path *)HYMO_REG0(regs);
	if (!p || !p->dentry)
		return 0;

	dp = ERR_PTR(-ENOENT);
	if (hymo_d_absolute_path)
		dp = hymo_d_absolute_path(p, tmp, sizeof(tmp));
	if (IS_ERR(dp) && hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(p->dentry, tmp, sizeof(tmp));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (entry && strlen(entry->src) < HYMO_D_PATH_SRC_MAX) {
		d->is_target = true;
		strscpy(d->src_path, entry->src, HYMO_D_PATH_SRC_MAX);
	}
	rcu_read_unlock();

	return 0;
}

/*
 * d_path kretprobe ret: if the resolved path was a redirect target,
 * overwrite the result so /proc/pid/fd/N shows /system/... instead of
 * /data/adb/modules/xxx/...
 *
 * d_path() returns a pointer INSIDE the caller's buffer (buf + offset).
 * We write the source path into the buffer from the end and update the
 * return value register to point to the new start.
 */
int hymo_krp_d_path_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	char *ret_ptr;
	size_t src_len;
	char *new_start;

	if (!d->is_target || !d->src_path[0] || !d->buf || d->buflen <= 0)
		return 0;

#if defined(__aarch64__)
	ret_ptr = (char *)regs->regs[0];
#elif defined(__x86_64__)
	ret_ptr = (char *)regs->ax;
#else
	ret_ptr = NULL;
#endif
	if (IS_ERR_OR_NULL(ret_ptr))
		return 0;

	src_len = strlen(d->src_path);
	if ((int)src_len + 1 > d->buflen)
		return 0;

	new_start = d->buf + d->buflen - src_len - 1;
	memcpy(new_start, d->src_path, src_len + 1);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)new_start;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)new_start;
#endif

	return 0;
}

/*
 * iterate_dir: pre swaps ctx to our wrapper so kernel runs filldir filter.
 * HYMO_NOCFI: indirect calls to hymo_d_absolute_path / hymo_dentry_path_raw.
 */
HYMO_NOCFI int hymo_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	struct hymofs_filldir_wrapper *w;
	struct dir_context *orig_ctx;
	struct inode *dir_inode;
	const char *dname;

	(void)p;
	hymo_this_cpu()->iterate_did_swap = 0;

	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (hymo_this_cpu()->in_populate_inject)
		return 0;
	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	if (READ_ONCE(hymo_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(hymo_daemon_pid))
		return 0;

	file = (struct file *)HYMO_REG0(regs);
	orig_ctx = (struct dir_context *)HYMO_REG1(regs);
	if (!orig_ctx || !orig_ctx->actor)
		return 0;
	if (orig_ctx->actor == hymofs_filldir_filter)
		return 0;

	w = kmem_cache_zalloc(hymo_filldir_cache, GFP_ATOMIC);
	if (!w)
		return 0;

	w->orig_ctx = orig_ctx;
	w->wrap_ctx.actor = hymofs_filldir_filter;
	w->wrap_ctx.pos = orig_ctx->pos;
	w->parent_dentry = file && file->f_path.dentry ? file->f_path.dentry : NULL;

	if (w->parent_dentry) {
		dir_inode = d_inode(w->parent_dentry);
		if (dir_inode && dir_inode->i_mapping) {
			w->dir_has_hidden = test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
						     &dir_inode->i_mapping->flags);
			/* Fast path: if dir has no inject flag, skip rcu_read_lock + hash traversal */
			w->dir_has_inject = test_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT,
						    &dir_inode->i_mapping->flags);
		}
		dname = w->parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' && dname[3] == '\0')
			w->dir_path_len = 4;

		/*
		 * Only when dir_has_inject (from flag) is true: build full path and
		 * traverse hash to get merge_target_dentries. Most dirs skip this.
		 */
		if (atomic_read(&hymo_rule_count) > 0 && w->dir_has_inject) {
			char *buf = hymo_iterate_buf_base + (smp_processor_id() * HYMO_ITERATE_PATH_BUF);
			char *dp = ERR_PTR(-ENOENT);

			if (hymo_d_absolute_path)
				dp = hymo_d_absolute_path(&file->f_path, buf,
							  HYMO_ITERATE_PATH_BUF);
			if (IS_ERR(dp) && hymo_dentry_path_raw)
				dp = hymo_dentry_path_raw(w->parent_dentry, buf,
							  HYMO_ITERATE_PATH_BUF);

			if (!IS_ERR_OR_NULL(dp) && *dp == '/') {
				struct hymo_inject_entry *ie;
				struct hymo_merge_entry *me;
				u32 h;
				int mbkt;
				size_t plen = strlen(dp);

				if (plen < HYMO_ITERATE_PATH_BUF) {
					memcpy(w->dir_path_buf, dp, plen + 1);
					w->dir_path = w->dir_path_buf;
				}
				h = full_name_hash(NULL, dp, strlen(dp));

				rcu_read_lock();
				hlist_for_each_entry_rcu(ie,
					&hymo_inject_dirs[hash_min(h, HYMO_HASH_BITS)],
					node) {
					if (strcmp(ie->dir, dp) == 0) {
						w->dir_has_inject = true;
						break;
					}
				}
				/* Scan all merge entries (few) to match both
				 * src and resolved_src; cache target dentries. */
				hash_for_each_rcu(hymo_merge_dirs, mbkt, me, node) {
					if (strcmp(me->src, dp) == 0 ||
					    (me->resolved_src &&
					     strcmp(me->resolved_src, dp) == 0)) {
						w->dir_has_inject = true;
						if (me->target_dentry &&
						    w->merge_target_count < HYMO_MAX_MERGE_TARGETS)
							w->merge_target_dentries[w->merge_target_count++] =
								me->target_dentry;
					}
				}
				rcu_read_unlock();
			}
		}
	}

	if (!w->dir_has_hidden && !w->dir_has_inject &&
	    (!hymo_stealth_enabled || w->dir_path_len != 4)) {
		kmem_cache_free(hymo_filldir_cache, w);
		hymo_this_cpu()->iterate_did_swap = 0;
		return 0;
	}

	hymo_this_cpu()->iterate_did_swap = 1;
	HYMO_REG1(regs) = (unsigned long)&w->wrap_ctx;
	return 0;
}

static int hymo_krp_iterate_dir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;
	struct dir_context *ctx = (struct dir_context *)HYMO_REG1(regs);

	d->did_swap = 0;
	d->wrapper = NULL;
	if (ctx && ctx->actor == hymofs_filldir_filter) {
		d->did_swap = 1;
		d->wrapper = container_of(ctx, struct hymofs_filldir_wrapper,
					  wrap_ctx);
	}
	return 0;
}

int hymo_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;

	(void)regs;
	if (d->did_swap && d->wrapper) {
		if (d->wrapper->orig_ctx)
			d->wrapper->orig_ctx->pos = d->wrapper->wrap_ctx.pos;
		kmem_cache_free(hymo_filldir_cache, d->wrapper);
		d->wrapper = NULL;
	}
	return 0;
}

#define HYMOFS_VFS_HOOK_COUNT 4
#define HYMOFS_VFS_IDX_GETNAME   0
#define HYMOFS_VFS_IDX_GETATTR  1
#define HYMOFS_VFS_IDX_DPATH    2
#define HYMOFS_VFS_IDX_ITERDIR  3

static const struct {
	const char *name;
	int (*pre)(struct kprobe *, struct pt_regs *);
} hymofs_vfs_hooks[] = {
	{ "getname_flags", hymo_kp_getname_flags_pre },
	{ "vfs_getattr",   hymo_kp_vfs_getattr_pre },
	{ "d_path",        hymo_kp_d_path_pre },
	{ "iterate_dir",   hymo_kp_iterate_dir_pre },
};
static struct kprobe hymofs_kprobes[HYMOFS_VFS_HOOK_COUNT];

static struct kretprobe hymo_krp_vfs_getattr;
static struct kretprobe hymo_krp_d_path;
static struct kretprobe hymo_krp_iterate_dir;
static struct kretprobe hymo_krp_vfs_getxattr;

/* ======================================================================
 * Part 24: Module Init / Exit
 * ====================================================================== */

static int __init hymofs_lkm_init(void)
{
	/* Use pr_alert for early logging - more likely to survive crash */
	pr_alert("HymoFS: === INIT START v%s ===\n", HYMOFS_VERSION);

	/* Dummy mode: exit immediately - for testing module loading itself */
	if (hymo_dummy_mode_param) {
		pr_alert("HymoFS: DUMMY MODE - exiting immediately\n");
		return 0;
	}

	hymo_filldir_cache = kmem_cache_create("hymofs_filldir",
		sizeof(struct hymofs_filldir_wrapper), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!hymo_filldir_cache) {
		pr_alert("HymoFS: failed to create filldir slab cache\n");
		return -ENOMEM;
	}

	pr_alert("HymoFS: skip_kallsyms=%d skip_vfs=%d skip_extra=%d skip_getfd=%d\n",
		hymo_skip_kallsyms_param, hymo_skip_vfs_param,
		hymo_skip_extra_kprobes_param, hymo_skip_getfd_param);

	pr_alert("HymoFS: STAGE 1: resolving kallsyms\n");

	/* Resolve kallsyms first - broader symbol access than kprobe on some GKI kernels. */
	if (!hymo_skip_kallsyms_param)
		hymofs_resolve_kallsyms_lookup();
	else
		pr_alert("HymoFS: skipping kallsyms (using per-symbol kprobe)\n");

	pr_alert("HymoFS: STAGE 2: resolving VFS symbols\n");
	/*
	 * Resolve ALL VFS symbols via kallsyms/kprobe - GKI kernels protect these
	 * behind namespaces or don't export them at all.
	 * Critical symbols fail the module load; optional ones just warn.
	 */
	hymo_kern_path = (void *)hymofs_lookup_name("kern_path");
	if (!hymo_kern_path) {
		pr_err("HymoFS: FATAL - kern_path not found\n");
		return -ENOENT;
	}
	hymo_strndup_user = (void *)hymofs_lookup_name("strndup_user");
	if (!hymo_strndup_user) {
		pr_err("HymoFS: FATAL - strndup_user not found\n");
		return -ENOENT;
	}
	hymo_ihold = (void *)hymofs_lookup_name("ihold");
	if (!hymo_ihold) {
		pr_err("HymoFS: FATAL - ihold not found\n");
		return -ENOENT;
	}
	hymo_getname_kernel = (void *)hymofs_lookup_name("getname_kernel");
	if (!hymo_getname_kernel)
		pr_warn("HymoFS: getname_kernel not found, path redirect may fail\n");

	/* Optional: allowlist support */
	hymo_filp_open = (void *)hymofs_lookup_name("filp_open");
	hymo_filp_close = (void *)hymofs_lookup_name("filp_close");
	hymo_kernel_read = (void *)hymofs_lookup_name("kernel_read");
	hymo_vfs_getattr = (void *)hymofs_lookup_name("vfs_getattr");
	hymo_dentry_open = (void *)hymofs_lookup_name("dentry_open");
	hymo_d_absolute_path = (void *)hymofs_lookup_name("d_absolute_path");
	hymo_dentry_path_raw = (void *)hymofs_lookup_name("dentry_path_raw");
	hymo_strncpy_from_user_nofault = (void *)hymofs_lookup_name("strncpy_from_user_nofault");
	if (!hymo_strncpy_from_user_nofault)
		pr_warn("HymoFS: strncpy_from_user_nofault not found, falling back to copy_from_user\n");
	hymo_d_path = (void *)hymofs_lookup_name("d_path");
	hymo_d_hash_and_lookup = (void *)hymofs_lookup_name("d_hash_and_lookup");
	/* path_put, dput, dget, iput, iterate_dir: use kernel exports directly, no lookup */
	if (!hymo_d_path)
		pr_warn("HymoFS: d_path not found, path resolution in populate/merge/hide may fail\n");
	if (!hymo_d_hash_and_lookup)
		pr_warn("HymoFS: d_hash_and_lookup not found, merge dedup and hide filter disabled\n");
	/* d_real_inode is inline in kernel; we use hymo_d_real_inode_impl via d_op->d_real */
	if (!hymo_filp_open || !hymo_kernel_read)
		pr_warn("HymoFS: filp_open/kernel_read not found, allowlist disabled\n");
	/* Prefer __ksu_is_allow_uid_for_current (handles uid 0) over __ksu_is_allow_uid */
	{
		unsigned long addr = hymofs_lookup_name("__ksu_is_allow_uid_for_current");
		if (addr && hymofs_valid_kernel_addr(addr)) {
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
		}
	}
	if (!hymo_ksu_is_allow_uid_ptr) {
		unsigned long addr = hymofs_lookup_name("__ksu_is_allow_uid");
		if (addr && hymofs_valid_kernel_addr(addr)) {
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
		}
	}
	if (!hymo_vfs_getattr || !hymo_dentry_open)
		pr_warn("HymoFS: vfs_getattr/dentry_open not found, merge whiteout/iterate disabled\n");
	if (!hymo_d_absolute_path && !hymo_dentry_path_raw)
		pr_warn("HymoFS: neither d_absolute_path nor dentry_path_raw found, inject/merge listing disabled\n");

	pr_alert("HymoFS: STAGE 3: initializing hash tables\n");
	/* Initialize hash tables */
	hash_init(hymo_paths);
	hash_init(hymo_targets);
	hash_init(hymo_hide_paths);
	hash_init(hymo_inject_dirs);
	hash_init(hymo_xattr_sbs);
	hash_init(hymo_merge_dirs);

	/* vmalloc per-CPU data and path buffers (avoids percpu allocator exhaustion on 6.6 Qualcomm) */
	hymo_percpu_base = vmalloc(nr_cpu_ids * sizeof(struct hymo_percpu));
	hymo_getname_buf_base = vmalloc(nr_cpu_ids * HYMO_PATH_BUF);
	hymo_iterate_buf_base = vmalloc(nr_cpu_ids * HYMO_ITERATE_PATH_BUF);
	if (!hymo_percpu_base || !hymo_getname_buf_base || !hymo_iterate_buf_base) {
		vfree(hymo_percpu_base);
		vfree(hymo_getname_buf_base);
		vfree(hymo_iterate_buf_base);
		hymo_percpu_base = NULL;
		hymo_getname_buf_base = NULL;
		hymo_iterate_buf_base = NULL;
		pr_err("HymoFS: failed to allocate per-CPU buffers\n");
		return -ENOMEM;
	}
	memset(hymo_percpu_base, 0, nr_cpu_ids * sizeof(struct hymo_percpu));

	pr_alert("HymoFS: STAGE 4: resolving /system path\n");
	/* Resolve /system device number for stat spoofing */
	if (hymo_kern_path) {
		struct path sys_path;
		if (hymo_kern_path("/system", LOOKUP_FOLLOW, &sys_path) == 0) {
			hymo_system_dev = sys_path.dentry->d_sb->s_dev;
			pr_info("HymoFS: /system dev=%u:%u\n",
				MAJOR(hymo_system_dev), MINOR(hymo_system_dev));
			path_put(&sys_path);
		} else {
			pr_warn("HymoFS: could not resolve /system for stat spoofing\n");
		}
	}

	pr_alert("HymoFS: STAGE 5: registering tracepoints\n");
	/* Try tracepoint for path redirect + GET_FD first. Tracepoint supports multiple listeners (KSU + HymoFS can coexist). */
	if (!hymo_skip_getfd_param && !hymo_no_tracepoint_param)
		(void)hymofs_tracepoint_path_init();
	else if (hymo_skip_getfd_param)
		pr_alert("HymoFS: skipping tracepoint (hymo_skip_getfd=1)\n");

	pr_alert("HymoFS: STAGE 6: registering GET_FD kprobes\n");
	/* GET_FD: use tracepoint if available, else kprobe */
	if (hymo_syscall_nr_param <= 0) {
		pr_err("HymoFS: hymo_syscall_nr must be positive (got %d)\n", hymo_syscall_nr_param);
		return -EINVAL;
	}

	if (!hymo_skip_getfd_param &&
	    (!hymofs_tracepoint_path_registered() || !hymofs_tracepoint_getfd_registered())) {
		const char *ni_names[] = { "__arm64_sys_ni_syscall", "sys_ni_syscall", "__x64_sys_ni_syscall", NULL };
		unsigned long ni_addr = 0;
		int i, ret;

		for (i = 0; ni_names[i]; i++) {
			ni_addr = hymofs_lookup_name(ni_names[i]);
			if (ni_addr)
				break;
		}
		if (!ni_addr) {
			pr_err("HymoFS: ni_syscall not found\n");
			return -ENOENT;
		}
		hymo_kp_ni.addr = (kprobe_opcode_t *)ni_addr;
		hymo_krp_ni.kp.addr = (kprobe_opcode_t *)ni_addr;
		ret = register_kprobe(&hymo_kp_ni);
		if (ret) {
			pr_err("HymoFS: register_kprobe(ni_syscall) failed: %d\n", ret);
			return ret;
		}
		ret = register_kretprobe(&hymo_krp_ni);
		if (ret) {
			unregister_kprobe(&hymo_kp_ni);
			return ret;
		}
		hymo_ni_kprobe_registered = 1;
		pr_info("HymoFS: GET_FD via kprobe on ni_syscall (nr=%d)\n", hymo_syscall_nr_param);
	} else if (hymo_skip_getfd_param) {
		pr_alert("HymoFS: skipping GET_FD kprobes (hymo_skip_getfd=1)\n");
	}

	if (!hymo_skip_extra_kprobes_param && !hymofs_tracepoint_path_registered()) {
		static const char *reboot_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_reboot", "sys_reboot", NULL
#elif defined(__x86_64__)
			"__x64_sys_reboot", "sys_reboot", NULL
#else
			NULL
#endif
		};
		void *reboot_addr = NULL;
		int i, ret;

		for (i = 0; reboot_symbols[i]; i++) {
			reboot_addr = (void *)hymofs_lookup_name(reboot_symbols[i]);
			if (reboot_addr)
				break;
		}
		if (reboot_addr) {
			hymo_kp_reboot.addr = (kprobe_opcode_t *)reboot_addr;
			hymo_krp_reboot.kp.addr = (kprobe_opcode_t *)reboot_addr;
			hymo_krp_reboot.maxactive = 16;
			ret = register_kprobe(&hymo_kp_reboot);
			if (ret == 0) {
				ret = register_kretprobe(&hymo_krp_reboot);
				if (ret)
					unregister_kprobe(&hymo_kp_reboot);
				else
					hymo_reboot_kprobe_registered = 1;
			}
		}
	}

	if (!hymo_skip_extra_kprobes_param && !hymofs_tracepoint_path_registered()) {
		static const char *prctl_symbols[] = {
#if defined(__aarch64__)
			"__arm64_sys_prctl", "sys_prctl", NULL
#elif defined(__x86_64__)
			"__x64_sys_prctl", "sys_prctl", NULL
#else
			NULL
#endif
		};
		void *prctl_addr = NULL;
		int i, ret;

		for (i = 0; prctl_symbols[i]; i++) {
			prctl_addr = (void *)hymofs_lookup_name(prctl_symbols[i]);
			if (prctl_addr)
				break;
		}
		if (prctl_addr) {
			hymo_kp_prctl.addr = (kprobe_opcode_t *)prctl_addr;
			ret = register_kprobe(&hymo_kp_prctl);
			if (ret == 0)
				hymo_prctl_kprobe_registered = 1;
		}
	} else if (hymo_skip_extra_kprobes_param) {
		pr_alert("HymoFS: skipping extra kprobes (reboot,prctl,uname,cmdline)\n");
	}

	/* uname spoofing: direct utsname() memory writes, no kprobe. Resolve
	 * symbols once here; ioctl handlers toggle global/scoped modes. */
	if (hymofs_uname_init() != 0)
		pr_warn("HymoFS: uname spoofing unavailable (init_uts_ns/uts_sem not resolvable)\n");

	/* cmdline spoofing: tracepoint when available, else kretprobe on read, else kprobe on cmdline_proc_show */
	if (!hymo_skip_extra_kprobes_param) {
		int ret;
		if (!hymofs_tracepoint_path_registered() || !hymofs_tracepoint_getfd_registered()) {
			const char *read_sym =
#if defined(__aarch64__)
			"__arm64_sys_read";
#elif defined(__x86_64__)
			"__x64_sys_read";
#else
			NULL;
#endif
		unsigned long read_addr = read_sym ? hymofs_lookup_name(read_sym) : 0;

		if (read_addr) {
			hymo_krp_cmdline_read.kp.addr = (kprobe_opcode_t *)read_addr;
			ret = register_kretprobe(&hymo_krp_cmdline_read);
			if (ret == 0) {
				pr_info("HymoFS: cmdline spoofing via kretprobe on %s\n", read_sym);
				hymo_cmdline_kretprobe_registered = 1;
			}
		}
		if (!hymo_cmdline_kretprobe_registered) {
			unsigned long cmdline_addr = hymofs_lookup_name("cmdline_proc_show");
			if (cmdline_addr) {
				hymo_kp_cmdline.addr = (kprobe_opcode_t *)cmdline_addr;
				ret = register_kprobe(&hymo_kp_cmdline);
				if (ret == 0) {
					pr_info("HymoFS: cmdline spoofing via kprobe on cmdline_proc_show\n");
					hymo_cmdline_kprobe_registered = 1;
				} else {
					pr_warn("HymoFS: register_kprobe(cmdline_proc_show) failed: %d\n", ret);
				}
			} else {
				pr_warn("HymoFS: cmdline_proc_show not found, cmdline spoofing disabled\n");
			}
		}
	} else {
		pr_info("HymoFS: cmdline spoofing via tracepoint (sys_enter/sys_exit)\n");
	}
	}

	/* /proc mount map hiding: prefer kretprobe on read() (less overhead, shares syscall with
	 * cmdline etc); fallback to kprobe on show_vfsmnt/show_mountinfo when read path unavailable. */
	{
		static const char *read_syms[] = {
#if defined(__aarch64__)
			"__arm64_sys_read", "sys_read", "SyS_read", NULL
#elif defined(__x86_64__)
			"__x64_sys_read", "sys_read", "SyS_read", NULL
#elif defined(__arm__)
			"__arm_sys_read", "sys_read", "SyS_read", NULL
#else
			"sys_read", "SyS_read", NULL
#endif
		};
		unsigned long read_addr = 0;
		int i;
		bool use_read_path = false;

		for (i = 0; read_syms[i]; i++) {
			read_addr = hymofs_lookup_name(read_syms[i]);
			if (read_addr)
				break;
		}
		if (read_addr) {
			hymo_read_filter_buf = vmalloc(HYMO_READ_MOUNT_FILTER_BUF);
			if (hymo_read_filter_buf) {
				hymo_krp_read_mount_filter.kp.addr = (kprobe_opcode_t *)read_addr;
				if (register_kretprobe(&hymo_krp_read_mount_filter) == 0) {
					hymo_mount_hide_read_fallback_registered = 1;
					use_read_path = true;
					pr_info("HymoFS: mount hide via kretprobe on %s (read buffer filter, preferred)\n",
						read_syms[i]);
				} else {
					vfree(hymo_read_filter_buf);
					hymo_read_filter_buf = NULL;
				}
			}
		}
		if (!use_read_path) {
			unsigned long addr_vfsmnt = hymofs_lookup_name("show_vfsmnt");
			unsigned long addr_mountinfo = hymofs_lookup_name("show_mountinfo");
			if (read_addr)
				pr_info("HymoFS: mount hide read path unavailable, falling back to kprobe\n");
			else
				pr_warn("HymoFS: read syscall not found, trying kprobe on show_vfsmnt/show_mountinfo\n");
			if (addr_vfsmnt) {
				hymo_kp_show_vfsmnt.addr = (kprobe_opcode_t *)addr_vfsmnt;
				if (register_kprobe(&hymo_kp_show_vfsmnt) == 0) {
					hymo_mount_hide_vfsmnt_registered = 1;
					pr_info("HymoFS: mount hide via kprobe on show_vfsmnt (/proc/mounts)\n");
				}
			} else {
				pr_warn("HymoFS: show_vfsmnt not found\n");
			}
			if (addr_mountinfo) {
				hymo_kp_show_mountinfo.addr = (kprobe_opcode_t *)addr_mountinfo;
				if (register_kprobe(&hymo_kp_show_mountinfo) == 0) {
					hymo_mount_hide_mountinfo_registered = 1;
					pr_info("HymoFS: mount hide via kprobe on show_mountinfo (/proc/pid/mountinfo)\n");
				}
			} else {
				pr_warn("HymoFS: show_mountinfo not found\n");
			}
			/* Maps spoof fallback: seq_read used by /proc/pid/maps when read path unavailable */
			{
				unsigned long seq_read_addr = hymofs_lookup_name("seq_read");
				if (seq_read_addr) {
					hymo_maps_spoof_buf = vmalloc(HYMO_READ_MOUNT_FILTER_BUF);
					if (hymo_maps_spoof_buf) {
						hymo_krp_seq_read_maps.kp.addr = (kprobe_opcode_t *)seq_read_addr;
						if (register_kretprobe(&hymo_krp_seq_read_maps) == 0) {
							hymo_maps_seq_read_registered = 1;
							pr_info("HymoFS: maps spoof via kretprobe on seq_read (fallback)\n");
						} else {
							vfree(hymo_maps_spoof_buf);
							hymo_maps_spoof_buf = NULL;
						}
					}
				} else {
					pr_warn("HymoFS: seq_read not found, maps spoof disabled when read path unavailable\n");
				}
			}
		}
		/* statfs f_type spoof: always try to register (independent of mount hide path).
		 * Makes direct statfs(path) match resolved f_type to avoid INCONSISTENT_MOUNT detection. */
		if (!hymo_statfs_kretprobe_registered) {
			static const char *statfs_syms[] = {
#if defined(__aarch64__)
				"__arm64_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#elif defined(__x86_64__)
				"__x64_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#elif defined(__arm__)
				"__arm_sys_statfs", "sys_statfs", "SyS_statfs", NULL
#else
				"sys_statfs", "SyS_statfs", NULL
#endif
			};
			unsigned long statfs_addr = 0;
			int j;

			for (j = 0; statfs_syms[j]; j++) {
				statfs_addr = hymofs_lookup_name(statfs_syms[j]);
				if (statfs_addr)
					break;
			}
			if (statfs_addr) {
				hymo_krp_statfs.kp.addr = (kprobe_opcode_t *)statfs_addr;
				if (register_kretprobe(&hymo_krp_statfs) == 0) {
					hymo_statfs_kretprobe_registered = 1;
					pr_info("HymoFS: statfs f_type spoof via kretprobe on %s (INCONSISTENT_MOUNT bypass)\n",
						statfs_syms[j]);
				} else {
					pr_warn("HymoFS: statfs kretprobe register failed\n");
				}
			} else {
				pr_warn("HymoFS: statfs syscall not found, INCONSISTENT_MOUNT bypass disabled\n");
			}
		}
	}

	pr_alert("HymoFS: STAGE 7: registering VFS hooks\n");
#if HYMOFS_VFS_KPROBES
	if (!hymo_skip_vfs_param) {
	/* Install VFS hooks: try ftrace (entry) + kretprobe (exit) first,
	 * fallback to kprobe+kretprobe only if ftrace unavailable. getname_flags uses kprobe. */
	{
		size_t i;
		int ret;
		size_t start_idx = (hymofs_tracepoint_path_registered() ? 1 : 0);

		{
			unsigned long ft_addr[4];

			pr_info("HymoFS: trying ftrace for VFS entry (preferred over kprobes)\n");
			ret = hymofs_ftrace_try_register(ft_addr);
			if (ret == 0) {
				hymo_vfs_getxattr_addr = (void *)ft_addr[3];
				hymo_vfs_use_ftrace = true;
				pr_info("HymoFS: ftrace registered for vfs_getattr, d_path, iterate_dir, vfs_getxattr\n");
				hymo_krp_vfs_getattr.kp.addr = (kprobe_opcode_t *)ft_addr[0];
				hymo_krp_vfs_getattr.entry_handler = hymo_ftrace_krp_entry;
				hymo_krp_vfs_getattr.handler = hymo_ftrace_krp_ret;
				hymo_krp_vfs_getattr.data_size = sizeof(void *);
				hymo_krp_vfs_getattr.maxactive = 64;
				ret = register_kretprobe(&hymo_krp_vfs_getattr);
				if (ret == 0) {
					hymo_krp_d_path.kp.addr = (kprobe_opcode_t *)ft_addr[1];
					hymo_krp_d_path.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_d_path.handler = hymo_ftrace_krp_ret;
					hymo_krp_d_path.data_size = sizeof(void *);
					hymo_krp_d_path.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_d_path);
				}
				if (ret == 0) {
					hymo_krp_iterate_dir.kp.addr = (kprobe_opcode_t *)ft_addr[2];
					hymo_krp_iterate_dir.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_iterate_dir.handler = hymo_ftrace_krp_ret;
					hymo_krp_iterate_dir.data_size = sizeof(void *);
					hymo_krp_iterate_dir.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_iterate_dir);
				}
				if (ret == 0 && ft_addr[3]) {
					hymo_krp_vfs_getxattr.kp.addr = (kprobe_opcode_t *)ft_addr[3];
					hymo_krp_vfs_getxattr.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_vfs_getxattr.handler = hymo_ftrace_krp_ret;
					hymo_krp_vfs_getxattr.data_size = sizeof(void *);
					hymo_krp_vfs_getxattr.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_vfs_getxattr);
					if (ret == 0)
						hymo_getxattr_kprobe_registered = 1;
				}
				if (ret != 0) {
					hymofs_ftrace_unregister();
					hymo_vfs_use_ftrace = false;
					unregister_kretprobe(&hymo_krp_vfs_getattr);
					unregister_kretprobe(&hymo_krp_d_path);
					unregister_kretprobe(&hymo_krp_iterate_dir);
					unregister_kretprobe(&hymo_krp_vfs_getxattr);
				}
			} else {
				pr_info("HymoFS: ftrace unavailable (err=%d), using kprobes\n", ret);
			}
		}

		/* getname_flags: always kprobe (needs skip-original) */
		if (start_idx == 0) {
			unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[0].name);
			if (!addr) {
				pr_err("HymoFS: symbol not found: %s\n", hymofs_vfs_hooks[0].name);
				hymofs_tracepoint_path_exit();
				return -ENOENT;
			}
			hymofs_kprobes[0].addr = (kprobe_opcode_t *)addr;
			hymofs_kprobes[0].pre_handler = hymofs_vfs_hooks[0].pre;
			ret = register_kprobe(&hymofs_kprobes[0]);
			if (ret) {
				pr_err("HymoFS: register_kprobe(getname_flags) failed: %d\n", ret);
				hymofs_tracepoint_path_exit();
				return ret;
			}
			pr_info("HymoFS: kprobe getname_flags @0x%lx\n", addr);
			hymo_getname_kprobe_registered = true;
		}

		if (!hymo_vfs_use_ftrace) {
		/* Register kprobes + kretprobes for getattr, d_path, iterate_dir */
		for (i = 1; i < HYMOFS_VFS_HOOK_COUNT; i++) {
			unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[i].name);
			if (!addr) {
				pr_err("HymoFS: symbol not found: %s\n", hymofs_vfs_hooks[i].name);
				for (; i > 1; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
				if (start_idx == 0)
					unregister_kprobe(&hymofs_kprobes[0]);
				hymofs_tracepoint_path_exit();
				return -ENOENT;
			}
			hymofs_kprobes[i].addr = (kprobe_opcode_t *)addr;
			hymofs_kprobes[i].pre_handler = hymofs_vfs_hooks[i].pre;
			ret = register_kprobe(&hymofs_kprobes[i]);
			if (ret) {
				pr_err("HymoFS: register_kprobe(%s) failed: %d\n",
				       hymofs_vfs_hooks[i].name, ret);
				for (; i > 1; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
				if (start_idx == 0)
					unregister_kprobe(&hymofs_kprobes[0]);
				hymofs_tracepoint_path_exit();
				return ret;
			}
			pr_info("HymoFS: kprobe %s @0x%lx\n", hymofs_vfs_hooks[i].name, addr);
		}

		/* kretprobes for vfs_getattr, d_path, iterate_dir (modify after return) */
		hymo_krp_vfs_getattr.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_GETATTR].addr;
		hymo_krp_vfs_getattr.entry_handler = hymo_krp_vfs_getattr_entry;
		hymo_krp_vfs_getattr.handler = hymo_krp_vfs_getattr_ret;
		hymo_krp_vfs_getattr.data_size = sizeof(struct hymo_getattr_ri_data);
		hymo_krp_vfs_getattr.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_vfs_getattr);
		if (ret) {
			pr_err("HymoFS: register_kretprobe(vfs_getattr) failed: %d\n", ret);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
			if (start_idx == 0)
				unregister_kprobe(&hymofs_kprobes[0]);
			hymofs_tracepoint_path_exit();
			return ret;
		}
		hymo_krp_d_path.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_DPATH].addr;
		hymo_krp_d_path.entry_handler = hymo_krp_d_path_entry;
		hymo_krp_d_path.handler = hymo_krp_d_path_ret;
		hymo_krp_d_path.data_size = sizeof(struct hymo_d_path_ri_data);
		hymo_krp_d_path.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_d_path);
		if (ret) {
			pr_err("HymoFS: register_kretprobe(d_path) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
			if (start_idx == 0)
				unregister_kprobe(&hymofs_kprobes[0]);
			hymofs_tracepoint_path_exit();
			return ret;
		}
		hymo_krp_iterate_dir.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_ITERDIR].addr;
		hymo_krp_iterate_dir.entry_handler = hymo_krp_iterate_dir_entry;
		hymo_krp_iterate_dir.handler = hymo_krp_iterate_dir_ret;
		hymo_krp_iterate_dir.data_size = sizeof(struct hymo_iterate_ri_data);
		hymo_krp_iterate_dir.maxactive = 64;
		ret = register_kretprobe(&hymo_krp_iterate_dir);
		if (ret) {
			pr_err("HymoFS: register_kretprobe(iterate_dir) failed: %d\n", ret);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
				unregister_kprobe(&hymofs_kprobes[i - 1]);
			if (start_idx == 0)
				unregister_kprobe(&hymofs_kprobes[0]);
			hymofs_tracepoint_path_exit();
			return ret;
		}
		pr_info("HymoFS: kretprobes vfs_getattr, d_path, iterate_dir registered\n");

		/* vfs_getxattr kretprobe for SELinux context spoofing (optional) */
		{
			unsigned long xattr_addr = hymofs_lookup_name("vfs_getxattr");
			if (xattr_addr) {
				hymo_vfs_getxattr_addr = (void *)xattr_addr;
				hymo_krp_vfs_getxattr.kp.addr = (kprobe_opcode_t *)xattr_addr;
				hymo_krp_vfs_getxattr.entry_handler = hymo_krp_vfs_getxattr_entry;
				hymo_krp_vfs_getxattr.handler = hymo_krp_vfs_getxattr_ret;
				hymo_krp_vfs_getxattr.data_size = sizeof(struct hymo_getxattr_ri_data);
				hymo_krp_vfs_getxattr.maxactive = 64;
				ret = register_kretprobe(&hymo_krp_vfs_getxattr);
				if (ret == 0) {
					hymo_getxattr_kprobe_registered = 1;
					pr_info("HymoFS: kretprobe vfs_getxattr registered (SELinux spoof)\n");
				} else {
					pr_warn("HymoFS: register_kretprobe(vfs_getxattr) failed: %d\n", ret);
				}
			} else {
				pr_warn("HymoFS: vfs_getxattr not found, SELinux context spoofing disabled\n");
			}
		}
		} /* !hymo_vfs_use_ftrace */
	}
	pr_info("HymoFS: initialized (%d VFS %s + GET_FD via %s)\n",
		(int)(HYMOFS_VFS_HOOK_COUNT - (hymofs_tracepoint_path_registered() ? 1 : 0)),
		hymo_vfs_use_ftrace ? "ftrace" : "kprobes",
		hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered() ?
			"sys_enter/sys_exit tracepoint" : "kprobes");
	} else {
		pr_alert("HymoFS: skipping VFS hooks (hymo_skip_vfs=1)\n");
		pr_info("HymoFS: initialized (VFS hooks skipped, GET_FD via %s)\n",
			hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered() ?
				"sys_enter/sys_exit tracepoint" : "kprobes");
	}
#else
	pr_info("HymoFS: initialized (GET_FD only, VFS kprobes disabled)\n");
#endif
	/* lookup-time inode_operations override (best-effort; spoof still works
	 * via the legacy kretprobe if this fails). */
	(void)hymofs_iop_override_init();
	return 0;
}

static void __exit hymofs_lkm_exit(void)
{
	pr_info("HymoFS: shutting down\n");

	hymofs_iop_override_exit();

	if (hymo_statfs_kretprobe_registered)
		unregister_kretprobe(&hymo_krp_statfs);
	if (hymo_mount_hide_read_fallback_registered) {
		unregister_kretprobe(&hymo_krp_read_mount_filter);
		if (hymo_read_filter_buf) {
			vfree(hymo_read_filter_buf);
			hymo_read_filter_buf = NULL;
		}
	}
	if (hymo_maps_seq_read_registered) {
		unregister_kretprobe(&hymo_krp_seq_read_maps);
		if (hymo_maps_spoof_buf) {
			vfree(hymo_maps_spoof_buf);
			hymo_maps_spoof_buf = NULL;
		}
	}
	/* Clear maps spoof rules (shared by read and seq_read paths) */
	if (hymo_mount_hide_read_fallback_registered || hymo_maps_seq_read_registered) {
		struct hymo_maps_rule_entry *e, *tmp;

		mutex_lock(&hymo_maps_mutex);
		list_for_each_entry_safe(e, tmp, &hymo_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&hymo_maps_mutex);
	}
	if (hymo_mount_hide_mountinfo_registered)
		unregister_kprobe(&hymo_kp_show_mountinfo);
	if (hymo_mount_hide_vfsmnt_registered)
		unregister_kprobe(&hymo_kp_show_vfsmnt);
	if (hymo_cmdline_kretprobe_registered)
		unregister_kretprobe(&hymo_krp_cmdline_read);
	if (hymo_cmdline_kprobe_registered)
		unregister_kprobe(&hymo_kp_cmdline);
	if (hymo_prctl_kprobe_registered)
		unregister_kprobe(&hymo_kp_prctl);
	if (hymo_reboot_kprobe_registered) {
		unregister_kretprobe(&hymo_krp_reboot);
		unregister_kprobe(&hymo_kp_reboot);
	}
	if (hymo_ni_kprobe_registered) {
		unregister_kretprobe(&hymo_krp_ni);
		unregister_kprobe(&hymo_kp_ni);
	}

#if HYMOFS_VFS_KPROBES
	hymofs_tracepoint_path_exit();
	if (!hymo_skip_vfs_param) {
		if (hymo_vfs_use_ftrace) {
			hymofs_ftrace_unregister();
			if (hymo_getxattr_kprobe_registered)
				unregister_kretprobe(&hymo_krp_vfs_getxattr);
			unregister_kretprobe(&hymo_krp_iterate_dir);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			if (hymo_getname_kprobe_registered)
				unregister_kprobe(&hymofs_kprobes[0]);
		} else {
			if (hymo_getxattr_kprobe_registered)
				unregister_kretprobe(&hymo_krp_vfs_getxattr);
			unregister_kretprobe(&hymo_krp_iterate_dir);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			{
				size_t i, start = hymofs_tracepoint_path_registered() ? 1 : 0;
				for (i = start; i < HYMOFS_VFS_HOOK_COUNT; i++)
					unregister_kprobe(&hymofs_kprobes[i]);
			}
		}
	}
#endif

	/* Tear down uname spoof state (restores init_uts_ns if global was on,
	 * frees scoped config). Per-task uts_ns copies already in use are
	 * owned by their tasks; they'll be put() on exit normally. */
	hymofs_uname_exit();

	/* Clean up all rules and wait for RCU grace period */
	{
		struct hymo_cmdline_rcu *old_cmdline;

		mutex_lock(&hymo_config_mutex);
		hymo_cleanup_locked();
		old_cmdline = rcu_dereference_protected(hymo_spoof_cmdline_ptr,
							lockdep_is_held(&hymo_config_mutex));
		rcu_assign_pointer(hymo_spoof_cmdline_ptr, NULL);
		mutex_unlock(&hymo_config_mutex);

		rcu_barrier();
		kfree(old_cmdline);
	}
	if (hymo_filldir_cache)
		kmem_cache_destroy(hymo_filldir_cache);
	vfree(hymo_percpu_base);
	vfree(hymo_getname_buf_base);
	vfree(hymo_iterate_buf_base);
	hymo_percpu_base = NULL;
	hymo_getname_buf_base = NULL;
	hymo_iterate_buf_base = NULL;
	pr_info("HymoFS: unloaded\n");
}

module_init(hymofs_lkm_init);
module_exit(hymofs_lkm_exit);
