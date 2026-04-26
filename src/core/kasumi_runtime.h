/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - runtime globals, resolved kernel symbols, and feature flags.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_RUNTIME_H
#define _KASUMI_RUNTIME_H

#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/fcntl.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/stat.h>
#include <linux/vmalloc.h>

#include "kasumi_base.h"
#include "kasumi_types.h"

extern bool kasumi_enabled;
extern atomic_t kasumi_rule_count;
extern atomic_t kasumi_hide_count;
extern atomic_t kasumi_spoof_kstat_count;

struct kasumi_hook_stats {
	atomic64_t vfs_getattr_entries;
	atomic64_t vfs_getattr_spoofs;
	atomic64_t iop_getattr_entries;
	atomic64_t iop_getattr_spoofs;
	atomic64_t d_path_entries;
	atomic64_t d_path_rewrites;
	atomic64_t dop_dname_entries;
	atomic64_t xattr_sid_overrides;
	atomic64_t iterate_entries;
	atomic64_t iterate_wrapped;
	atomic64_t iterate_fop_entries;
	atomic64_t iterate_fop_wrapped;
	atomic64_t sop_destroy_inode;
	atomic64_t filldir_hidden;
	atomic64_t filldir_injected;
	atomic64_t getxattr_entries;
	atomic64_t getxattr_spoofs;
};

extern struct kasumi_hook_stats kasumi_hook_stats;

struct kasumi_percpu {
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
	struct {
		struct statx __user *buf;
		char path[KSM_MAX_LEN_PATHNAME];
		int active;
	} statx_ctx;
	struct {
		void __user *buf;
		unsigned long spoof_f_type;
		int active;
	} statfs_ctx;
#endif
	int mount_proxy_pending;
};

extern struct kasumi_percpu *kasumi_percpu_base;

static inline struct kasumi_percpu *kasumi_this_cpu(void)
{
	return kasumi_percpu_base + smp_processor_id();
}

extern char *kasumi_getname_buf_base;
extern char *kasumi_iterate_buf_base;
extern atomic_long_t kasumi_ioctl_tgid;
extern atomic_long_t kasumi_xattr_source_tgid;
extern struct kmem_cache *kasumi_filldir_cache;
extern unsigned long (*kasumi_kallsyms_lookup_name)(const char *name);

bool kasumi_valid_kernel_addr(unsigned long addr);
unsigned long kasumi_lookup_name(const char *name);
void kasumi_resolve_kallsyms_lookup(void);

typedef bool (*kasumi_ksu_is_allow_uid_fn)(uid_t uid);
typedef bool (*kasumi_ksu_uid_should_umount_fn)(uid_t uid);
typedef bool (*kasumi_ksu_get_allow_list_fn)(int *array, u16 length, u16 *out_length,
					   u16 *out_total, bool allow);

extern kasumi_ksu_is_allow_uid_fn kasumi_ksu_is_allow_uid_ptr;
extern kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;
extern kasumi_ksu_get_allow_list_fn kasumi_ksu_get_allow_list_ptr;

extern bool kasumi_stealth_enabled;
extern char kasumi_mirror_path_buf[PATH_MAX];
extern char kasumi_mirror_name_buf[NAME_MAX];
extern char *kasumi_current_mirror_path;
extern char *kasumi_current_mirror_name;

struct kasumi_cmdline_rcu {
	struct rcu_head rcu;
	char cmdline[KSM_FAKE_CMDLINE_SIZE];
};

extern struct kasumi_cmdline_rcu __rcu *kasumi_spoof_cmdline_ptr;
extern bool kasumi_cmdline_spoof_active;
extern pid_t kasumi_daemon_pid;

extern int kasumi_cmdline_kprobe_registered;
extern int kasumi_cmdline_kretprobe_registered;
extern int kasumi_getxattr_kprobe_registered;
extern int kasumi_mount_hide_vfsmnt_registered;
extern int kasumi_mount_hide_mountinfo_registered;
extern int kasumi_mount_hide_vfs_read_registered;
extern int kasumi_mount_hide_read_fallback_registered;
extern int kasumi_mount_hide_pread_fallback_registered;
extern int kasumi_maps_seq_read_registered;
extern int kasumi_proc_proxy_registered;
extern int kasumi_feature_enabled_mask;
extern int kasumi_statfs_kretprobe_registered;
extern int kasumi_statfs_tracepoint_registered;
extern int kasumi_ni_kprobe_registered;
extern int kasumi_reboot_kprobe_registered;
extern int kasumi_syscall_nr_param;
extern bool kasumi_getname_kprobe_registered;
extern bool kasumi_vfs_use_ftrace;
extern dev_t kasumi_system_dev;

extern int (*kasumi_kern_path)(const char *, unsigned int, struct path *);
extern int (*kasumi_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
extern struct file *(*kasumi_dentry_open)(const struct path *, int, const struct cred *);
extern char *(*kasumi_d_absolute_path)(const struct path *, char *, int);
extern char *(*kasumi_dentry_path_raw)(const struct dentry *, char *, int);
extern char *(*kasumi_d_path)(const struct path *, char *, int);
extern struct dentry *(*kasumi_d_hash_and_lookup)(struct dentry *, const struct qstr *);
extern void *kasumi_vfs_getxattr_addr;
extern struct file *(*kasumi_filp_open)(const char *, int, umode_t);
extern int (*kasumi_filp_close)(struct file *, fl_owner_t);
extern ssize_t (*kasumi_kernel_read)(struct file *, void *, size_t, loff_t *);
extern char *(*kasumi_strndup_user)(const char __user *, long);
extern struct filename *(*kasumi_getname_kernel)(const char *);
extern void (*kasumi_ihold)(struct inode *);
extern long (*kasumi_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);

#endif /* _KASUMI_RUNTIME_H */
