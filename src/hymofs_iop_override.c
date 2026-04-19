// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
/*
 * HymoFS - lookup-time inode_operations override.
 *
 * See hymofs_iop_override.h for design notes.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "hymofs_lkm.h"
#include "hymofs_iop_override.h"

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/namei.h>

#define HYMO_IOP_HASH_BITS 10

struct hymo_iop_meta {
	struct inode *inode;                          /* hash key */
	const struct inode_operations *orig_iop;      /* what i_op pointed to before */
	struct inode_operations shadow_iop;           /* our copy with .getattr patched */
	struct hlist_node node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(hymo_iop_table, HYMO_IOP_HASH_BITS);
static DEFINE_SPINLOCK(hymo_iop_lock);

/* __destroy_inode kprobe: triggers uninstall before inode memory is freed */
static struct kprobe hymo_kp_destroy_inode = {
	.symbol_name = "__destroy_inode",
};
static bool hymo_kp_destroy_inode_registered;

/* ------------------------------------------------------------------ */
/* hash table helpers                                                  */
/* ------------------------------------------------------------------ */

static struct hymo_iop_meta *hymo_iop_lookup_rcu(struct inode *inode)
{
	struct hymo_iop_meta *m;

	hash_for_each_possible_rcu(hymo_iop_table, m, node, (unsigned long)inode) {
		if (m->inode == inode)
			return m;
	}
	return NULL;
}

static void hymo_iop_meta_free_rcu(struct rcu_head *rcu)
{
	struct hymo_iop_meta *m = container_of(rcu, struct hymo_iop_meta, rcu);
	kfree(m);
}

/* ------------------------------------------------------------------ */
/* shadow getattr - signature varies across kernel versions             */
/* ------------------------------------------------------------------ */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0))
HYMO_NOCFI static int hymo_shadow_getattr(struct mnt_idmap *idmap,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct hymo_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	rcu_read_lock();
	m = hymo_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(idmap, path, stat, request_mask, query_flags);
	else
		ret = -EOPNOTSUPP;

	if (ret == 0)
		hymo_apply_kstat_spoof(inode, stat);
	return ret;
}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
HYMO_NOCFI static int hymo_shadow_getattr(struct user_namespace *userns,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct hymo_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	rcu_read_lock();
	m = hymo_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(userns, path, stat, request_mask, query_flags);
	else
		ret = -EOPNOTSUPP;

	if (ret == 0)
		hymo_apply_kstat_spoof(inode, stat);
	return ret;
}
#else
HYMO_NOCFI static int hymo_shadow_getattr(const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct hymo_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	rcu_read_lock();
	m = hymo_iop_lookup_rcu(inode);
	if (m)
		orig = m->orig_iop;
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(path, stat, request_mask, query_flags);
	else
		ret = -EOPNOTSUPP;

	if (ret == 0)
		hymo_apply_kstat_spoof(inode, stat);
	return ret;
}
#endif

/* ------------------------------------------------------------------ */
/* install / uninstall                                                  */
/* ------------------------------------------------------------------ */

int hymofs_iop_install(struct inode *inode)
{
	struct hymo_iop_meta *m, *existing;
	const struct inode_operations *orig;

	if (!inode || !inode->i_op)
		return -EINVAL;
	/* Require mapping so AS_FLAGS bit (and __destroy_inode fast filter) work. */
	if (!inode->i_mapping)
		return -EINVAL;

	/* Fast path: already installed (atomic flag check). */
	if (test_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &inode->i_mapping->flags))
		return 0;

	orig = inode->i_op;

	m = kzalloc(sizeof(*m), GFP_ATOMIC);
	if (!m)
		return -ENOMEM;

	m->inode = inode;
	m->orig_iop = orig;
	memcpy(&m->shadow_iop, orig, sizeof(struct inode_operations));
	m->shadow_iop.getattr = hymo_shadow_getattr;

	spin_lock(&hymo_iop_lock);
	/* Race: another CPU may have installed concurrently. */
	existing = hymo_iop_lookup_rcu(inode);
	if (existing) {
		spin_unlock(&hymo_iop_lock);
		kfree(m);
		return 0;
	}
	hash_add_rcu(hymo_iop_table, &m->node, (unsigned long)inode);
	/* Publish: set flag THEN swap pointer so readers seeing new i_op
	 * also see the flag. */
	set_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &inode->i_mapping->flags);
	smp_wmb();
	WRITE_ONCE(inode->i_op, &m->shadow_iop);
	spin_unlock(&hymo_iop_lock);

	hymo_log("iop_override: installed on inode %p (orig=%p)\n", inode, orig);
	return 0;
}

/*
 * Internal uninstall (called from __destroy_inode kprobe and from exit).
 * Restores original i_op pointer and frees metadata after RCU grace period.
 * Safe to call when not installed.
 */
static void hymo_iop_uninstall_locked(struct inode *inode)
{
	struct hymo_iop_meta *m;

	m = hymo_iop_lookup_rcu(inode);
	if (!m)
		return;

	/* Restore original first so any in-flight reader either sees old or
	 * shadow (both valid until RCU grace ends). */
	if (inode->i_op == &m->shadow_iop)
		WRITE_ONCE(inode->i_op, m->orig_iop);

	hash_del_rcu(&m->node);
	if (inode->i_mapping)
		clear_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &inode->i_mapping->flags);

	call_rcu(&m->rcu, hymo_iop_meta_free_rcu);
}

/* ------------------------------------------------------------------ */
/* __destroy_inode kprobe                                              */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__)
#define HYMO_DESTROY_INODE_REG(regs) ((struct inode *)(regs)->regs[0])
#elif defined(__x86_64__)
#define HYMO_DESTROY_INODE_REG(regs) ((struct inode *)(regs)->di)
#else
#define HYMO_DESTROY_INODE_REG(regs) ((struct inode *)NULL)
#endif

static int hymo_kp_destroy_inode_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = HYMO_DESTROY_INODE_REG(regs);

	if (!inode)
		return 0;
	/* Fast filter: skip the lookup if flag not set. */
	if (!inode->i_mapping ||
	    !test_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &inode->i_mapping->flags))
		return 0;

	spin_lock(&hymo_iop_lock);
	hymo_iop_uninstall_locked(inode);
	spin_unlock(&hymo_iop_lock);
	return 0;
}

/* ------------------------------------------------------------------ */
/* init / exit                                                          */
/* ------------------------------------------------------------------ */

int hymofs_iop_override_init(void)
{
	unsigned long addr;
	int ret;

	hash_init(hymo_iop_table);

	addr = hymofs_lookup_name("__destroy_inode");
	if (!addr) {
		pr_warn("HymoFS: __destroy_inode symbol not found; iop_override disabled\n");
		return -ENOENT;
	}
	hymo_kp_destroy_inode.addr = (kprobe_opcode_t *)addr;
	hymo_kp_destroy_inode.symbol_name = NULL; /* prefer addr */
	hymo_kp_destroy_inode.pre_handler = hymo_kp_destroy_inode_pre;
	ret = register_kprobe(&hymo_kp_destroy_inode);
	if (ret) {
		pr_err("HymoFS: register_kprobe(__destroy_inode) failed: %d\n", ret);
		return ret;
	}
	hymo_kp_destroy_inode_registered = true;
	pr_info("HymoFS: iop_override initialized (__destroy_inode @0x%lx)\n", addr);
	return 0;
}

void hymofs_iop_override_exit(void)
{
	struct hymo_iop_meta *m;
	struct hlist_node *tmp;
	int bkt;

	if (hymo_kp_destroy_inode_registered) {
		unregister_kprobe(&hymo_kp_destroy_inode);
		hymo_kp_destroy_inode_registered = false;
	}

	/*
	 * Restore all live shadow installs. After unregister_kprobe above,
	 * no new entries can be added (callers gated by hymofs_enabled or
	 * destroy_inode no longer calls us).
	 */
	spin_lock(&hymo_iop_lock);
	hash_for_each_safe(hymo_iop_table, bkt, tmp, m, node) {
		if (m->inode && m->inode->i_op == &m->shadow_iop)
			WRITE_ONCE(m->inode->i_op, m->orig_iop);
		if (m->inode && m->inode->i_mapping)
			clear_bit(AS_FLAGS_HYMO_IOP_INSTALLED,
				  &m->inode->i_mapping->flags);
		hash_del_rcu(&m->node);
		call_rcu(&m->rcu, hymo_iop_meta_free_rcu);
	}
	spin_unlock(&hymo_iop_lock);

	/* Wait for outstanding RCU readers and freelist callbacks. */
	rcu_barrier();
	pr_info("HymoFS: iop_override exited\n");
}
