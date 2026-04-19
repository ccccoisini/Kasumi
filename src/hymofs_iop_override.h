/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - lookup-time inode_operations override.
 *
 * Strategy: install a per-inode shadow inode_operations table that wraps
 * .getattr to apply kstat spoofing inline (indirect call instead of kprobe
 * trap). After install, vfs_getattr -> inode->i_op->getattr runs our shadow
 * directly with no probe overhead.
 *
 * The pointer inode->i_op IS writable (only the pointed-to ops table itself is
 * declared const), so no read-only memory tricks are required.
 *
 * Lifecycle:
 *   - install:    called when an inode is first identified as a redirect
 *                 target (currently from the existing vfs_getattr kretprobe
 *                 ret handler; future: from a d_splice_alias hook).
 *   - uninstall:  triggered automatically by kprobe on __destroy_inode.
 */
#ifndef _HYMOFS_IOP_OVERRIDE_H
#define _HYMOFS_IOP_OVERRIDE_H

#include <linux/fs.h>

/* Module init/exit. Returns 0 on success. */
int hymofs_iop_override_init(void);
void hymofs_iop_override_exit(void);

/*
 * Install shadow inode_operations on `inode`. Idempotent: safe to call on an
 * already-installed inode (becomes a no-op).
 *
 * After successful install, AS_FLAGS_HYMO_IOP_INSTALLED is set on
 * inode->i_mapping->flags so the slow kprobe path can short-circuit.
 *
 * Returns 0 on success or already-installed; negative errno on failure.
 */
int hymofs_iop_install(struct inode *inode);

/*
 * Apply kstat spoofing in place. Extracted from the original vfs_getattr
 * kretprobe ret handler so both the legacy kprobe and the new shadow getattr
 * share one implementation.
 *
 * Caller must have a valid inode and stat. Safe to call from atomic context.
 */
void hymo_apply_kstat_spoof(struct inode *inode, struct kstat *stat);

#endif /* _HYMOFS_IOP_OVERRIDE_H */
