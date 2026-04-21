// SPDX-License-Identifier: GPL-2.0
/*
 * HymoFS uname spoofing.
 *
 * Two modes, both operate directly on `struct new_utsname` memory so every
 * in-kernel consumer (uname(2), /proc/version, /proc/sys/kernel/{ostype,
 * osrelease,version,domainname}, sysinfo, ...) sees the fake values without
 * any per-call hook. This replaces the old kretprobe-on-newuname design.
 *
 *   Global  — overwrite init_uts_ns.name. Affects every task that still
 *             shares init_uts_ns (almost all of Android userspace).
 *   Scoped  — unshare CLONE_NEWUTS for a target task on first trigger,
 *             then write fake fields into its private uts_ns. Only that
 *             task (and its children via inherit) see spoofed values.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

#include "hymofs_lkm.h"
#include "hymofs_uname.h"

/* ------------------------------------------------------------------
 * Resolved kernel symbols (none of these are EXPORT_SYMBOL)
 * ------------------------------------------------------------------ */
static struct rw_semaphore *hymo_uts_sem;
static struct uts_namespace *hymo_init_uts_ns_ptr;
static struct nsproxy *(*hymo_create_new_namespaces_fn)(unsigned long,
							struct task_struct *,
							struct user_namespace *,
							struct fs_struct *);
static int (*hymo_unshare_nsproxy_namespaces_fn)(unsigned long,
						 struct nsproxy **,
						 struct cred *,
						 struct fs_struct *);
static void (*hymo_switch_task_namespaces_fn)(struct task_struct *,
					      struct nsproxy *);
static const struct cred *(*hymo_override_creds_fn)(const struct cred *);
static void (*hymo_revert_creds_fn)(const struct cred *);
static struct task_struct *hymo_init_task_ptr;
static struct cred *hymo_scoped_kcred;

/* ------------------------------------------------------------------
 * Config state
 * ------------------------------------------------------------------ */
static DEFINE_MUTEX(hymo_uname_cfg_mutex);

struct hymo_uname_cfg_rcu {
	struct hymo_spoof_uname data;
	struct rcu_head rcu;
};

/* Scoped-mode spoof config (RCU-protected). */
static struct hymo_uname_cfg_rcu __rcu *hymo_uname_scoped_cfg;
static bool hymo_uname_scoped_on;

/* Global-mode state */
static bool hymo_uname_global_on;
static struct new_utsname hymo_uname_global_saved; /* originals captured on first apply */
static bool hymo_uname_global_saved_valid;

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

static inline bool field_set(const char *s)
{
	return s && s[0] != '\0';
}

/* Overwrite dst fields in-place with any non-empty src fields. Caller holds uts_sem. */
static void hymo_merge_uts(struct new_utsname *dst, const struct hymo_spoof_uname *src)
{
	if (field_set(src->sysname))
		strscpy(dst->sysname, src->sysname, sizeof(dst->sysname));
	if (field_set(src->nodename))
		strscpy(dst->nodename, src->nodename, sizeof(dst->nodename));
	if (field_set(src->release))
		strscpy(dst->release, src->release, sizeof(dst->release));
	if (field_set(src->version))
		strscpy(dst->version, src->version, sizeof(dst->version));
	if (field_set(src->machine))
		strscpy(dst->machine, src->machine, sizeof(dst->machine));
	if (field_set(src->domainname))
		strscpy(dst->domainname, src->domainname, sizeof(dst->domainname));
}

static bool spoof_has_any(const struct hymo_spoof_uname *u)
{
	return field_set(u->sysname) || field_set(u->nodename) ||
	       field_set(u->release) || field_set(u->version) ||
	       field_set(u->machine) || field_set(u->domainname);
}

static const char *hymo_errno_name(int err)
{
	switch (err) {
	case 0:
		return "OK";
	case -EPERM:
		return "EPERM";
	case -EINVAL:
		return "EINVAL";
	case -ENOMEM:
		return "ENOMEM";
	case -ENOSPC:
		return "ENOSPC";
	case -EUSERS:
		return "EUSERS";
	default:
		return "UNKNOWN";
	}
}

/*
 * kCFI rejects indirect calls through dynamically resolved pointers unless the
 * callsite is explicitly exempted. Keep the exemption narrowly scoped to this
 * wrapper so the rest of the uname path still benefits from normal checking.
 */
static HYMO_NOCFI struct nsproxy *hymo_create_new_uts_ns_nocfi(struct task_struct *task)
{
	if (!hymo_create_new_namespaces_fn || !task || !task->fs)
		return ERR_PTR(-ENOSYS);
	return hymo_create_new_namespaces_fn(CLONE_NEWUTS, task,
					     current_user_ns(), task->fs);
}

/* ------------------------------------------------------------------
 * Init / exit
 * ------------------------------------------------------------------ */

int hymofs_uname_init(void)
{
	hymo_uts_sem = (struct rw_semaphore *)hymofs_lookup_name("uts_sem");
	hymo_init_uts_ns_ptr = (struct uts_namespace *)hymofs_lookup_name("init_uts_ns");
	hymo_create_new_namespaces_fn = (void *)hymofs_lookup_name("create_new_namespaces");
	hymo_unshare_nsproxy_namespaces_fn = (void *)hymofs_lookup_name("unshare_nsproxy_namespaces");
	hymo_switch_task_namespaces_fn = (void *)hymofs_lookup_name("switch_task_namespaces");
	hymo_override_creds_fn = (void *)hymofs_lookup_name("override_creds");
	hymo_revert_creds_fn = (void *)hymofs_lookup_name("revert_creds");
	hymo_init_task_ptr = (struct task_struct *)hymofs_lookup_name("init_task");

	if (!hymo_uts_sem || !hymo_init_uts_ns_ptr) {
		pr_warn("HymoFS: uname: uts_sem/init_uts_ns not resolvable — uname spoof disabled\n");
		return -ENOENT;
	}
	if (hymo_unshare_nsproxy_namespaces_fn && hymo_switch_task_namespaces_fn &&
	    hymo_override_creds_fn && hymo_revert_creds_fn && hymo_init_task_ptr)
		hymo_scoped_kcred = prepare_kernel_cred(hymo_init_task_ptr);
	if ((!hymo_create_new_namespaces_fn &&
	     (!hymo_unshare_nsproxy_namespaces_fn || !hymo_override_creds_fn ||
	      !hymo_revert_creds_fn || !hymo_init_task_ptr || !hymo_scoped_kcred)) ||
	    !hymo_switch_task_namespaces_fn) {
		pr_info("HymoFS: uname: scoped mode unavailable (ns/cred helpers missing), global mode only\n");
	}
	return 0;
}

void hymofs_uname_exit(void)
{
	struct hymo_uname_cfg_rcu *old;

	if (hymo_uname_global_on)
		hymofs_uname_restore_global();

	mutex_lock(&hymo_uname_cfg_mutex);
	old = rcu_dereference_protected(hymo_uname_scoped_cfg,
					lockdep_is_held(&hymo_uname_cfg_mutex));
	rcu_assign_pointer(hymo_uname_scoped_cfg, NULL);
	WRITE_ONCE(hymo_uname_scoped_on, false);
	mutex_unlock(&hymo_uname_cfg_mutex);

	if (old) {
		rcu_barrier();
		kfree(old);
	}

	if (hymo_scoped_kcred) {
		put_cred(hymo_scoped_kcred);
		hymo_scoped_kcred = NULL;
	}
}

/* ------------------------------------------------------------------
 * Global mode
 * ------------------------------------------------------------------ */

int hymofs_uname_apply_global(const struct hymo_spoof_uname *u)
{
	if (!hymo_uts_sem || !hymo_init_uts_ns_ptr)
		return -ENOSYS;
	if (!u || !spoof_has_any(u))
		return -EINVAL;

	mutex_lock(&hymo_uname_cfg_mutex);
	down_write(hymo_uts_sem);
	if (!hymo_uname_global_saved_valid) {
		memcpy(&hymo_uname_global_saved, &hymo_init_uts_ns_ptr->name,
		       sizeof(hymo_uname_global_saved));
		hymo_uname_global_saved_valid = true;
	}
	hymo_merge_uts(&hymo_init_uts_ns_ptr->name, u);
	up_write(hymo_uts_sem);
	hymo_uname_global_on = true;
	mutex_unlock(&hymo_uname_cfg_mutex);

	pr_info("HymoFS: uname global applied: release='%s' version='%s'\n",
		hymo_init_uts_ns_ptr->name.release,
		hymo_init_uts_ns_ptr->name.version);
	return 0;
}

int hymofs_uname_restore_global(void)
{
	if (!hymo_uts_sem || !hymo_init_uts_ns_ptr)
		return -ENOSYS;

	mutex_lock(&hymo_uname_cfg_mutex);
	if (!hymo_uname_global_saved_valid) {
		mutex_unlock(&hymo_uname_cfg_mutex);
		return 0;
	}
	down_write(hymo_uts_sem);
	memcpy(&hymo_init_uts_ns_ptr->name, &hymo_uname_global_saved,
	       sizeof(hymo_init_uts_ns_ptr->name));
	up_write(hymo_uts_sem);
	hymo_uname_global_saved_valid = false;
	hymo_uname_global_on = false;
	mutex_unlock(&hymo_uname_cfg_mutex);

	pr_info("HymoFS: uname global restored\n");
	return 0;
}

bool hymofs_uname_global_active(void)
{
	return READ_ONCE(hymo_uname_global_on);
}

bool hymofs_uname_capable(void)
{
	return hymo_uts_sem && hymo_init_uts_ns_ptr;
}

/* ------------------------------------------------------------------
 * Scoped mode
 * ------------------------------------------------------------------ */

int hymofs_uname_set_scoped_config(const struct hymo_spoof_uname *u)
{
	struct hymo_uname_cfg_rcu *new_cfg = NULL;
	struct hymo_uname_cfg_rcu *old_cfg;
	bool active = u && spoof_has_any(u);

	if (active && !hymo_switch_task_namespaces_fn)
		return -ENOSYS;
	if (active && !hymo_create_new_namespaces_fn &&
	    (!hymo_unshare_nsproxy_namespaces_fn ||
	     !hymo_override_creds_fn ||
	     !hymo_revert_creds_fn ||
	     !hymo_init_task_ptr ||
	     !hymo_scoped_kcred))
		return -ENOSYS;

	if (active) {
		new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
		if (!new_cfg)
			return -ENOMEM;
		memcpy(&new_cfg->data, u, sizeof(new_cfg->data));
	}

	mutex_lock(&hymo_uname_cfg_mutex);
	old_cfg = rcu_dereference_protected(hymo_uname_scoped_cfg,
					    lockdep_is_held(&hymo_uname_cfg_mutex));
	rcu_assign_pointer(hymo_uname_scoped_cfg, new_cfg);
	WRITE_ONCE(hymo_uname_scoped_on, active);
	mutex_unlock(&hymo_uname_cfg_mutex);

	if (old_cfg)
		kfree_rcu(old_cfg, rcu);

	pr_info("HymoFS: uname scoped config %s\n", active ? "set" : "cleared");
	return 0;
}

bool hymofs_uname_scoped_active(void)
{
	return READ_ONCE(hymo_uname_scoped_on);
}

void hymofs_uname_apply_scoped_current(void)
{
	struct task_struct *task = current;
	struct nsproxy *new_nsp = NULL;
	struct uts_namespace *cur_uts;
	struct hymo_uname_cfg_rcu *cfg;
	struct hymo_spoof_uname spoof;
	const struct cred *old_cred;
	int ret;

	if (!READ_ONCE(hymo_uname_scoped_on))
		return;
	if (!hymo_switch_task_namespaces_fn)
		return;
	if (!hymo_create_new_namespaces_fn &&
	    (!hymo_unshare_nsproxy_namespaces_fn || !hymo_override_creds_fn ||
	     !hymo_revert_creds_fn || !hymo_init_task_ptr || !hymo_scoped_kcred))
		return;
	if (!task || (task->flags & PF_KTHREAD))
		return;

	/* task_lock protects nsproxy read; cheap enough for one-shot path. */
	task_lock(task);
	cur_uts = task->nsproxy ? task->nsproxy->uts_ns : NULL;
	task_unlock(task);

	/*
	 * Fast exit: already owns a private uts_ns (either we did it earlier
	 * or the task unshared on its own). We never touch a namespace we
	 * don't own, and we never re-apply.
	 */
	if (!cur_uts || cur_uts != hymo_init_uts_ns_ptr)
		return;

	if (!task->fs)
		return;

	rcu_read_lock();
	cfg = rcu_dereference(hymo_uname_scoped_cfg);
	if (!cfg) {
		rcu_read_unlock();
		return;
	}
	memcpy(&spoof, &cfg->data, sizeof(spoof));
	rcu_read_unlock();

	/*
	 * This helper enforces CAP_SYS_ADMIN in the caller's current user_ns.
	 * Normal apps fail that check, so scoped uname would silently never
	 * activate. Temporarily adopt a kernel service cred while creating the
	 * private UTS ns, then immediately revert.
	 */
	if (hymo_create_new_namespaces_fn) {
		new_nsp = hymo_create_new_uts_ns_nocfi(task);
		if (IS_ERR(new_nsp)) {
			ret = PTR_ERR(new_nsp);
			hymo_log("uname scoped: nocfi create_new_namespaces(CLONE_NEWUTS) failed: %d (%s)\n",
				 ret, hymo_errno_name(ret));
			return;
		}
	} else {
		old_cred = hymo_override_creds_fn(hymo_scoped_kcred);
		ret = hymo_unshare_nsproxy_namespaces_fn(CLONE_NEWUTS, &new_nsp,
							 hymo_scoped_kcred,
							 task->fs);
		hymo_revert_creds_fn(old_cred);
		if (ret || !new_nsp) {
			hymo_log("uname scoped: CLONE_NEWUTS unshare failed: %d (%s)\n",
				 ret, hymo_errno_name(ret));
			return;
		}
	}

	down_write(hymo_uts_sem);
	hymo_merge_uts(&new_nsp->uts_ns->name, &spoof);
	up_write(hymo_uts_sem);

	hymo_switch_task_namespaces_fn(task, new_nsp);
}
