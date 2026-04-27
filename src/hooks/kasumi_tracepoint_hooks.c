/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - syscall tracepoint registration and dispatch glue.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>
#include <asm/unistd.h>

#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_syscall_redirect.h"
#include "kasumi_tracepoint_hooks.h"
#include "kasumi_uname.h"

static int tp_path_registered;
static int tp_getfd_registered;
static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;

/* Fast path: skip ~99% of syscalls we never handle */
static inline bool kasumi_syscall_id_relevant(long id)
{
	return id == __NR_openat || id == __NR_faccessat ||
#ifdef __NR_newfstatat
	       id == __NR_newfstatat ||
#endif
	       id == __NR_execve ||
#ifdef __NR_execveat
	       id == __NR_execveat ||
#endif
#ifdef __NR_openat2
	       id == __NR_openat2 ||
#endif
#ifdef __NR_statx
	       id == __NR_statx ||
#endif
	       id == __NR_reboot || id == __NR_prctl || id == __NR_read ||
	       id == (long)kasumi_syscall_nr_param;
}

static void kasumi_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
	(void)data;
	if (!regs || !current || current->pid == 0)
		return;
	/*
	 * uname scoped apply: first relevant syscall from a hidden-uid task
	 * triggers a one-shot CLONE_NEWUTS unshare. After that, the task's
	 * private uts_ns carries the fake values — no further hook needed.
	 * apply_scoped_current short-circuits when not active or already
	 * applied, so this is near-zero cost on the fast path.
	 */
	if (kasumi_uname_scoped_active() && kasumi_should_apply_hide_rules())
		kasumi_uname_apply_scoped_current();

	if (!kasumi_syscall_id_relevant(id))
		return;

	/* Redirect hooked syscalls to dispatcher — runs in process context */
	if (kasumi_syscall_dispatcher_nr >= 0 && kasumi_has_syscall_hook(id)) {
		PT_REGS_ORIG_SYSCALL(regs) = id;
		regs->syscallno = kasumi_syscall_dispatcher_nr;
		return;
	}

	kasumi_handle_sys_enter_getfd(regs, id);
	kasumi_handle_sys_enter_path(regs, id);
	kasumi_handle_sys_enter_statx(regs, id);
	kasumi_handle_sys_enter_cmdline(regs, id);
}

static void kasumi_sys_exit_handler(void *data, struct pt_regs *regs, long ret)
{
	(void)data;
	/* Defensive: verify we have valid context */
	if (!regs)
		return;
	if (!current || current->pid == 0)
		return;
	kasumi_handle_sys_exit_path(regs, ret);
	kasumi_handle_sys_exit_statx(regs, ret);
	kasumi_handle_sys_exit_getfd(regs, ret);
	kasumi_handle_sys_exit_cmdline(regs, ret);
}

int kasumi_tracepoint_path_init(void)
{
	int ret;
	unsigned long addr;

	addr = kasumi_lookup_name("__tracepoint_sys_enter");
	if (!addr || IS_ERR_VALUE(addr)) {
		pr_warn("Kasumi: __tracepoint_sys_enter not found, falling back to getname_flags kprobe\n");
		return 0;
	}
	tp_sys_enter = (struct tracepoint *)addr;

	ret = tracepoint_probe_register(tp_sys_enter, kasumi_sys_enter_handler, NULL);
	if (ret) {
		pr_warn("Kasumi: tracepoint_probe_register(sys_enter) failed: %d\n", ret);
		tp_sys_enter = NULL;
		return 0;
	}
	tp_path_registered = 1;

	addr = kasumi_lookup_name("__tracepoint_sys_exit");
	if (addr && !IS_ERR_VALUE(addr)) {
		tp_sys_exit = (struct tracepoint *)addr;
		ret = tracepoint_probe_register(tp_sys_exit, kasumi_sys_exit_handler, NULL);
		if (ret == 0)
			tp_getfd_registered = 1;
		else
			tp_sys_exit = NULL;
	}

	pr_info("Kasumi: sys_enter tracepoint (path+GET_FD)%s\n",
		tp_getfd_registered ? ", sys_exit (GET_FD)" : "");
	return 1;
}

void kasumi_tracepoint_path_exit(void)
{
	if (tp_getfd_registered && tp_sys_exit) {
		tracepoint_probe_unregister(tp_sys_exit, kasumi_sys_exit_handler, NULL);
		tp_getfd_registered = 0;
		tp_sys_exit = NULL;
	}
	if (tp_path_registered && tp_sys_enter) {
		tracepoint_probe_unregister(tp_sys_enter, kasumi_sys_enter_handler, NULL);
		tracepoint_synchronize_unregister();
		tp_path_registered = 0;
		tp_sys_enter = NULL;
	}
}

int kasumi_tracepoint_path_registered(void)
{
	return tp_path_registered;
}

int kasumi_tracepoint_getfd_registered(void)
{
	return tp_getfd_registered;
}
