/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - proc-facing hook lifecycle and mount-proxy interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_PROC_HOOKS_H
#define _HYMOFS_PROC_HOOKS_H

#include <linux/types.h>

int hymofs_proc_hooks_init(bool skip_getfd, bool no_tracepoint, bool skip_extra_kprobes);
void hymofs_proc_hooks_exit(void);
void hymofs_proc_read_hooks_init(void);
void hymofs_proc_read_hooks_exit(void);
int hymo_mount_proxy_install_fd(int fd);
bool hymo_path_is_proc_mount_view(const char *path);
bool hymo_path_is_proc_mountinfo(const char *path);

#endif /* _HYMOFS_PROC_HOOKS_H */
