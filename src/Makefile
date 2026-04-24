# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android16-6.12  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

obj-m += hymofs_lkm.o
hymofs_lkm-objs := \
	hymofs_main.o \
	core/hymofs_bootstrap.o \
	core/hymofs_runtime.o \
	control/hymofs_ioctl.o \
	policy/hymofs_path_policy.o \
	overlay/hymofs_overlay.o \
	hooks/hymofs_proc_hooks.o \
	hooks/hymofs_proc_read_hooks.o \
	hooks/hymofs_vfs_hooks.o \
	hooks/hymofs_tracepoint_hooks.o \
	hooks/hymofs_ftrace_hooks.o \
	features/hymofs_uname.o \
	features/hymofs_iop_override.o \
	features/hymofs_fake_mountinfo.o

ccflags-y += -gz=none
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)/internal
ccflags-y += -I$(src)/core
ccflags-y += -I$(src)/control
ccflags-y += -I$(src)/policy
ccflags-y += -I$(src)/overlay
ccflags-y += -I$(src)/hooks
ccflags-y += -I$(src)/features
# Do not force CONFIG_DYNAMIC_FTRACE / CONFIG_FUNCTION_TRACER from module flags.
# They must follow target kernel Kconfig, otherwise some arches/toolchains
# (e.g. x86 with missing fentry flags) fail at asm/ftrace.h checks.
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use HYMO_NOCFI only on functions that make indirect calls to resolved symbols.

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
