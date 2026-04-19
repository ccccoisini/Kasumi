# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android14-6.1  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

obj-m += hymofs_lkm.o
hymofs_lkm-objs := hymofs_core.o hymofs_tracepoint.o hymofs_ftrace.o hymofs_uname.o hymofs_iop_override.o

ccflags-y += -gz=none
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
