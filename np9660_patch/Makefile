TARGET = npdrm_free
OBJS =  src/main.o src/exports.o src/lib.o src/pgd.o src/setk1.o src/imports.o

LIBDIR = libs
LIBS = -lpspsystemctrl_kernel -lpspkubridge

CFLAGS = -Wall -Wextra -O2 -G0
ASFLAGS = $(CFLAGS)

USE_KERNEL_LIBC = 1
USE_KERNEL_LIBS = 1

ifeq ($(CONFIG_620), 1)
CFLAGS += -DCONFIG_620=1
PSP_FW_VERSION=620
endif

ifeq ($(CONFIG_660), 1)
CFLAGS += -DCONFIG_660=1
PSP_FW_VERSION=660
endif

ifeq ($(CONFIG_661), 1)
CFLAGS += -DCONFIG_661=1
PSP_FW_VERSION=661
endif

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build_prx.mak
