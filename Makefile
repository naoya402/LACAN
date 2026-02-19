# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2016 Intel Corporation

# binary name
APP = dpdk_test

# all source are stored in SRCS-y
SRCS-y := dpdk-util/eth_config2.c common_func.c DPDK_func.c mainrev.cpp


# Build using pkg-config variables if possible
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lcrypto -lssl -L/liWb/x86_64-linux-gnu/
# LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk) -lcrypto -lssl -L/lib/x86_64-linux-gnu/
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk) -L/usr/local/lib -lgroupsig -lcrypto -lssl -lm -lz -pthread
# LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -L/usr/local/lib -lgroupsig -lcrypto -lssl -lm -pthread
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lgroupsig -lcrypto -lssl -lm -lz -pthread


build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CXX) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CXX) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true

else # Build using legacy build system

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -I$(SRCDIR)
CFLAGS += -O3 $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

include $(RTE_SDK)/mk/rte.extapp.mk
endif
