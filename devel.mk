#!/usr/bin/make -f
#
# Developer's convenience wrapper over autotools build system via GNU make,
# with extra pedantic compiler flags. Forces pedantic compilation flags.
#
# Usage examples:
#
#  $ ./devel.mk D=1 O=2 CC=clang
#
#  $ ./devel.mk V=1 clean
#
# If you want to build in separate 'build' directory, try:
#
#  $ make -C <build-dir> VPATH=$(pwd) -f $(pwd)/devel.mk <make-rule>
#

# User options:
# D = DEBUG (0|1)
# O = OPTLEVEL (0|1|2|3)
# V = VERBOSE (0|1)
# CC = COMPLIER (gcc|clang)
# ANALYZER = ANALYZER-MODE (0|1)
# PREFIX =
D ?= 1
O ?= 0
V ?= 0
ANALYZER ?= 0

MKDIR_P := mkdir -p
SELF := $(lastword $(MAKEFILE_LIST))
NAME := $(notdir $(SELF))
TOP := $(realpath $(dir $(SELF)))
BUILDDIR := $(TOP)/build
PREFIX ?= $(BUILDDIR)/local
VERSION := $(shell $(TOP)/version.sh)

CCS  := gcc clang
CXXS := g++ clang++
OPTS := 0 1 2 3
DBGS := 0 1
VRBS := 0 1
ANLZ := 0 1

# Guard against environment variables
CFLAGS =
MAKE_OPTS =
CONFIGURE_OPTS =

# Vars setup
ifneq ($(CC), $(CCS))
CC := gcc
CXX := g++
endif

ifeq ($(CC), clang)
CXX := clang++
endif

ifneq ($(O), $(OPTS))
O := 0
endif

ifneq ($(D), $(DBGS))
D := 1
endif

ifneq ($(V), $(VRBS))
V := 0
endif

ifneq ($(ANALYZER), $(ANLZ))
ANALYZER := 0
endif


# Configure options
CONFIGURE_OPTS += --prefix=$(PREFIX)
CONFIGURE_OPTS += --disable-shared
CONFIGURE_OPTS += --enable-unitests=yes
ifeq ($(D), 1)
CONFIGURE_OPTS += --enable-debug=yes
else
CONFIGURE_OPTS += --enable-debug=no
endif

# Make options
ifeq ($(V), 0)
MAKE_OPTS += --silent --no-print-directory
endif


# Developer's (pedantic) compilation flags
CFLAGS += -Wall -Wextra -Winit-self -Winline
CFLAGS += -Wunused -Wunused-parameter -Wunused-result
CFLAGS += -Wunused-local-typedefs -Wunused-label
CFLAGS += -Wshadow -Wfloat-equal -Wwrite-strings -Wpointer-arith
CFLAGS += -Wcast-align -Wsign-compare -Wredundant-decls -Wformat=2
CFLAGS += -Wmissing-include-dirs -Wmissing-declarations -Wswitch -Wswitch-enum
CFLAGS += -Wswitch-default -Wcomment -Wparentheses -Wsequence-point
CFLAGS += -Wpointer-arith -Wdisabled-optimization -Wmain -Wundef
CFLAGS += -Wunknown-pragmas -Wunused-macros -Wendif-labels
CFLAGS += -Wvla -Waddress -Woverlength-strings -Wconversion -Wsign-conversion
CFLAGS += -Wunreachable-code -Wwrite-strings -Wlarger-than=4096
CFLAGS += -Wframe-larger-than=4096 -Wmissing-field-initializers
CFLAGS += -Wstrict-aliasing=2 -Warray-bounds -Winline -Wcast-qual
CFLAGS += -fPIC -fwrapv -fstrict-aliasing
CFLAGS += -fstack-protector -fstack-protector-strong # -fstack-check
CFLAGS += -fasynchronous-unwind-tables
# CFLAGS += -Wpadded

# Have 'pedantic' flag only when not using private fuse header
ifneq (,$(wildcard "$(TOP)/include/linux/fuse.h"))
CFLAGS += -pedantic
endif


# C-Dialect compilation flags
CFLAGS += -Wbad-function-cast -Wmissing-prototypes -Waggregate-return
CFLAGS += -Wdeclaration-after-statement -Wnested-externs -Wstrict-prototypes
CFLAGS += -Wold-style-definition -Winit-self -std=gnu11
CFLAGS += -Wfree-nonheap-object -Wuninitialized

# Debug flags
CFLAGS += -DDEBUG=$(D)
ifeq ($(D), 1)
CFLAGS += -g -ggdb -fno-omit-frame-pointer
endif

# Optimization flags
ifeq ($(O), 0)
CFLAGS += -O0
ifeq ($(CC), gcc)
CFLAGS += -Wunsafe-loop-optimizations -funsafe-loop-optimizations
CFLAGS += -fasynchronous-unwind-tables -fstack-clash-protection
endif
else ifeq ($(O), 1)
CFLAGS += -O1 -D_FORTIFY_SOURCE=2
else ifeq ($(O), 2)
CFLAGS += -O2 -D_FORTIFY_SOURCE=2
else ifeq ($(O), 3)
CFLAGS += -O3 -D_FORTIFY_SOURCE=2
else
$(error Illegal O=$(O))
endif

# Compiler specific flags
ifeq ($(CC), gcc)
CFLAGS += -Werror -Wstack-usage=4096 -Wlogical-op -Wjump-misses-init
CFLAGS += -Wunsuffixed-float-constants -Wmultistatement-macros
CFLAGS += -Wunused-const-variable=2 -Wswitch-unreachable
CFLAGS += -Wold-style-declaration -Wmaybe-uninitialized
# CFLAGS += -Wstringop-truncation -Wstringop-overread -Wstringop-overflow
# CFLAGS += -Wstring-compare
ifeq ($(ANALYZER), 1)
CFLAGS += -fanalyzer -Wno-analyzer-malloc-leak
endif
else ifeq ($(CC), clang)
endif


# Helper functions: report action & sub-execute make in build directory
define report
	$(info $(NAME):$(1))
endef

define submakeat
	@+$(MAKE) $(MAKE_OPTS) V=$(V) CFLAGS="$(CFLAGS)" -C $(1) $(2)
endef

define submake
	$(call report, $@)
	$(call submakeat, $(BUILDDIR), $@)
endef


# Delegated targtes
.PHONY: all install clean maintainer-clean dist check

all: params configure
	$(call submake, $@)

check: params configure
	$(call submake, $@)

install: params configure
	$(call submake, $@)

clean: params
	$(call submake, $@)

maintainer-clean: params
	$(call submake, $@)

dist: check
	$(call submake, $@)


# Pre-make targets:
.PHONY: configure bootstrap

configure: bootstrap
	$(call report, $@)
	@if [ ! -e $(BUILDDIR)/config.status ]; then \
            cd $(BUILDDIR) && $(TOP)/configure $(CONFIGURE_OPTS); fi

bootstrap:
	$(call report, $@)
	@if [ ! -d $(BUILDDIR) ]; then $(MKDIR_P) $(BUILDDIR); fi
	@if [ ! -e $(BUILDDIR)/config.status ]; then $(TOP)/bootstrap; fi


# Special targets
.PHONY: clangscan rpm reset params

clangscan:
	$(call report, $@)
	@$(TOP)/misc/clangscanbuild.sh $(TOP)

rpm: reset
	$(call report, $@)
	@$(TOP)/dist/packagize-rpm.sh

deb: reset
	$(call report, $@)
	@$(TOP)/dist/packagize-deb.sh

reset:
	$(call report, $@)
	@$(TOP)/bootstrap -c

params:
	$(call report, $@)
	$(info  VERSION=$(VERSION))
	$(info  COMPILER=$(CC))
	$(info  DEBUG=$(D))
	$(info  OPTLEVEL=$(O))
	$(info  VERBOSE=$(V))
	$(info  PREFIX=$(PREFIX))


# Help the naive user
.PHONY: help

help:
	$(info Usage: $(SELF) [option=val] [<target>])
	$(info )
	$(info Targets:)
	$(info   all)
	$(info   check)
	$(info   clean)
	$(info   dist)
	$(info   configure)
	$(info   reset)
	$(info   version)
	$(info )
	$(info Options:)
	$(info   CC=[$(CCS)])
	$(info   D=[$(DBGS)])
	$(info   O=[$(OPTS)])
	$(info   V=[$(VRBS)])
	$(info   ANALYZER=[$(ANLZ)])
	$(info   PREFIX=[DIRPATH])
	$(info )

# By default, build all
.PHONY: build
build: all

.DEFAULT_GOAL := build
