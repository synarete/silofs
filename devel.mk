#
# Developer's convenience wrapper over autotools build system via GNU make,
# with extra pedantic compiler flags. Forces pedantic compilation flags.
#
# See also:
#   https://best.openssf.org/ \
#     Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++
#
# Usage examples:
#
#  $ make -f devel.mk D=1 O=2 CC=clang
#
#  $ make -f devel.mk V=1 clean
#
# If you want to build in separate 'build' directory, try:
#
#  $ make -C <build-dir> VPATH=$(pwd) -f $(pwd)/devel.mk <make-rule>
#

# User options:
# D=0|1|2          DEBUG-LEVEL
# O=0|1|2|3        OPTIMIZE-LEVEL
# V=0|1            VERBOSE-MODE
# CC=gcc|clang     COMPLIER
# ANALYZER=0|1     ANALYZER-MODE
# SANITIZER=0|1    SANITIZER-MODE
# PREFIX =
D ?= 1
O ?= 0
V ?= 0
ANALYZER ?= 0
SANITIZER ?= 0


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
DBGS := 0 1 2
VRBS := 0 1
ANLZ := 0 1
SNTZ := 0 1

# Guard against environment variables
CFLAGS =
CFLAGS2 =
CXXFLAGS =
LDFLAGS =
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

ifneq ($(SANITIZER), $(SNTZ))
SANITIZER := 0
endif


# Configure options
CONFIGURE_OPTS += --prefix=$(PREFIX)
CONFIGURE_OPTS += --disable-shared
CONFIGURE_OPTS += --enable-unitests=2
CONFIGURE_OPTS += --enable-compile-warnings=error
ifeq ($(D), 2)
CONFIGURE_OPTS += --enable-debug=profile
else ifeq ($(D), 1)
CONFIGURE_OPTS += --enable-debug=yes
else
CONFIGURE_OPTS += --enable-debug=no
endif

# Make options
ifeq ($(V), 0)
MAKE_OPTS += --silent --no-print-directory
endif


# Developer's (pedantic) compilation flags
CFLAGS += -pedantic
CFLAGS += -Waddress
CFLAGS += -Wall
CFLAGS += -Walloca
CFLAGS += -Warray-bounds
CFLAGS += -Wcast-align
CFLAGS += -Wcast-qual
CFLAGS += -Wcomment
CFLAGS += -Wconversion
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -Wdisabled-optimization
CFLAGS += -Wdouble-promotion
CFLAGS += -Wendif-labels
CFLAGS += -Werror
CFLAGS += -Wextra
CFLAGS += -Wfloat-equal
CFLAGS += -Wformat=2
CFLAGS += -Wimplicit-fallthrough
CFLAGS += -Winit-self
CFLAGS += -Winline
CFLAGS += -Wmain
CFLAGS += -Wmissing-declarations
CFLAGS += -Wmissing-field-initializers
CFLAGS += -Wmissing-format-attribute
CFLAGS += -Wmissing-include-dirs
CFLAGS += -Wmissing-noreturn
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wnested-externs
CFLAGS += -Wnull-dereference
CFLAGS += -Woverlength-strings
CFLAGS += -Wpacked
CFLAGS += -Wparentheses
CFLAGS += -Wpointer-arith
CFLAGS += -Wredundant-decls
CFLAGS += -Wreturn-type
CFLAGS += -Wsequence-point
CFLAGS += -Wshadow
CFLAGS += -Wsign-compare
CFLAGS += -Wsign-conversion
CFLAGS += -Wstrict-aliasing=2
#CFLAGS += -Wsuggest-attribute=const
CFLAGS += -Wswitch
CFLAGS += -Wswitch-default
CFLAGS += -Wswitch-enum
CFLAGS += -Wundef
CFLAGS += -Wunknown-pragmas
CFLAGS += -Wunreachable-code
CFLAGS += -Wunused
CFLAGS += -Wunused-but-set-variable
CFLAGS += -Wunused-label
CFLAGS += -Wunused-local-typedefs
CFLAGS += -Wunused-macros
CFLAGS += -Wunused-parameter
CFLAGS += -Wunused-result
CFLAGS += -Wvla
CFLAGS += -Wwrite-strings
CFLAGS += -fasynchronous-unwind-tables
CFLAGS += -fcf-protection=full
CFLAGS += -fPIC
CFLAGS += -fPIE
CFLAGS += -fsigned-char
CFLAGS += -fstack-clash-protection
CFLAGS += -fstack-protector-all
CFLAGS += -fstack-protector-strong
CFLAGS += -fstrict-aliasing
CFLAGS += -fwrapv

ifeq ($(SANITIZER), 0)
CFLAGS += -Wframe-larger-than=4096
CFLAGS += -Wlarger-than=4096
endif

# C-Dialect compilation flags
CFLAGS2 += -std=gnu17
CFLAGS2 += -Waggregate-return
CFLAGS2 += -Wbad-function-cast
CFLAGS2 += -Wdeclaration-after-statement
CFLAGS2 += -Wfree-nonheap-object
CFLAGS2 += -Winit-self
CFLAGS2 += -Wmissing-prototypes
CFLAGS2 += -Wnested-externs
CFLAGS2 += -Wold-style-definition
CFLAGS2 += -Wpointer-sign
CFLAGS2 += -Wstrict-prototypes
CFLAGS2 += -Wuninitialized

# Debug flags
CFLAGS += -DDEBUG=$(D)
ifneq ($(D), 0)
CFLAGS += -g -ggdb -fno-omit-frame-pointer
endif
ifeq ($(D), 2)
CFLAGS += -pg
endif

# Optimization flags
ifeq ($(O), 0)
CFLAGS += -O0
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
CFLAGS += -pie
CFLAGS += -Walloc-zero
CFLAGS += -Wduplicated-branches
CFLAGS += -Wduplicated-cond
CFLAGS += -Wlogical-op
CFLAGS += -Wl,-z,nodlopen
CFLAGS += -Wl,-z,noexecstack
CFLAGS += -Wl,-z,now
CFLAGS += -Wl,-z,relro
CFLAGS += -Wmaybe-uninitialized
CFLAGS += -Wmultistatement-macros
CFLAGS += -Wpacked-not-aligned
CFLAGS += -Wrestrict
CFLAGS += -Wstack-usage=4096
CFLAGS += -Wstring-compare
CFLAGS += -Wstringop-overflow
CFLAGS += -Wstringop-overread
CFLAGS += -Wstringop-truncation
CFLAGS += -Wswitch-unreachable
CFLAGS += -Wtrampolines
CFLAGS += -Wunused-const-variable=2
CFLAGS2 += -Wjump-misses-init
CFLAGS2 += -Wold-style-declaration
CFLAGS2 += -Wunsuffixed-float-constants
ifeq ($(O), 0)
CFLAGS += -Wunsafe-loop-optimizations
CFLAGS += -fasynchronous-unwind-tables
CFLAGS += -fshort-enums
CFLAGS += -fstack-clash-protection
CFLAGS += -funsafe-loop-optimizations
endif
endif

# Analyzer flags
ifeq ($(ANALYZER), 1)
ifeq ($(CC), gcc)
CFLAGS += -Wno-analyzer-malloc-leak
CFLAGS += -fanalyzer
endif
endif

# Sanitizer flags
# (ASAN_OPTIONS=detect_leaks=1)
ifeq ($(SANITIZER), 1)
ifeq ($(CC), gcc)
CFLAGS += -fsanitize=address
CFLAGS += -fsanitize=leak
CFLAGS += -fsanitize=undefined
#LDFLAGS += -static-libasan
endif
ifeq ($(CC), clang)
CFLAGS += -fsanitize=address
CFLAGS += -fsanitize=leak
endif
endif

# Helper functions: report action & sub-execute make in build directory
define report
	$(info $(strip $(NAME):$(1) $(2)))
endef

define submakeat
	@+$(MAKE) $(MAKE_OPTS) V=$(V) \
	  CFLAGS="$(CFLAGS) $(CFLAGS2)" LDFLAGS="$(LDFLAGS)" -C $(1) $(2)
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
	$(call report, $@, $(CONFIGURE_OPTS))
	@if [ ! -e $(BUILDDIR)/config.status ]; then \
	    cd $(BUILDDIR) && $(TOP)/configure $(CONFIGURE_OPTS); \
	fi

bootstrap:
	$(call report, $@, $(BUILDDIR))
	@if [ ! -d $(BUILDDIR) ]; then $(MKDIR_P) $(BUILDDIR); fi
	@if [ ! -e $(BUILDDIR)/config.status ]; then $(TOP)/bootstrap; fi


# Special targets
.PHONY: tags clangscan rpm deb reset params

tags:
	$(call report, $@)
	@rm -f $(TOP)/TAGS
	@find $(TOP) -name "*.[ch]" -print | etags -

clangscan:
	$(call report, $@)
	@$(TOP)/scripts/clangscanbuild.sh $(TOP)

rpm: reset
	$(call report, $@)
	@$(TOP)/dist/rpm/packagize-rpm.sh

deb: reset
	$(call report, $@)
	@$(TOP)/dist/deb/packagize-deb.sh

reset:
	$(call report, $@)
	@$(TOP)/bootstrap -c

params:
	$(call report, $@)
	$(info  VERSION=$(VERSION))
	$(info  COMPILER=$(CC))
	$(info  DEBUG=$(D))
	$(info  OPTLEVEL=$(O))
	$(info  ANALYZER=$(ANALYZER))
	$(info  SANITIZER=$(SANITIZER))
	$(info  VERBOSE=$(V))
	$(info  PREFIX=$(PREFIX))
	$(info  CFLAGS=$(CFLAGS) $(CFLAGS2))
	$(info  LDFLAGS=$(LDFLAGS))


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
	$(info   SANITIZER=[$(SNTZ)])
	$(info   PREFIX=[DIRPATH])
	$(info )

# By default, build all
.PHONY: build
build: all

.DEFAULT_GOAL := build
