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
# SANITIZER=0|1|2  SANITIZER-MODE
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
SNTZ := 0 1 2

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
CFLAGS += -pedantic -Werror -Wall -Wextra -Winit-self -Winline
CFLAGS += -Wunused -Wunused-parameter -Wunused-result
CFLAGS += -Wunused-local-typedefs -Wunused-label
CFLAGS += -Wshadow -Wfloat-equal -Wwrite-strings -Wpointer-arith
CFLAGS += -Wcast-align -Wsign-compare -Wredundant-decls -Wformat
CFLAGS += -Wmissing-include-dirs -Wmissing-declarations -Wswitch -Wswitch-enum
CFLAGS += -Wswitch-default -Wcomment -Wparentheses -Wsequence-point
CFLAGS += -Wpointer-arith -Wdisabled-optimization -Wmain -Wundef
CFLAGS += -Wunknown-pragmas -Wunused-macros -Wendif-labels
CFLAGS += -Wvla -Waddress -Woverlength-strings -Wconversion -Wsign-conversion
CFLAGS += -Wunreachable-code -Wwrite-strings -Wlarger-than=4096
CFLAGS += -Wframe-larger-than=4096 -Wmissing-field-initializers
CFLAGS += -Wstrict-aliasing=2 -Warray-bounds -Winline -Wcast-qual
CFLAGS += -Wmissing-noreturn -Wimplicit-fallthrough
CFLAGS += -fwrapv -fstrict-aliasing -fsigned-char
CFLAGS += -fstack-protector-all -fstack-protector-strong
CFLAGS += -fstack-clash-protection
CFLAGS += -fasynchronous-unwind-tables -fcf-protection=full
CFLAGS += -fPIE -fPIC
# CFLAGS += -Wsuggest-attribute=const -Wpadded

# C-Dialect compilation flags
CFLAGS2 += -Wbad-function-cast -Wmissing-prototypes -Waggregate-return
CFLAGS2 += -Wdeclaration-after-statement -Wnested-externs -Wstrict-prototypes
CFLAGS2 += -Wold-style-definition -Wpointer-sign -Winit-self -std=gnu11
CFLAGS2 += -Wfree-nonheap-object -Wuninitialized

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
CFLAGS += -Wstack-usage=4096 -Wlogical-op
CFLAGS += -Wmultistatement-macros -Wunused-const-variable=2
CFLAGS += -Wswitch-unreachable -Wmaybe-uninitialized -Wtrampolines
CFLAGS += -Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now
CFLAGS += -pie
# CFLAGS += -Wstringop-truncation -Wstringop-overread -Wstringop-overflow
# CFLAGS += -Wstring-compare
CFLAGS2 += -Wjump-misses-init -Wunsuffixed-float-constants
CFLAGS2 += -Wold-style-declaration
ifeq ($(O), 0)
CFLAGS += -Wunsafe-loop-optimizations -funsafe-loop-optimizations
CFLAGS += -fasynchronous-unwind-tables -fstack-clash-protection
CFLAGS += -fshort-enums
endif
endif

# Analyzer flags
ifeq ($(ANALYZER), 1)
ifeq ($(CC), gcc)
CFLAGS += -fanalyzer -Wno-analyzer-malloc-leak
endif
endif

# Sanitizer flags
ifeq ($(SANITIZER), 1)
CFLAGS += -fsanitize=address
CFLAGS += -fsanitize-address-use-after-scope
CFLAGS += -fsanitize=pointer-overflow
CFLAGS += -fsanitize=alignment
CFLAGS += -fsanitize=bounds
CFLAGS += -fsanitize=object-size
CFLAGS += -fsanitize=undefined
CFLAGS += -fsanitize=float-divide-by-zero
CFLAGS += -fsanitize=float-cast-overflow
# CFLAGS += -fsanitize=null
CFLAGS += -fno-sanitize=null
LDFLAGS += -fsanitize=address

LDFLAGS += -fsanitize=undefined
endif
ifeq ($(SANITIZER), 2)
CFLAGS += -fsanitize=bounds
CFLAGS += -fsanitize=object-size
CFLAGS += -fsanitize=undefined
CFLAGS += -fsanitize=null
CFLAGS += -fsanitize=undefined
ifeq ($(CC), clang)
CFLAGS += -fsanitize=memory
CFLAGS += -fsanitize-memory-track-origins=2
LDFLAGS += -fsanitize=memory
endif
endif

# C++ flags
CXXFLAGS += $(CFLAGS)
CXXFLAGS += -Wctor-dtor-privacy -Wnoexcept -Wold-style-cast
CXXFLAGS += -Woverloaded-virtual -Wredundant-decls -Wstrict-null-sentinel
CXXFLAGS += -Winit-self -Wlogical-op -std=c++1z -Wsized-deallocation
CXXFLAGS += -Wsuggest-final-types -Wsuggest-final-methods -Wsuggest-override
CXXFLAGS += -Wuseless-cast -Weffc++ -Wzero-as-null-pointer-constant
CXXFLAGS += -D_GLIBCXX_ASSERTIONS

# Helper functions: report action & sub-execute make in build directory
define report
	$(info $(strip $(NAME):$(1) $(2)))
endef

define submakeat
	@+$(MAKE) $(MAKE_OPTS) V=$(V) \
	  CFLAGS="$(CFLAGS) $(CFLAGS2)" \
	  CXXFLAGS="$(CXXFLAGS)" \
	  LDFLAGS="$(LDFLAGS)" \
	  -C $(1) $(2)
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
            cd $(BUILDDIR) && $(TOP)/configure $(CONFIGURE_OPTS); fi

bootstrap:
	$(call report, $@, $(BUILDDIR))
	@if [ ! -d $(BUILDDIR) ]; then $(MKDIR_P) $(BUILDDIR); fi
	@if [ ! -e $(BUILDDIR)/config.status ]; then $(TOP)/bootstrap; fi


# Special targets
.PHONY: clangscan rpm reset params

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
