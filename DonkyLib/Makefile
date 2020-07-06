# PLATFORM is one of (riscv, x86_64)
PLATFORM ?= riscv
# SIM is one of ("", pk)
SIM?=
SHARED?=
CCFLAGS?=
LDFLAGS?=
LDLIBS?=
INSTALLDIR?=/usr/lib

LDLIBS+=-lpthread

CCFLAGS+=-DTLS_MISALIGNMENT_BUG
ifeq ($(RELEASE),1)
CCFLAGS+=-DRELEASE
endif

ifeq ($(TIMING),1)
CCFLAGS+=-DTIMING
LDLIBS+=-lm
endif

ifeq ($(CONSTRUCTOR),1)
CCFLAGS+=-DCONSTRUCTOR
endif

ifeq ($(PRELOAD),1)
CCFLAGS+=-DCONSTRUCTOR
CCFLAGS+=-DDL_HOOKING
CCFLAGS+=-DDLU_HOOKING
LDLIBS+=-ldl
export DO_LD_PRELOAD=$(CURDIR)/libpku.so
#export DO_LD_PRELOAD=$(CURDIR)/libpk.so
endif

CCFLAGS+=$(CF)

ifeq ($(SHARED),1)
CCFLAGS+=-fPIC
CCFLAGS+=-fvisibility=hidden
CCFLAGS+=-DSHARED
LD_LIBRARY_PATH=$(CURDIR)
export LD_LIBRARY_PATH
endif

ifeq ($(FAKEMPK),1)
CCFLAGS+=-DFAKE_MPK_REGISTER
CCFLAGS+=-DFAKE_PKEY_SYSCALLS 
CCFLAGS+=-DFAKE_MPK_EXCEPTION 
endif # FAKEMPK

########################################################################
# RISC-V
########################################################################
ifeq ($(PLATFORM),riscv)

ifndef RISCV
$(error RISCV is not set)
endif

ifndef SDKBASE
$(error SDKBASE is not set)
endif

#SDKBASE?=$(realpath ../../ariane-sdk)/

PREFIX=$(RISCV)/bin/riscv64-unknown-linux-gnu-
ARCH=arch/riscv

# compiler selection for platform
AR=$(PREFIX)gcc-ar
CC=$(PREFIX)gcc
LD=$(PREFIX)ld
OD=$(PREFIX)objdump
OC=$(PREFIX)objcopy
GDB=$(PREFIX)gdb

LDFLAGS+=-L$(RISCV)/riscv64-unknown-linux-gnu/lib64/lp64d \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib64 \
         -L$(RISCV)/riscv64-unknown-linux-gnu/lib
RUN=$(RISCV)/bin/spike
#RUNARGS=--isa=rv64imacn
RUNARGS=
DEBUGGER=$(RISCV)/bin/spike
#DEBUGARGS=--isa=rv64imacn -d
DEBUGARGS=-d

#CCFLAGS+=-mabi=lp64 -march=rv64imac
#CCFLAGS+=-mabi=lp64d -march=rv64imafdc

CCFLAGS+=-DFAKE_TLS_SWAP -DSYSCALL_SANDBOXING
ifeq ($(SIM),pk)

CCFLAGS+=-DPROXYKERNEL #-DFAKE_PKEY_SYSCALLS
RUN_DEPS=
RUN_BIN=$(SDKBASE)riscv-pk/build/pk $(MAIN)
DEBUG_BIN=$(RUN_BIN)
#LDFLAGS+=-static

else  # SIM=pk

CCFLAGS+=
RUN_DEPS=linux
RUN_BIN=$(SDKBASE)bbl

endif # SIM=pk

#fvisibility=hidden might help aviding GOT stuff
CCFLAGS+=-fvisibility=hidden

#LDFLAGS+=-flto
#CCFLAGS+=-flto

endif # PLATFORM=riscv

########################################################################
# x86_64
########################################################################
ifeq ($(PLATFORM),x86_64)
PREFIX=

# compiler selection for platform
AR=$(PREFIX)gcc-ar
CC=$(PREFIX)clang
LD=$(PREFIX)ld
OD=$(PREFIX)objdump
OC=$(PREFIX)objcopy
GDB=$(PREFIX)gdb

ARCH=arch/x86_64
#CCFLAGS+=-Werror

ifeq ($(SIM),pk)

CCFLAGS+=-DFAKE_MPK_REGISTER
CCFLAGS+=-DFAKE_PKEY_SYSCALLS 
CCFLAGS+=-DFAKE_MPK_EXCEPTION 
CCFLAGS+=-DFAKE_TLS_SWAP

else # SIM

# Since we cannot build x86 hardware
CCFLAGS+=-DFAKE_MPK_EXCEPTION 
CCFLAGS+=-DFAKE_TLS_SWAP

endif # SIM
LDFLAGS+=
RUN_DEPS=
RUN=
RUNARGS=
RUN_BIN=
ifeq ($(PRELOAD),1)
RUN_BIN+=LD_PRELOAD=$(CURDIR)/libpku.so
#RUN_BIN+=LD_PRELOAD=$(CURDIR)/libpk.so
endif
RUN_BIN+=LD_LIBRARY_PATH=$(CURDIR) setarch x86_64 --addr-no-randomize ./$(MAIN)
DEBUGGER=./gdbscreen.sh gdb
DEBUGARGS=
DEBUG_BIN=./$(MAIN)
endif # PLATFORM=x86_64
########################################################################
ifndef ARCH
$(error Unknown platform $(PLATFORM))
endif
########################################################################
AWK=awk
LDSCRIPT=$(ARCH)/linker

# FLAGS FOR CC AND LD
CCFLAGS+=-I. -Ipk -Ipk/$(ARCH) -Iuser -Iuser/$(ARCH) -I../syscall_hook
CFLAGS+=-std=gnu11
CXXFLAGS+=-std=c++11
CCFLAGS+=-fPIC
CCFLAGS+=-Wall
CCFLAGS+=-Werror=implicit-function-declaration
CCFLAGS+=-Werror=pointer-arith
CCFLAGS+=-Werror=format
CCFLAGS+=-Wpointer-arith
CCFLAGS+=-Werror=int-conversion
CCFLAGS+=-pthread
#CCFLAGS+=-flto
CCFLAGS+=-g
#CCFLAGS+=-O3
#CCFLAGS+=-O
CCFLAGS+=-Os


CCFLAGS+=-DADDITIONAL_DEBUG_CHECKS
CCFLAGS+=-DDEBUG__CSR
#CCFLAGS+=-DRELEASE
#CCFLAGS+=-DTIMING

#LDFLAGS:=$(CCFLAGS) $(LDFLAGS)
#
#CCFLAGS+=-Wextra
#CCFLAGS+=-pedantic 
#LDFLAGS+=-no-pie
#LDFLAGS+=-pie
#LDFLAGS+=-Wl,-z,relro
ifneq ($(SHARED),1)
LDFLAGS+=-static # or alternatively sudo ln -s ${RISCV}/sysroot/lib/ld-linux-riscv64-lp64d.so.1 /lib
endif
#LDFLAGS+=-flto

PK_OBJ=pk/pk_handler_generic.o pk/$(ARCH)/pk_handler_c.o pk/$(ARCH)/pk_handler.o
PKU_OBJ=pk/pku_handler_generic.o pk/$(ARCH)/pku_handler_c.o pk/$(ARCH)/pku_handler.o pk/mprotect.o

ifeq ($(SHARED),1)
PKSO=libpk.so
PKUSO=libpku.so
MAIN=x.elf-shared
else # SHARED
PK=pk.a
PKU=pku.a
MAIN=x.elf
endif # SHARED
########################################################################
all: $(MAIN)

USR_OBJ=main.o \
	user/$(ARCH)/tests.o \
	user/test_ecalls.o \
	user/test0.o \
	user/test1_api.o \
	user/$(ARCH)/test2.o user/$(ARCH)/test2_ecall.o \
	user/test3.o \
	user/test4_pthread.o \
	user/test5.o \
	user/test6.o \
	user/bench.o
USR=usr.a

.PHONY: all clean clean-all run debug linux run_quiet run_deps bench-pk bench-x86

$(LDSCRIPT).ld:
	mkdir -p $(dir $(LDSCRIPT).%)
	$(LD) --verbose > $@.tmp
	@./patch_ld.sh $@.tmp
	@mv $@.tmp $@

$(LDSCRIPT).lds:
	mkdir -p $(dir $(LDSCRIPT).%)
	$(LD) -shared --verbose > $@.tmp
	@./patch_ld.sh $@.tmp
	@mv $@.tmp $@

%.o: %.c
	$(CC) $(CFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.cc
	$(CC) $(CXXFLAGS) $(CCFLAGS) -c $^ -o $@

%.o: %.S
	$(CC) $(CCFLAGS) -c $^ -o $@

$(PK): $(PK_OBJ)
	$(AR) -crs $@ $^

$(PKU): $(PKU_OBJ)
	$(AR) -crs $@ $^

$(PKSO): $(PK_OBJ)
	$(CC) -shared -o $@ $(CCFLAGS) $^ $(LDLIBS)

$(PKUSO): $(PKU_OBJ) | $(PKSO)
	$(CC) -shared -o $@ $(CCFLAGS) $^ $(LDLIBS) -L. -lpk

$(USR): $(USR_OBJ)
	$(AR) -crs $@ $^
	# clang 7.0.0 workaround --remove-section .llvm_addrsig because of:
	# https://sourceware.org/bugzilla/show_bug.cgi?id=23788
	$(OC) --remove-section .llvm_addrsig --redefine-syms=rename_pk.lst $@

# We mis-use order-only prerequisites to use separate linker script ($|)
# from the object files ($^)
# We enclose all object files into --start-group/--end-group to avoid
# problems with the link order

ifeq ($(SHARED),1)

$(MAIN): $(USR) | $(PKSO) $(PKUSO)
	$(CC) -o $@ $(LDFLAGS) -Wl,--start-group $^ $(PKSO) $(PKUSO) -Wl,--end-group $(LDLIBS)

else

$(MAIN): $(USR) $(PK) $(PKU) | $(LDSCRIPT).ld
	$(CC) -o $@ $(LDFLAGS) -Wl,-T $| -Wl,--start-group $^ -Wl,--end-group $(LDLIBS)

endif

debug: $(MAIN)
	$(OD) -t $(MAIN) | grep '[ _]pk_\|ecall\|_debug' | awk '{print "until pc 0 "$$1" # "$$(NF)}' | sort -k6
	$(DEBUGGER) $(DEBUGARGS) $(DEBUG_BIN)

linux: $(MAIN)
	cp $^ $(SDKBASE)rootfs/$^
	#riscv64-unknown-linux-gnu-strip -R .comment --strip-unneeded --strip-all $(SDKBASE)rootfs/$^
	make -C $(SDKBASE) bbl bbl.bin

run_deps:  $(RUN_DEPS)

run: $(MAIN) $(RUN_DEPS)
	$(RUN) $(RUNARGS) $(RUN_BIN)

run_quiet: $(MAIN) $(RUN_DEPS)
	$(RUN) $(RUNARGS) $(RUN_BIN) 2>/dev/null

ifeq ($(SHARED),1)

install: $(PKSO) $(PKUSO)
	@echo "Installing '$^' into '$(INSTALLDIR)'"
	sudo cp -t '$(INSTALLDIR)' $^

else

install: $(PK) $(PKU)
	@echo "Installing '$^' into '$(INSTALLDIR)'"
	sudo cp -t '$(INSTALLDIR)' $^

endif

clean:
	rm -f --preserve-root $(PK_OBJ) $(PKU_OBJ) $(USR_OBJ) $(PK) $(PKSO) $(PKU) $(PKUSO) $(USR) $(LDSCRIPT).ld pk_stats.csv results.csv $(MAIN)

clean-all: clean
	rm -f --preserve-root $(SDKBASE)rootfs/$(MAIN) $(MAIN) core
