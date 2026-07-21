# SPDX-License-Identifier: MIT
# Copyright (c) 2026 liaoyq / ASRT Contributors

ARCH ?= x86_64
ifeq ($(ARCH), aarch64)
CROSS_ROOT=/opt/arm-gnu-toolchain-13.2
CROSS_COMPILE=aarch64-none-linux-gnu-
else
CROSS_COMPILE=
CROSS_ROOT=
endif

CC=$(CROSS_COMPILE)gcc
CXX=$(CROSS_COMPILE)g++
AR=$(CROSS_COMPILE)ar -rcs
AS=$(CROSS_COMPILE)as
LD=$(CROSS_COMPILE)ld
NM=$(CROSS_COMPILE)nm
STRIP=$(CROSS_COMPILE)strip
MKDIR_P ?= mkdir -p
BUILD_DIR = build


# 目标
TARGET := pgfile

# 依赖库
LIBS := MinoCrypt AsyncRuntime pthread

CFLAGS := ${CFLAG} -fstack-protector -Wall -Wno-deprecated -fno-strict-aliasing -Wunused-but-set-variable -D__LINUX__
CXXFLAGS := -Wreorder -std=c++11 -fno-exceptions -fno-rtti
INCLUDES := -I./src -I../Product/include
LINKFLAGS := -fPIC  -static-libgcc -static-libstdc++ -L../Product/$(ARCH)

RM-F := rm -f

ifeq ($(V),1)
NQ=true
else
NQ=echo
endif

override CFLAGS += $(INCLUDES)
override CXXFLAGS += $(CFLAGS)

# 源文件

SRC := $(wildcard src/*.cpp)

OBJS := $(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.cpp=.o)))

DEPS := $(OBJS:.o=.d)

.PHONY : everything deps objs clean veryclean rebuild

everything : $(TARGET)

deps : $(DEPS)

objs : $(OBJS)

$(BUILD_DIR)/%.o: src/%.cpp Makefile | $(BUILD_DIR)
	@$(NQ) "Compiling: " $(basename $(notdir $@)).cpp
	$(Q)$(CC) -c $(CXXFLAGS) $< -o $@

$(BUILD_DIR):
	$(MKDIR_P) $@

clean :
	@$(NQ) "Cleaning..."
	@find . -iname '*.o' -o -iname '*.bak' -o -iname '*.d' -o -iname '*.lst' | xargs rm -f
	@$(RM-F) $(TARGET)
	rm -rf $(BUILD_DIR)

veryclean: clean
	@$(RM-F) $(TARGET)

rebuild: veryclean everything

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM-F) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

# pgfile
$(TARGET) : $(OBJS) Makefile | $(BUILD_DIR)
	@$(NQ) "Linking..." $(TARGET)
	$(CXX) $(CXXFLAGS) $(OBJS) -L$(LIB_DIR) $(LINKFLAGS) $(addprefix -l,$(LIBS)) -o $@
ifeq ($(debug),false)
	$(STRIP) $(TARGET)
endif
	mv $(TARGET) ../Product/$(ARCH)/
