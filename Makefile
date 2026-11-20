# MemoryGuard Auto - Makefile for a Momentics "QNX Executable" project.
#
# Momentics runs "make" with PLATFORM / BUILD_PROFILE for the selected
# build configuration; the defaults below are for a Raspberry Pi 4
# (aarch64le) debug build. Every program in src/<name>/ is linked with
# the shared code in src/common/. Output: build/<platform>-<profile>/<name>

PLATFORM      ?= aarch64le
BUILD_PROFILE ?= debug
CONFIG_NAME   ?= $(PLATFORM)-$(BUILD_PROFILE)
OUTPUT_DIR     = build/$(CONFIG_NAME)

CC = qcc -Vgcc_nto$(PLATFORM)
LD = $(CC)

APPS = mg_supervisor mg_watchdog mg_sensor mg_devmgr mg_logger mg_ui mg_statusfs mg_webui mgctl mg_selftest

CCFLAGS_release  += -O2
CCFLAGS_debug    += -g -O0 -fno-builtin
CCFLAGS_profile  += -g -O0 -finstrument-functions
LIBS_profile     += -lprofilingS
CCFLAGS_coverage += -g -O0 -ftest-coverage -fprofile-arcs
LDFLAGS_coverage += -ftest-coverage -fprofile-arcs

CCFLAGS_all += -Wall -Wextra -Wno-unused-parameter -fmessage-length=0 -std=gnu11 -Isrc/common
CCFLAGS_all += $(CCFLAGS_$(BUILD_PROFILE))
LDFLAGS_all += $(LDFLAGS_$(BUILD_PROFILE))
LIBS_all    += -lslog2 -lsocket -lm $(LIBS_$(BUILD_PROFILE))
DEPS = -Wp,-MMD,$(@:%.o=%.d),-MT,$@

COMMON_SRCS = $(wildcard src/common/*.c)
COMMON_OBJS = $(addprefix $(OUTPUT_DIR)/,$(COMMON_SRCS:.c=.o))
ALL_OBJS    = $(COMMON_OBJS)

all: $(addprefix $(OUTPUT_DIR)/,$(APPS))

$(OUTPUT_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(DEPS) -o $@ $(CCFLAGS_all) $(CCFLAGS) $<

define APP_RULE
$(1)_OBJS = $$(addprefix $$(OUTPUT_DIR)/,$$(patsubst %.c,%.o,$$(wildcard src/$(1)/*.c)))
ALL_OBJS += $$($(1)_OBJS)
$$(OUTPUT_DIR)/$(1): $$($(1)_OBJS) $$(COMMON_OBJS)
	$$(LD) -o $$@ $$(LDFLAGS_all) $$(LDFLAGS) $$^ $$(LIBS_all) $$(LIBS)
endef
$(foreach a,$(APPS),$(eval $(call APP_RULE,$(a))))

clean:
	rm -fr build

rebuild: clean all

.PHONY: all clean rebuild

-include $(ALL_OBJS:%.o=%.d)
