#!/usr/bin/make -f
# Fallback Makefile for CEP (no-internet builds)

# Directories
SRCDIR := ../src
# Use a separate build dir so accidental `make` does not clobber Meson builds
BUILD_DIR := ../build-make
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# Target
TARGET := $(BIN_DIR)/cep_tests

# Tools and flags
CC ?= gcc
CFLAGS ?= -g -Wall -D_GNU_SOURCE -fplan9-extensions \
          -I$(SRCDIR)/l0_kernel -I$(SRCDIR)/test
LDFLAGS :=

# Sources and objects (only cep_cell.* and tests)
SRC := $(SRCDIR)/l0_kernel/cep_cell.c \
       $(wildcard $(SRCDIR)/test/*.c)
OBJ := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))

.PHONY: all run debug clean help

all: $(TARGET)

help:
	@echo "CEP fallback Makefile (no internet / no Meson)."
	@echo "Build dir: $(BUILD_DIR)"
	@echo "Targets: all, run, debug, clean"

# Link
$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) -Wall -o "$@" $(OBJ) $(LDFLAGS)

# Compile: place objects under build/obj mirroring source tree
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c "$<" -o "$@"

# Convenience targets
run: $(TARGET)
	"$(TARGET)" --log-visible debug

debug: $(TARGET)
	gdb -w --args "$(TARGET)" --log-visible debug

clean:
	rm -rf "$(BUILD_DIR)"
