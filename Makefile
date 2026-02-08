NASM      := nasm
NASMFLAGS := -f elf64 -g -F dwarf -Iinclude/

CC        := gcc
CFLAGS    := -c -O2 -m64 -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nostartfiles

LD        := ld
LDFLAGS   :=

AR        := ar
ARFLAGS   := rcs

SRC_DIR   := src
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/main
LIB       := $(BUILD_DIR)/libmylib.a

OBJS := \
  $(BUILD_DIR)/main.o \
  $(BUILD_DIR)/AES256.o \
  $(BUILD_DIR)/CRC.o \
  $(BUILD_DIR)/SHA384.o \
  $(BUILD_DIR)/transmit.o \
  $(BUILD_DIR)/receive.o

LIBOBJS := \
  $(BUILD_DIR)/detect_entries.o \
  $(BUILD_DIR)/essentials.o

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB): $(LIBOBJS) | $(BUILD_DIR)
	$(AR) $(ARFLAGS) $@ $^

$(TARGET): $(OBJS) $(LIB) | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIB)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/AES256.o: $(SRC_DIR)/AES256.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/CRC.o: $(SRC_DIR)/CRC.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/transmit.o: $(SRC_DIR)/transmit.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/receive.o: $(SRC_DIR)/receive.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/detect_entries.o: $(SRC_DIR)/detect_entries.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/essentials.o: include/essentials.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/SHA384.o: $(SRC_DIR)/SHA384.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

