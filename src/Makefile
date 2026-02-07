NASM      := nasm
NASMFLAGS := -f elf64 -g -F dwarf -I../include/

CC        := gcc
CFLAGS    := -c -O2 -m64 -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nostartfiles

LD        := ld
LDFLAGS   :=

AR        := ar
ARFLAGS   := rcs

BUILD_DIR := build
TARGET    := $(BUILD_DIR)/main
LIB       := $(BUILD_DIR)/libmylib.a

OBJS := \
  $(BUILD_DIR)/main.o \
  $(BUILD_DIR)/AES256.o \
  $(BUILD_DIR)/CRC.o \
  $(BUILD_DIR)/SHA256.o \
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

$(BUILD_DIR)/main.o: main.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/AES256.o: AES256.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/CRC.o: CRC.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/transmit.o: transmit.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/receive.o: receive.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/detect_entries.o: detect_entries.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/essentials.o: ../include/essentials.asm | $(BUILD_DIR)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BUILD_DIR)/SHA256.o: SHA256.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean

