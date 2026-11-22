CROSS_COMPILE ?= x86_64-w64-mingw32-
CC            := $(CROSS_COMPILE)gcc
PYTHON        ?= python3
ROOTFS        ?= ../../rootfs
BUILD         := build
TARGET        := $(BUILD)/hello_world.exe
OBJECT        := $(BUILD)/hello_world.o

.PHONY: all install clean
all: $(TARGET)

$(BUILD):
	mkdir -p $@

$(OBJECT): hello_world.S | $(BUILD)
	$(CC) -c -x assembler-with-cpp $< -o $@

$(TARGET): $(OBJECT) clear_empty_imports.py
	$(CC) -nostdlib -nostartfiles \
		-Wl,-e,mainCRTStartup \
		-Wl,--subsystem,console \
		-Wl,--file-alignment,4096 \
		-Wl,--section-alignment,4096 \
		-Wl,--image-base,0x140000000 \
		-Wl,--disable-dynamicbase \
		-Wl,--disable-high-entropy-va \
		-Wl,--disable-reloc-section \
		-Wl,--no-seh \
		-Wl,--no-insert-timestamp \
		$< -o $@
	$(PYTHON) clear_empty_imports.py $@
	@echo "Built $@"

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(ROOTFS)/windows/hello_world.exe

clean:
	rm -rf $(BUILD)
