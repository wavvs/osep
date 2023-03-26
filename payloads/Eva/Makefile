OPTIONS =  -fdata-sections -ffunction-sections -Wl,--gc-sections -fno-asynchronous-unwind-tables -fno-unwind-tables -O3 -Wl,--exclude-all-symbols -s -fno-leading-underscore -nostdlib
OUT = eva
TARGET = exe

ifeq ($(ARCH), x86)
	CC = i686-w64-mingw32-gcc
else
	CC = x86_64-w64-mingw32-gcc
endif

ifeq ($(TARGET), exe)
	TARGET_FLAGS = -mwindows -e emain -o build/$(OUT).$(TARGET)
else
	TARGET_FLAGS = -e DllMain -shared -o build/$(OUT).$(TARGET)
endif

all:
	$(CC) $(OPTIONS) $(TARGET_FLAGS) main.c core.c
	strip build/$(OUT).$(TARGET)

clean:
	rm build/*