OPTIONS =  -fdata-sections -ffunction-sections -Wl,--gc-sections -fno-asynchronous-unwind-tables -fno-unwind-tables -O3 -Wl,--exclude-all-symbols -s -fno-leading-underscore -nostdlib
TARGET = exe
OUTPUT =

ifeq ($(ARCH), x86)
	CC = i686-w64-mingw32-gcc
else
	CC = x86_64-w64-mingw32-gcc
endif

ifeq ($(TARGET), exe)
	TARGET_FLAGS = -mwindows -e emain -o $(OUTPUT)
else
	TARGET_FLAGS = -e DllMain -shared -o $(OUTPUT)
endif

all:
	$(CC) $(OPTIONS) $(TARGET_FLAGS) main.c core.c
	strip $(OUTPUT)

clean:
	rm build/*