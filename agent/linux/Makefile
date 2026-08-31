CC ?= gcc
CFLAGS ?= -O2 -Wall -I../../include
LDLIBS ?= -lcurl
TARGET = ../../build/ominulld

all: $(TARGET)

$(TARGET): main.c
	mkdir -p ../../build
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
