CC ?= gcc
CFLAGS ?= -O2 -Wall -I../../include
TARGET = ../../build/ominulld

all: $(TARGET)

$(TARGET): main.c
	mkdir -p ../../build
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
