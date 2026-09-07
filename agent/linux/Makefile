CC ?= gcc
CFLAGS ?= -O2 -Wall -I../include
LDLIBS ?= -lcurl -lutil -lbpf
TARGET = ../../build/ominulld

all: $(TARGET)

$(TARGET): main.c udp_collector.h tcp_pending.h bpf/udp.bpf.c ../include/udp_observation.h
	bash ../../scripts/build-bpf.sh
	mkdir -p ../../build
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
