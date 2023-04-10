CC = gcc
LDFLAGS =-lpcap

all: packet_sniffer

packet_sniffer: packet_sniffer.c
	$(CC) -o packet_sniffer packet_sniffer.c $(LDFLAGS)

clean:
	rm -f packet_sniffer
