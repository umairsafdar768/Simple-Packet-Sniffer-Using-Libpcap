CC = gcc
LDLIBS =-lpcap

all: packet_sniffer

packet_sniffer: packet_sniffer.c
	$(CC) -o packet_sniffer packet_sniffer.c $(LDLIBS)

clean:
	rm -f packet_sniffer
