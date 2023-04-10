# Simple-Packet-Sniffer-Using-Libpcap
This is a simple packet sniffer written in C that captures packets on a specified network interface and prints useful information about the packets such as source and destination MAC addresses, IP addresses, and protocols. The program uses the libpcap library to capture packets

## Requirements
You will need development version of Pcap. Run `sudo apt-get install git libpcap-dev` in your Linux terminal
## Usage
To use this program, follow these steps: 
1. Git clone this repository using: `git clone https://github.com/umairsafdar768/Simple-Packet-Sniffer-Using-Libpcap` 
2. `cd` into the cloned repository and run `make`
3. An executable named **packet_sniffer** will be created in the current directory. Run it using `sudo ./packet_sniffer`
4. You will be prompted for name of interface and number of packets to capture. Enter appropriate responses.
5. Run `make clean` to clear the main directory

Note: This program requires root privileges to run, as capturing packets requires special permissions.

Feel free to suggest changes/improvements.
