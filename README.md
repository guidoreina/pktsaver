pktsaver
========

pktsaver is a packet capturing tool for Linux which uses the `PACKET_MMAP` feature (TPACKET version 3).

Options:
* The size of the ring buffer can be specified (`-s`).
* It can store the packets in memory and only dump them before exiting (option `-m`).
* Basic filtering: it can filter the protocols (`ICMP`, `TCP` and `UDP`).
 For TCP and UDP a list of ports can be specified (`-f`).


### Compiling
Just execute `make`.
