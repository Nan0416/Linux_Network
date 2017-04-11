all:main_cpair.c sniffer_select.o transceiver.o
	gcc -Wall -o cpair main_cpair.c sniffer_select.o transceiver.o
sniffer_select.o: sniffer_select.c
	gcc -Wall -c sniffer_select.c
transceiver.o: transceiver.c
	gcc -Wall -c transceiver.c
