packet_capture: packet_capture_controller

packet_capture_controller: global_functions.o interfacer.o interface_analyser.o packet_sniffer.o packet_analyser.o packet_capture_controller.o
	gcc -o packet_capture_controller global_functions.o interfacer.o interface_analyser.o packet_sniffer.o packet_analyser.o packet_capture_controller.o -lpcap

global_functions.o: global_functions.c
	gcc -c global_functions.c

interfacer.o: interfacer.c
	gcc -c interfacer.c

interface_analyser.o: interface_analyser.c
	gcc -c interface_analyser.c

packet_sniffer.o: packet_sniffer.c
	gcc -c packet_sniffer.c

packet_analyser.o: packet_analyser.c
	gcc -c packet_analyser.c

packet_capture_controller.o: packet_capture_controller.c
	gcc -c packet_capture_controller.c

clean:
	rm -rf *.o packet_capture_controller
	rm -rf *~