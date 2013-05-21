deauth-jammer: deauth-jammer.c
	gcc  -Wall radiotap.c deauth-jammer.c -o deauth-jammer -lpcap

clean:
	rm -f deauth-jammer *~
