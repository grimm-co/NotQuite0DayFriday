obj-m += cleanup.o

all: exploit send_pdu

exploit:
	gcc -DEXPLOIT leak.c symbols.c common.c exploit.c -o exploit

send_pdu:
	gcc send_pdu_oob.c leak.c symbols.c common.c -o send_pdu_oob

deliverable:
	./make_deliverable.sh build

clean:
	rm -rf exploit send_pdu_oob
	rm -rf build

.PHONY: exploit send_pdu deliverable
