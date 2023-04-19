# Make local tools and library

ifeq ($(shell uname),Darwin)
LIBS=-L/usr/local/opt/openssl@3/lib -I/usr/local/include/
INCLUDES=-I/usr/local/opt/openssl@3/include -L/usr/local/Cellar/popt/1.18/lib/
else
LIBS=
INCLUDES=
endif

all: nfc destest

pull:
	git pull
	git submodule update --recursive

update:
	git submodule update --init --recursive --remote
	git commit -a -m "Library update"

AJL/ajl.o: AJL
	make -C AJL

nfc: nfc.c desfireaes.o pn532.o include/desfireaes.h pn532.h AJL/ajl.o AJL/ajl.h tdea.o
	gcc -fPIC -O -o $@ -Iinclude $< desfireaes.o pn532.o ${INCLUDES} ${LIBS} -lcrypto -lssl -lpopt AJL/ajl.o -IAJL

desfireaes.o: desfireaes.c
	gcc -fPIC -O -DLIB -c -o $@ -Iinclude $< ${INCLUDES}

destest: destest.c desfireaes.o
	gcc -fPIC -O -o $@ -Iinclude $< desfireaes.o ${INCLUDES} ${LIBS}-lcrypto -lssl -lpopt

pn532.o: pn532.c
	gcc -fPIC -O -DLIB -c -o $@ -Iinclude $< ${INCLUDES}

tdea.o: tdea.c
	gcc -fPIC -O -DLIB -c -o $@ -Iinclude $< ${INCLUDES}
