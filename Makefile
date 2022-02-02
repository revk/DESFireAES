# Make local tools and library

ifeq ($(shell uname),Darwin)
LIBS="-L/usr/local/opt/openssl@3/lib"
INCLUDES="-I/usr/local/opt/openssl@3/include"
else
LIBS=
INCLUDES=
endif

all: nfc

pull:
	git pull
	git submodule update --recursive

update:
	git submodule update --init --recursive --remote
	git commit -a -m "Library update"

AJL/ajl.o: AJL
	make -C AJL

nfc: nfc.c desfireaes.o pn532.o include/desfireaes.h include/pn532.h AJL/ajl.o AJL/ajl.h
	cc -fPIC -O -DLIB -o $@ -Iinclude $< desfireaes.o pn532.o ${INCLUDES} ${LIBS} -lcrypto -lssl -lpopt AJL/ajl.o -IAJL

desfireaes.o: desfireaes.c
	cc -fPIC -O -DLIB -c -o $@ -Iinclude $< ${INCLUDES}

pn532.o: pn532.c
	cc -fPIC -O -DLIB -c -o $@ -Iinclude $< ${INCLUDES}
