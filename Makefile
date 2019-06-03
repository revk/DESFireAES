desfireaes.o: desfireaes.c
	cc -fPIC -O -DLIB -c -o $@ $<
