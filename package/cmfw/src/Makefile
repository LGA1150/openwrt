libipt_CMFW.so: libipt_CMFW.o
	$(CC) -shared -lxtables -o $@ $^;
libipt_CMFW.o: libipt_CMFW.c
	$(CC) ${CFLAGS} -fPIC -D_INIT=$*_init -c -o $@ $<;

obj-m += xt_CMFW.o
