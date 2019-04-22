libxt_SPOOFTCP.so: libxt_SPOOFTCP.o
	$(CC) -shared -lxtables -o $@ $^;
libxt_SPOOFTCP.o: libxt_SPOOFTCP.c
	$(CC) ${CFLAGS} -fPIC -D_INIT=$*_init -c -o $@ $<;

obj-m += xt_SPOOFTCP.o

