CFLAGS+=-Wall -Wextra -O2 -I/usr/local/include
LDFLAGS+=-L/usr/local/lib
LIBS=-lcjson -lcurl -lssl -lcrypto -lm
OBJS=main.o cos.o ddns.o json.o natmap.o template.o

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

zddns: $(OBJS)
	$(CC) -o zddns $(CFLAGS) $(LDFLAGS) $(LIBS) $(OBJS)

clean:
	rm -f $(OBJS) zddns