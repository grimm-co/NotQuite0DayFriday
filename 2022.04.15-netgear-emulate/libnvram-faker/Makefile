
OBJS = nvram-faker.o netgear.o internal.o
LIB = libnvram-faker.so

all: lib test
lib: $(LIB)

%.o:%.c
	$(CC) -Wall $(INCLUDES) $(CFLAGS) -fPIC -c -o $@ $<

$(LIB): $(OBJS)
	$(LD) -shared -o $@ $^ -nostdlib

test:
	$(CC) nvram-test.c -o nvram-test -L. -lnvram-faker

clean:
	rm -f *.o *.so nvram-test
