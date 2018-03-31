TARGET = sbwdn
LIBS = -levent -lconfuse
CC = gcc
DEBUGFLAG= -g
CFLAGS = $(DEBUGFLAG) -Wall -Wextra -Wno-address-of-packed-member
LFLAGS = $(DEBUGFLAG) -Wall -Wextra

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LFLAGS) $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
