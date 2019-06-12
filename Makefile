TARGET = sbwdn
LIBS = -levent -lconfuse
CC = gcc
SB_GIT_VERSION := "$(shell git describe --abbrev=8 --dirty --always --tags 2>/dev/null || echo 'not built in git environment')"
override CFLAGS += --std=gnu99 $(DEBUGFLAG) -DSB_GIT_VERSION=\"$(SB_GIT_VERSION)\" -Wall -Wextra -Wno-address-of-packed-member
override LFLAGS += $(DEBUGFLAG) -Wall -Wextra

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
