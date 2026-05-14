CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter -std=c11 -D_GNU_SOURCE
LDFLAGS ?=

BIN     := planetar-broker
SRC     := planetar-broker.c

.PHONY: all clean run debug

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wpedantic -Wno-unused-parameter -std=c11 -D_GNU_SOURCE -fsanitize=address,undefined
debug: clean $(BIN)

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN)
