# Makefile
BINARY  := failtop
PREFIX  := /usr/local/bin
LDFLAGS := -s -w

.PHONY: build install clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

install: build
	install -m 0755 $(BINARY) $(PREFIX)/$(BINARY)

clean:
	rm -f $(BINARY)
