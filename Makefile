EXE = tftp_client

all: $(EXE)

$(EXE): main.zig tftp_client.zig Makefile
	zig build-exe --name $(EXE) $(ZIGFLAGS) $<
clean:
	rm -rf *.o $(EXE)
test:
	zig test tftp_client_test.zig
