const std = @import("std");
const udp = @import("udp.zig");
const os = std.os;
const log = std.log;
const time = std.time;
const net = std.net;

const UDP_PAYLOADSIZE = 65507;

fn helloToServer(adr: []const u8, port: u16, verbose:bool) !void {
    const a = try net.Address.resolveIp(adr, port);
    var s = try udp.udpConnectToAddress(a);
    defer s.close();
    if (verbose) {
        log.info("{d}:Connected.", .{time.milliTimestamp()});
    }
    const bytes_write = try s.write("Hello from client.");
    if (verbose) {
        log.info("{d}:bytes_write={d}", .{time.milliTimestamp(),bytes_write});
    }
    var buf: [UDP_PAYLOADSIZE]u8 = .{};
    const bytes_read = try s.read(buf[0..]);
    if (verbose) {
        log.info("{d}:Got message [{s}].", .{time.milliTimestamp(),buf[0..bytes_read]});
    }
}

pub fn main() !void {
    // TODO: get parameters from command line options
    const verbose = true;
    const adr = "127.0.0.1";
    const port = 7200;
    try helloToServer(adr, port, verbose);
}
