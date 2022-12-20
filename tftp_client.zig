const std = @import("std");
const udp = @import("udp.zig");
const os = std.os;
const log = std.log;
const time = std.time;
const net = std.net;

//const TFTP_PORT = 69;
const TFTP_PORT = 7200;
const UDP_PAYLOADSIZE = 65507;
const RETRY_MAX = 5;

fn req(adr: []const u8, timeout:i32, verbose: bool) !u16 {
    const a = try net.Address.resolveIp(adr, TFTP_PORT);
    var s = try udp.udpConnectToAddress(a);
    defer s.close();
    if (verbose) {
        log.info("{d}:Connected.", .{time.milliTimestamp()});
    }
    var retry_count:u16 = 0;
    while (retry_count < RETRY_MAX) {
        const bytes_write = try s.write("Hello from client.");
        if (verbose) {
            log.info("{d}:bytes_write={d}", .{time.milliTimestamp(),bytes_write});
        }
        var buf: [UDP_PAYLOADSIZE]u8 = .{};
        var pfd = [1]os.pollfd{.{
            .fd = s.handle,
            .events = os.POLL.IN,
            .revents = undefined,
        }};
        const nevent = os.poll(&pfd, timeout) catch 0;
        if (nevent == 0) {
            // timeout
            retry_count += 1;
            continue;
        }
        if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
            log.err("{d}:Got revents={d}", .{time.milliTimestamp(),pfd[0].revents});
            return os.ReadError.ReadError;
        }
        const bytes_read = try s.read(buf[0..]);
        if (verbose) {
            log.info("{d}:Got message [{s}].", .{time.milliTimestamp(),buf[0..bytes_read]});
        }
        const port = 0;
        return port;
    }
    return os.ReadError.ReadError;
}

pub fn main() !void {
    // TODO: get parameters from command line options
    const verbose = true;
    const timeout = 5 * 1000;
    const adr = "127.0.0.1";
    _ = try req(adr, timeout, verbose);
}
