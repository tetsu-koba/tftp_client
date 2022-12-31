const std = @import("std");
const os = std.os;
const mem = std.mem;
const net = std.net;
const time = std.time;
const expect = std.testing.expect;
const t = @import("tftp_client.zig");

const TEST_ADDR = "127.0.0.1";
const TEST_PORT = 7069;

fn toVisualStr(input: []const u8, output: []u8) !usize {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        if (x < 0x20 or 0x7f <= x) {
            try w.print("\\{o}", .{x});
        } else {
            try w.print("{c}", .{x});
        }
    }
    return fbs.getPos();
}

fn checkReq(buf: []u8, req: u16, remotename: []const u8) !bool {
    var fbs = std.io.fixedBufferStream(buf);
    const r = fbs.reader();

    if (req != try r.readIntBig(u16)) return false;
    var b: [1024]u8 = undefined;
    if (!mem.eql(u8, remotename, try r.readUntilDelimiter(&b, 0))) {
        return false;
    }
    if (!mem.eql(u8, "octet", try r.readUntilDelimiter(&b, 0))) {
        return false;
    }
    return true;
}

test "read single packet from test server" {
    const Server = struct {
        adr: []const u8,
        port: u16,
        filename: []const u8,
        stream: *std.io.StreamSource,
        timeout: i32,
        const Self = @This();
        fn serve(self: *const Self) !void {
            const data_max = t.DATA_MAXSIZE;
            var databuf: [4 + data_max]u8 = undefined;
            const r = self.stream.reader();
            const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
            defer os.closeSocket(sockfd);
            const a = try net.Address.resolveIp(self.adr, self.port);
            try os.bind(sockfd, &a.any, a.getOsSockLen());
            var pfd = [1]os.pollfd{.{
                .fd = sockfd,
                .events = os.POLL.IN,
                .revents = undefined,
            }};
            var nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                unreachable;
            }
            if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
                std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
                unreachable;
            }
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], t.opcode.RRQ, self.filename)) unreachable;
            const block_n = 1;
            t.makeDataHead(databuf[0..4], block_n);
            const n = try r.readAll(databuf[4 .. 4 + data_max]);
            _ = try os.sendto(sockfd, databuf[0 .. 4 + n], 0, &cliaddr, cliaddrlen);
            nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                unreachable;
            }
            if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
                std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
                unreachable;
            }
            if (try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen) < 4) unreachable;
            if (!t.checkAck(databuf[0..4], block_n)) unreachable;
        }
    };
    const remotename = "read_short.txt";
    const str = "Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliett Kilo Lima Mike";
    var ss = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5*1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    var buf: [1024]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    try t.tftpRead(TEST_ADDR, TEST_PORT, remotename, &s, 200, false);
    const n = try s.buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
    try expect(mem.eql(u8, str, buf[0..n]));
    thread.join();
}

test "write single packet to test server" {
    const Server = struct {
        adr: []const u8,
        port: u16,
        filename: []const u8,
        stream: *std.io.StreamSource,
        timeout: i32,
        const Self = @This();
        fn serve(self: *const Self) !void {
            const data_max = t.DATA_MAXSIZE;
            var databuf: [4 + data_max]u8 = undefined;
            const w = self.stream.writer();
            const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
            defer os.closeSocket(sockfd);
            const a = try net.Address.resolveIp(self.adr, self.port);
            try os.bind(sockfd, &a.any, a.getOsSockLen());
            var pfd = [1]os.pollfd{.{
                .fd = sockfd,
                .events = os.POLL.IN,
                .revents = undefined,
            }};
            var nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                unreachable;
            }
            if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
                std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
                unreachable;
            }
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], t.opcode.WRQ, self.filename)) unreachable;
            var block_n: u16 = 0;
            _ = t.makeAck(databuf[0..4], block_n);
            _ = try os.sendto(sockfd, databuf[0..4], 0, &cliaddr, cliaddrlen);
            block_n += 1;
            nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                unreachable;
            }
            if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
                std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
                unreachable;
            }
            const n = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (n < 4) unreachable;
            if (!t.checkDataHead(databuf[0..4], block_n)) unreachable;
            _ = try w.writeAll(databuf[4 .. n]);
            _ = t.makeAck(databuf[0..4], block_n);
            _ = try os.sendto(sockfd, databuf[0..4], 0, &cliaddr, cliaddrlen);
        }
    };
    const remotename = "write_short.txt";
    var buf: [1024]u8 = undefined;
    var ss = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5*1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    const str = "November Oscar Papa Quebec Romeo Sierra Tango Uniform Victor Whiskey Xray Yankee Zulu";
    var s = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    try t.tftpWrite(TEST_ADDR, TEST_PORT, remotename, &s, 200, false);
    const n = try s.const_buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
    try expect(mem.eql(u8, str, buf[0..n]));
    thread.join();
}
