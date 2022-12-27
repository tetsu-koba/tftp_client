const std = @import("std");
const os = std.os;
const log = std.log;
const time = std.time;
const net = std.net;

const TFTP_PORT = 69;
const UDP_PAYLOADSIZE = 65507;
const DATA_MAXSIZE = 4 + 512;
const RETRY_MAX = 5;

const opcode = struct {
    const RRQ = 1;
    const WRQ = 2;
    const DATA = 3;
    const ACK = 4;
    const ERROR = 5;
};

fn makeReq(buf: []u8, remotename: []const u8) !usize {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeIntBig(u16, opcode.RRQ);
    try w.writeAll(remotename);
    try w.writeIntBig(u8, 0);
    try w.writeAll("octet");
    try w.writeIntBig(u8, 0);
    return fbs.getPos();
}

fn makeAck(buf: []u8, n: u16) !usize {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeIntBig(u16, opcode.RRQ);
    try w.writeIntBig(u16, n);
    return fbs.getPos();
}

pub fn tftpRead(adr: []const u8, port: u16, remotename: []const u8, s: *std.io.StreamSource, timeout: i32, verbose: bool) !void {
    const w = s.writer();
    const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
    defer os.closeSocket(sockfd);
    var send_buf: [1024]u8 = undefined;
    const req = send_buf[0..try makeReq(&send_buf, remotename)];
    const a = try net.Address.resolveIp(adr, port);
    var svraddr: std.os.linux.sockaddr = undefined;
    var svraddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
    var bytes_read: usize = 0;
    var block_n: u16 = 0;
    var retry_count: u16 = 0;
    while (retry_count < RETRY_MAX) : (retry_count += 1) {
        const send_bytes = try os.sendto(sockfd, req, 0, &a.any, a.getOsSockLen());
        if (verbose) {
            log.info("{d}:send_bytes={d}, a={}", .{ time.milliTimestamp(), send_bytes, a });
        }
        var buf: [UDP_PAYLOADSIZE]u8 = undefined;
        var pfd = [1]os.pollfd{.{
            .fd = sockfd,
            .events = os.POLL.IN,
            .revents = undefined,
        }};
        const nevent = os.poll(&pfd, timeout) catch 0;
        if (nevent == 0) {
            // timeout
            continue;
        }
        if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
            log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
            return os.ReadError.ReadError;
        }
        bytes_read = try os.recvfrom(sockfd, &buf, 0, &svraddr, &svraddrlen);
        if (verbose) {
            log.info("{d}:bytes_read={d} {} [{s}].", .{ time.milliTimestamp(), bytes_read, svraddr, buf[0..bytes_read] });
            var out_buf: [1024]u8 = undefined;
            const n = try toStr(buf[0..bytes_read], &out_buf);
            log.info("len = {d}, s=[{s}]\n", .{ n, out_buf[0..n] });
        }
        if (bytes_read <= DATA_MAXSIZE and buf[0] == 0 and buf[1] == 3 and buf[2] == 0 and buf[3] == 1) {
            _ = try w.writeAll(buf[4..bytes_read]);
            block_n = 1;
            break;
        }
    } else {
        return os.ReadError.ReadError;
    }
    var ack: []u8 = undefined;
    retry_count = 0;
    while (retry_count < RETRY_MAX) : (retry_count += 1) {
        ack = send_buf[0..try makeAck(&send_buf, block_n)];
        const send_bytes = try os.sendto(sockfd, ack, 0, &svraddr, svraddrlen);
        if (verbose) {
            log.info("{d}:send_bytes={d}, a={}", .{ time.milliTimestamp(), send_bytes, svraddr });
        }
        if (bytes_read < DATA_MAXSIZE) {
            return;
        }
    } else {
        return os.ReadError.ReadError;
    }
}

fn toStr(input: []const u8, output: []u8) !usize {
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

pub fn main() !void {
    // TODO: get parameters from command line options
    const verbose = true;
    const timeout = 5 * 1000;
    const adr = "127.0.0.1";
    const port = TFTP_PORT;
    const remotename = "hello.txt";
    const localname = remotename;
    var s = std.io.StreamSource{ .file = try std.fs.cwd().createFile(localname, .{}) };
    defer s.file.close();
    try tftpRead(adr, port, remotename, &s, timeout, verbose);
}

test "to fixedBufferStream" {
    const verbose = true;
    const timeout = 5 * 1000;
    const adr = "127.0.0.1";
    const port = TFTP_PORT;
    const remotename = "hello.txt";
    var buf: [1024]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    try tftpRead(adr, port, remotename, &s, timeout, verbose);
    const n = try s.buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
}
