const std = @import("std");
const os = std.os;
const debug = std.debug;
const time = std.time;
const net = std.net;
const mem = std.mem;

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

fn makeReq(buf: []u8, opc:u16, remotename: []const u8) !usize {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeIntBig(u16, opc);
    try w.writeAll(remotename);
    try w.writeIntBig(u8, 0);
    try w.writeAll("octet");
    try w.writeIntBig(u8, 0);
    return fbs.getPos();
}

fn makeAck(b: []u8, n: u16) usize {
    mem.writeIntBig(u16, b[0..2], opcode.ACK);
    mem.writeIntBig(u16, b[2..4], n);
    return 4;
}

fn checkDataHead(b: []u8, n: u16) bool {
    if (mem.readIntBig(u16, b[0..2]) != opcode.DATA) return false;
    if (mem.readIntBig(u16, b[2..4]) != n) return false;
    return true;
}

var payload_buf: [UDP_PAYLOADSIZE]u8 = undefined;

pub fn tftpRead(adr: []const u8, port: u16, remotename: []const u8, s: *std.io.StreamSource, timeout: i32, verbose: bool) !void {
    const w = s.writer();
    const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
    defer os.closeSocket(sockfd);
    const req = payload_buf[0..try makeReq(&payload_buf, opcode.RRQ, remotename)];
    const a = try net.Address.resolveIp(adr, port);
    var svraddr: std.os.linux.sockaddr = undefined;
    var svraddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
    var bytes_read: usize = 0;
    var block_n: u16 = 0;
    var pfd = [1]os.pollfd{.{
        .fd = sockfd,
        .events = os.POLL.IN,
        .revents = undefined,
    }};
    var retry_count: u16 = 0;
    while (retry_count < RETRY_MAX) : (retry_count += 1) {
        const send_bytes = try os.sendto(sockfd, req, 0, &a.any, a.getOsSockLen());
        if (verbose) {
            debug.print("{d}:send_bytes={d}, a={}", .{ time.milliTimestamp(), send_bytes, a });
        }
        const nevent = os.poll(&pfd, timeout) catch 0;
        if (nevent == 0) {
            // timeout
            continue;
        }
        if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
            std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
            return os.ReadError.ReadError;
        }
        bytes_read = try os.recvfrom(sockfd, &payload_buf, 0, &svraddr, &svraddrlen);
        if (verbose) {
            debug.print("{d}:bytes_read={d} {} [{s}].", .{ time.milliTimestamp(), bytes_read, svraddr, payload_buf[0..bytes_read] });
            // var out_buf: [1024]u8 = undefined;
            // const n = try toStr(payload_buf[0..bytes_read], &out_buf);
            // debug.print("len = {d}, s=[{s}]\n", .{ n, out_buf[0..n] });
        }
        if (checkDataHead(payload_buf[0..4], 1)) {
            _ = try w.writeAll(payload_buf[4..bytes_read]);
            block_n = 1;
            break;
        }
    } else {
        return os.ReadError.ReadError;
    }

    try os.connect(sockfd, &svraddr, svraddrlen);
    if (verbose) {
        debug.print("{d}:connect, a={}", .{ time.milliTimestamp(), svraddr });
    }
    var ack: []u8 = undefined;
    retry_count = 0;
    while (retry_count < RETRY_MAX) {
        ack = payload_buf[0..makeAck(&payload_buf, block_n)];
        const send_bytes = try os.send(sockfd, ack, 0);
        if (verbose) {
            debug.print("{d}:send_bytes={d} block_n={d}", .{ time.milliTimestamp(), send_bytes, block_n });
        }
        if (bytes_read < DATA_MAXSIZE) {
            return;
        }
        const nevent = os.poll(&pfd, timeout) catch 0;
        if (nevent == 0) {
            // timeout
            retry_count += 1;
            continue;
        }
        if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
            std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
            return os.ReadError.ReadError;
        }
        bytes_read = try os.recv(sockfd, &payload_buf, 0);
        if (verbose) {
            debug.print("{d}:bytes_read={d} {d}", .{ time.milliTimestamp(), bytes_read, payload_buf[3] });
        }
        if (checkDataHead(payload_buf[0..4], block_n + 1)) {
            _ = try w.writeAll(payload_buf[4..bytes_read]);
            block_n += 1;
            retry_count = 0;
            continue;
        }
        retry_count += 1;
    } else {
        return os.ReadError.ReadError;
    }
}

