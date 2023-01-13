const std = @import("std");
const os = std.os;
const time = std.time;
const net = std.net;
const mem = std.mem;

const UDP_PAYLOADSIZE = 65507;
const RETRY_MAX = 5;
pub const DATA_MAXSIZE = 512;
const HEADER_SIZE = 4;

pub const opcode = struct {
    pub const RRQ = 1;
    pub const WRQ = 2;
    pub const DATA = 3;
    pub const ACK = 4;
    pub const ERROR = 5;
};

pub const errCode = struct {
    pub const NotDefined = 0;
    pub const FileNotFound = 1;
    pub const AccessViolation = 2;
    pub const DiskFullOrAllocationExceed = 3;
    pub const IllegalTftpOperation = 4;
    pub const UnknownTransferId = 5;
    pub const FileAlreadyExits = 6;
    pub const NoSuchUser = 7;
    pub const Timeout = 8;
};

pub const TftpError = error{
    NotDefined,
    FileNotFound,
    AccessViolation,
    DiskFullOrAllocationExceed,
    IllegalTftpOperation,
    UnknownTransferId,
    FileAlreadyExits,
    NoSuchUser,
    Timeout,
} || std.os.SocketError || std.os.WriteError || std.os.ReadError || std.os.SendToError || std.os.RecvFromError || std.os.ConnectError;

fn makeReq(buf: []u8, opc: u16, remotename: []const u8) !usize {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeIntBig(u16, opc);
    try w.writeAll(remotename);
    try w.writeByte(0);
    try w.writeAll("octet");
    try w.writeByte(0);
    return fbs.getPos();
}

fn makeAck(b: []u8, n: u16) usize {
    mem.writeIntBig(u16, b[0..2], opcode.ACK);
    mem.writeIntBig(u16, b[2..4], n);
    return 4;
}

fn checkAck(b: []u8, n: u16) bool {
    if (mem.readIntBig(u16, b[0..2]) != opcode.ACK) return false;
    if (mem.readIntBig(u16, b[2..4]) != n) return false;
    return true;
}

fn makeDataHead(b: []u8, n: u16) void {
    mem.writeIntBig(u16, b[0..2], opcode.DATA);
    mem.writeIntBig(u16, b[2..4], n);
}

fn checkDataHead(b: []u8, n: u16) bool {
    if (mem.readIntBig(u16, b[0..2]) != opcode.DATA) return false;
    if (mem.readIntBig(u16, b[2..4]) != n) return false;
    return true;
}

fn toVisualStr(input: []const u8, output: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        if (x < 0x20 or 0x7f <= x) {
            try w.print("\\{o}", .{x});
        } else {
            try w.print("{c}", .{x});
        }
    }
    return fbs.getWritten();
}

fn toHex(input: []const u8, output: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        try w.print("{x:0>2} ", .{x});
    }
    return fbs.getWritten();
}

pub const TftpClient = struct {
    address: net.Address = undefined,
    alc: mem.Allocator = undefined,
    timeout: i32 = 1000,
    dbuf: []u8 = undefined,
    payload_buf: []u8 = undefined,
    err_msg_buf: []u8 = undefined,
    err_msg_len: u16 = 0,
    verbose: bool = false,

    const Self = @This();

    pub fn init(adr: net.Address, alc: mem.Allocator, timeout: i32, verbose: bool) std.mem.Allocator.Error!TftpClient {
        return TftpClient{ .address = adr, .alc = alc, .timeout = timeout, .dbuf = try alc.alloc(u8, 1024), .payload_buf = try alc.alloc(u8, HEADER_SIZE + DATA_MAXSIZE), .err_msg_buf = try alc.alloc(u8, 1024), .verbose = verbose };
    }
    pub fn deinit(self: *Self) void {
        self.alc.free(self.err_msg_buf);
        self.alc.free(self.dbuf);
        self.alc.free(self.payload_buf);
    }

    pub fn getErrMsg(self: *Self) []u8 {
        return self.err_msg_buf[0..self.err_msg_len];
    }

    fn dprint(self: *Self, comptime fmt: []const u8, a: anytype) void {
        if (self.verbose) {
            std.debug.print(fmt, a);
        }
    }

    fn checkError(self: *Self, b: []u8) !void {
        if (mem.readIntBig(u16, b[0..2]) != opcode.ERROR) return;
        if (b[b.len - 1] != 0) return;
        const errc = mem.readIntBig(u16, b[2..4]);
        mem.copy(u8, self.err_msg_buf, b[4 .. b.len - 1]);
        self.err_msg_len = @truncate(u16, b.len - 1 - 4);
        switch (errc) {
            errCode.NotDefined => return error.NotDefined,
            errCode.FileNotFound => return error.FileNotFound,
            errCode.DiskFullOrAllocationExceed => return error.DiskFullOrAllocationExceed,
            errCode.IllegalTftpOperation => return error.IllegalTftpOperation,
            errCode.UnknownTransferId => return error.UnknownTransferId,
            errCode.FileAlreadyExits => return error.FileAlreadyExits,
            errCode.NoSuchUser => return error.NoSuchUser,
            else => return,
        }
        unreachable;
    }

    pub fn tftpRead(self: *Self, remotename: []const u8, s: *std.io.StreamSource) TftpError!void {
        const w = s.writer();
        const data_max = DATA_MAXSIZE;
        const adr = &self.address;
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
        defer os.closeSocket(sockfd);
        const req = self.payload_buf[0..try makeReq(self.payload_buf, opcode.RRQ, remotename)];
        var svraddr: std.os.linux.sockaddr = undefined;
        var svraddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
        var recv_bytes: usize = 0;
        var block_n: u16 = 0;
        var pfd = [1]os.pollfd{.{
            .fd = sockfd,
            .events = os.POLL.IN,
            .revents = undefined,
        }};
        var retry_count: u16 = 0;
        while (retry_count < RETRY_MAX) : (retry_count += 1) {
            const send_bytes = try os.sendto(sockfd, req, 0, &adr.any, adr.getOsSockLen());
            self.dprint("{d}:send_bytes={d}, \"{s}\", a={}\n", .{ time.milliTimestamp(), send_bytes, try toVisualStr(self.payload_buf[0..send_bytes], self.dbuf), adr });
            const nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                continue;
            }
            recv_bytes = try os.recvfrom(sockfd, self.payload_buf, 0, &svraddr, &svraddrlen);
            self.dprint("{d}:recv_bytes={d}, [{s} ...], {}\n", .{ time.milliTimestamp(), recv_bytes, try toHex(self.payload_buf[0..HEADER_SIZE], self.dbuf), svraddr });
            if (checkDataHead(self.payload_buf[0..HEADER_SIZE], 1)) {
                _ = try w.writeAll(self.payload_buf[HEADER_SIZE..recv_bytes]);
                block_n = 1;
                break;
            }
            try self.checkError(self.payload_buf[0..recv_bytes]);
        } else {
            return error.Timeout;
        }

        try os.connect(sockfd, &svraddr, svraddrlen);
        var ack: []u8 = undefined;
        retry_count = 0;
        while (retry_count < RETRY_MAX) {
            ack = self.payload_buf[0..makeAck(self.payload_buf, block_n)];
            const send_bytes = try os.send(sockfd, ack, 0);
            self.dprint("{d}:send_bytes={d}, [{s}]\n", .{ time.milliTimestamp(), send_bytes, try toHex(self.payload_buf[0..send_bytes], self.dbuf) });
            if (recv_bytes < (HEADER_SIZE + data_max)) {
                return;
            }
            const nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                retry_count += 1;
                continue;
            }
            recv_bytes = try os.recv(sockfd, self.payload_buf, 0);
            self.dprint("{d}:recv_bytes={d}, [{s}...]\n", .{ time.milliTimestamp(), recv_bytes, try toHex(self.payload_buf[0..HEADER_SIZE], self.dbuf) });
            if (checkDataHead(self.payload_buf[0..HEADER_SIZE], block_n + 1)) {
                _ = try w.writeAll(self.payload_buf[HEADER_SIZE..recv_bytes]);
                block_n += 1;
                retry_count = 0;
                continue;
            }
            try self.checkError(self.payload_buf[0..recv_bytes]);
            retry_count += 1;
        } else {
            return error.Timeout;
        }
    }

    pub fn tftpWrite(self: *Self, remotename: []const u8, s: *std.io.StreamSource) TftpError!void {
        const r = s.reader();
        const data_max = DATA_MAXSIZE;
        const adr = &self.address;
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
        defer os.closeSocket(sockfd);
        const req = self.payload_buf[0..try makeReq(self.payload_buf, opcode.WRQ, remotename)];
        var svraddr: std.os.linux.sockaddr = undefined;
        var svraddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
        var recv_bytes: usize = 0;
        var block_n: u16 = 0;
        var pfd = [1]os.pollfd{.{
            .fd = sockfd,
            .events = os.POLL.IN,
            .revents = undefined,
        }};
        var retry_count: u16 = 0;
        while (retry_count < RETRY_MAX) : (retry_count += 1) {
            const send_bytes = try os.sendto(sockfd, req, 0, &adr.any, adr.getOsSockLen());
            self.dprint("{d}:send_bytes={d}, \"{s}\", a={}\n", .{ time.milliTimestamp(), send_bytes, try toVisualStr(self.payload_buf[0..send_bytes], self.dbuf), adr });
            const nevent = os.poll(&pfd, self.timeout) catch 0;
            if (nevent == 0) {
                // timeout
                continue;
            }
            recv_bytes = try os.recvfrom(sockfd, self.payload_buf, 0, &svraddr, &svraddrlen);
            self.dprint("{d}:recv_bytes={d}, [{s}], {}\n", .{ time.milliTimestamp(), recv_bytes, try toHex(self.payload_buf[0..recv_bytes], self.dbuf), svraddr });
            if (checkAck(self.payload_buf[0..HEADER_SIZE], block_n)) {
                block_n += 1;
                break;
            }
            try self.checkError(self.payload_buf[0..recv_bytes]);
        } else {
            return error.Timeout;
        }

        try os.connect(sockfd, &svraddr, svraddrlen);
        retry_count = 0;
        while (retry_count < RETRY_MAX) {
            makeDataHead(self.payload_buf[0..HEADER_SIZE], block_n);
            const n = try r.readAll(self.payload_buf[HEADER_SIZE .. HEADER_SIZE + data_max]);
            const send_bytes = try os.send(sockfd, self.payload_buf[0..(HEADER_SIZE + n)], 0);
            self.dprint("{d}:send_bytes={d}, [{s}...]\n", .{ time.milliTimestamp(), send_bytes, try toHex(self.payload_buf[0..HEADER_SIZE], self.dbuf) });
            const nevent = try os.poll(&pfd, self.timeout);
            if (nevent == 0) {
                // timeout
                retry_count += 1;
                continue;
            }
            recv_bytes = try os.recv(sockfd, self.payload_buf, 0);
            self.dprint("{d}:recv_bytes={d}, [{s}]\n", .{ time.milliTimestamp(), recv_bytes, try toHex(self.payload_buf[0..recv_bytes], self.dbuf) });
            if (checkAck(self.payload_buf[0..HEADER_SIZE], block_n)) {
                if (n < data_max) break;
                block_n += 1;
                retry_count = 0;
                continue;
            }
            try self.checkError(self.payload_buf[0..recv_bytes]);
            retry_count += 1;
        } else {
            return error.Timeout;
        }
    }
};

const expect = std.testing.expect;
const TEST_ADDR = "127.0.0.1";
const TEST_PORT = 7069;

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

fn makeError(buf: []u8, errc: u16, errmsg: []const u8) !usize {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeIntBig(u16, opcode.ERROR);
    try w.writeIntBig(u16, errc);
    try w.writeAll(errmsg);
    try w.writeByte(0);
    return fbs.getPos();
}

fn waitWithTimeout(pfd: []os.pollfd, timeout: i32) !usize {
    const nevent = try os.poll(pfd, timeout);
    if (nevent == 0) {
        std.log.err("{d}:poll timeout", .{time.milliTimestamp()});
        unreachable;
    }
    if ((pfd[0].revents & os.linux.POLL.IN) == 0) {
        std.log.err("{d}:Got revents={d}", .{ time.milliTimestamp(), pfd[0].revents });
        unreachable;
    }
    return nevent;
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
            const data_max = DATA_MAXSIZE;
            var databuf: [HEADER_SIZE + data_max]u8 = undefined;
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
            var nevent = try waitWithTimeout(&pfd, self.timeout);
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], opcode.RRQ, self.filename)) unreachable;
            const block_n = 1;
            makeDataHead(databuf[0..HEADER_SIZE], block_n);
            const n = try r.readAll(databuf[HEADER_SIZE .. HEADER_SIZE + data_max]);
            _ = try os.sendto(sockfd, databuf[0 .. HEADER_SIZE + n], 0, &cliaddr, cliaddrlen);
            nevent = try waitWithTimeout(&pfd, self.timeout);
            if (try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen) < HEADER_SIZE) unreachable;
            if (!checkAck(databuf[0..HEADER_SIZE], block_n)) unreachable;
        }
    };
    const remotename = "read_short.txt";
    const str = "Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliett Kilo Lima Mike";
    var ss = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5 * 1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    var buf: [1024]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 200, false);
    defer tc.deinit();
    try tc.tftpRead(remotename, &s);
    const n = try s.buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
    try expect(mem.eql(u8, str, buf[0..n]));
    thread.join();
}

test "read multiple packets from test server" {
    const Server = struct {
        adr: []const u8,
        port: u16,
        filename: []const u8,
        stream: *std.io.StreamSource,
        timeout: i32,
        const Self = @This();
        fn serve(self: *const Self) !void {
            const data_max = DATA_MAXSIZE;
            var databuf: [HEADER_SIZE + data_max]u8 = undefined;
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
            var nevent = try waitWithTimeout(&pfd, self.timeout);
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], opcode.RRQ, self.filename)) unreachable;
            try os.connect(sockfd, &cliaddr, cliaddrlen);
            var block_n: u16 = 0;
            var n: usize = data_max;
            while (n == data_max) {
                if (block_n == 0xffff) {
                    // too big file size
                    const en = try makeError(&databuf, 3, "File size is too big.");
                    _ = try os.send(sockfd, databuf[0..en], 0);
                    return;
                }
                block_n += 1;
                n = try r.readAll(databuf[HEADER_SIZE .. HEADER_SIZE + data_max]);
                makeDataHead(databuf[0..HEADER_SIZE], block_n);
                _ = try os.send(sockfd, databuf[0 .. HEADER_SIZE + n], 0);
                nevent = try waitWithTimeout(&pfd, self.timeout);
                if (try os.recv(sockfd, &databuf, 0) < HEADER_SIZE) unreachable;
                if (!checkAck(databuf[0..HEADER_SIZE], block_n)) unreachable;
            }
        }
    };
    const remotename = "read_long.bin";
    const DATASIZE = 2000;
    const seed = 201476;
    var rbuf: [DATASIZE]u8 = undefined;
    var prng = std.rand.DefaultPrng.init(seed);
    prng.fill(&rbuf);
    var ss = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&rbuf) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5 * 1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    var buf: [DATASIZE + 512]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 200, false);
    defer tc.deinit();
    try tc.tftpRead(remotename, &s);
    const n = try s.buffer.getPos();
    try expect(mem.eql(u8, &rbuf, buf[0..n]));
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
            const data_max = DATA_MAXSIZE;
            var databuf: [HEADER_SIZE + data_max]u8 = undefined;
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
            var nevent = try waitWithTimeout(&pfd, self.timeout);
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], opcode.WRQ, self.filename)) unreachable;
            var block_n: u16 = 0;
            _ = makeAck(databuf[0..HEADER_SIZE], block_n);
            _ = try os.sendto(sockfd, databuf[0..HEADER_SIZE], 0, &cliaddr, cliaddrlen);
            block_n += 1;
            nevent = try waitWithTimeout(&pfd, self.timeout);
            const n = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (n < HEADER_SIZE) unreachable;
            if (!checkDataHead(databuf[0..HEADER_SIZE], block_n)) unreachable;
            _ = try w.writeAll(databuf[HEADER_SIZE..n]);
            _ = makeAck(databuf[0..HEADER_SIZE], block_n);
            _ = try os.sendto(sockfd, databuf[0..HEADER_SIZE], 0, &cliaddr, cliaddrlen);
        }
    };
    const remotename = "write_short.txt";
    var buf: [1024]u8 = undefined;
    var ss = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5 * 1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    const str = "November Oscar Papa Quebec Romeo Sierra Tango Uniform Victor Whiskey Xray Yankee Zulu";
    var s = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 200, false);
    defer tc.deinit();
    try tc.tftpWrite(remotename, &s);
    const n = try s.const_buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
    try expect(mem.eql(u8, str, buf[0..n]));
    thread.join();
}

test "write multiple packets to test server" {
    const Server = struct {
        adr: []const u8,
        port: u16,
        filename: []const u8,
        stream: *std.io.StreamSource,
        timeout: i32,
        const Self = @This();
        fn serve(self: *const Self) !void {
            const data_max = DATA_MAXSIZE;
            var databuf: [HEADER_SIZE + data_max]u8 = undefined;
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
            var nevent = try waitWithTimeout(&pfd, self.timeout);
            var cliaddr: std.os.linux.sockaddr = undefined;
            var cliaddrlen: std.os.socklen_t = @sizeOf(os.linux.sockaddr);
            var recv_bytes = try os.recvfrom(sockfd, &databuf, 0, &cliaddr, &cliaddrlen);
            if (!try checkReq(databuf[0..recv_bytes], opcode.WRQ, self.filename)) unreachable;
            try os.connect(sockfd, &cliaddr, cliaddrlen);
            var block_n: u16 = 0;
            _ = makeAck(databuf[0..HEADER_SIZE], block_n);
            _ = try os.send(sockfd, databuf[0..HEADER_SIZE], 0);
            var n: usize = HEADER_SIZE + data_max;
            while (n == HEADER_SIZE + data_max and block_n <= 0xffff) {
                block_n += 1;
                nevent = try waitWithTimeout(&pfd, self.timeout);
                n = try os.recv(sockfd, &databuf, 0);
                if (n < HEADER_SIZE) unreachable;
                if (!checkDataHead(databuf[0..HEADER_SIZE], block_n)) unreachable;
                _ = try w.writeAll(databuf[HEADER_SIZE..n]);
                _ = makeAck(databuf[0..HEADER_SIZE], block_n);
                _ = try os.send(sockfd, databuf[0..HEADER_SIZE], 0);
            }
        }
    };
    const remotename = "write_long.bin";
    const DATASIZE = 2000;
    var buf: [DATASIZE + 512]u8 = undefined;
    var ss = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const svr = Server{ .adr = TEST_ADDR, .port = TEST_PORT, .filename = remotename, .stream = &ss, .timeout = 5 * 1000 };
    var thread = try std.Thread.spawn(.{}, Server.serve, .{&svr});

    const seed = 201476;
    var buf2: [DATASIZE]u8 = undefined;
    var prng = std.rand.DefaultPrng.init(seed);
    prng.fill(&buf2);
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf2) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 200, false);
    defer tc.deinit();
    try tc.tftpWrite(remotename, &s);
    const n = try s.buffer.getPos();
    try expect(mem.eql(u8, &buf2, buf[0..n]));
    thread.join();
}

test "read timeout 1" {
    const remotename = "read_short.txt";
    var buf: [1024]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 100, false);
    defer tc.deinit();
    tc.tftpRead(remotename, &s) catch |e| {
        if (e == error.Timeout) return;
    };
    unreachable;
}

test "write timeout 1" {
    const remotename = "write_short.txt";
    const str = "November Oscar Papa Quebec Romeo Sierra Tango Uniform Victor Whiskey Xray Yankee Zulu";
    var s = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    const adr = try std.net.Address.resolveIp(TEST_ADDR, TEST_PORT);
    var tc = try TftpClient.init(adr, std.testing.allocator, 100, false);
    defer tc.deinit();
    tc.tftpWrite(remotename, &s) catch |e| {
        if (e == error.Timeout) return;
    };
    unreachable;
}
