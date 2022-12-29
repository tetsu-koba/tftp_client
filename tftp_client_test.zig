const std = @import("std");
const t = @import("tftp_client.zig");

const TEST_ADDR = "127.0.0.1";
const TEST_PORT = 69;

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

test "write to fixedBufferStream" {
    const verbose = false;
    const timeout = 5 * 1000;
    const remotename = "hello.txt";
    var buf: [1024]u8 = undefined;
    var s = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    try t.tftpRead(TEST_ADDR, TEST_PORT, remotename, &s, timeout, verbose);
    const n = try s.buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, buf[0..n] });
}

test "read from fixedBufferStream" {
    const verbose = false;
    const timeout = 5 * 1000;
    const remotename = "hello.txt";
    const str = "Hello, how are you?";
    var s = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(str) };
    try t.tftpWrite(TEST_ADDR, TEST_PORT, remotename, &s, timeout, verbose);
    const n = try s.const_buffer.getPos();
    std.debug.print("\nn={d}, [{s}]\n", .{ n, str[0..n] });
}
