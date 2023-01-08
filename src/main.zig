const std = @import("std");
const t = @import("tftp_client.zig");

const TFTP_PORT = 69;

pub fn main() !void {
    // TODO: add -v, -t, -p options
    const verbose = true;
    const timeout = 5 * 1000;
    const port = TFTP_PORT;
    const alc = std.heap.page_allocator;
    const args = try std.process.argsAlloc(alc);
    defer std.process.argsFree(alc, args);

    if (args.len < 4 or 5 < args.len) {
        std.debug.print("Usage: {s} get|put host remote_filename [local_filename]\n", .{args[0]});
        std.os.exit(1);
    }
    const a1 = std.mem.sliceTo(args[1], 0);
    const op: enum { get, put } = if (std.mem.eql(u8, a1, "get")) .get else if (std.mem.eql(u8, a1, "put")) .put else {
        std.debug.print("{s} is not allowed. Specify 'get' or 'put'\n", .{a1});
        std.os.exit(1);
    };
    const host = std.mem.sliceTo(args[2], 0);
    const remotename = std.mem.sliceTo(args[3], 0);
    var localname: []u8 = remotename;
    if (args.len >= 5) {
        localname = std.mem.sliceTo(args[4], 0);
    }
    var alist = std.net.getAddressList(alc, host, port) catch |e| {
        std.debug.print("std.net.getAddressList: host={s} {}\n", .{ host, e });
        std.os.exit(1);
    };
    defer alist.deinit();
    const adr = alist.addrs[0];
    var tc = t.TftpClient.init(adr, timeout, verbose);
    switch (op) {
        .get => {
            var s = std.io.StreamSource{ .file = try std.fs.cwd().createFile(localname, .{}) };
            defer s.file.close();
            try tc.tftpRead(remotename, &s);
        },
        .put => {
            var s = std.io.StreamSource{ .file = try std.fs.cwd().openFile(localname, .{}) };
            defer s.file.close();
            try tc.tftpWrite(remotename, &s);
        },
    }
}
