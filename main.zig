const std = @import("std");
const t = @import("tftp_client.zig");

const TFTP_PORT = 69;

pub fn main() !void {
    // TODO: get parameters from command line options
    const verbose = true;
    const timeout = 5 * 1000;
    const adr = "127.0.0.1";
    const port = TFTP_PORT;
    //const remotename = "hello.txt";
    const remotename = "st.log";
    const localname = remotename;
    var s = std.io.StreamSource{ .file = try std.fs.cwd().createFile(localname, .{}) };
    defer s.file.close();
    try t.tftpRead(adr, port, remotename, &s, timeout, verbose);
}
