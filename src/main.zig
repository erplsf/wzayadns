const std = @import("std");
const net = std.net;
const posix = std.posix;

pub fn main() !void {
    const address = try std.net.Address.parseIp("127.0.0.1", 53);

    const tpe: u32 = posix.SOCK.DGRAM;
    const protocol = posix.IPPROTO.UDP;
    const listener = try posix.socket(address.any.family, tpe, protocol);
    defer posix.close(listener);
}
