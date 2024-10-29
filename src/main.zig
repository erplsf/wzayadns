const std = @import("std");
const net = std.net;
const posix = std.posix;

// DNS Request/Response
const RRType = enum(u1) {
    Query = 0,
    Response = 1,
};

const Opcode = enum(u4) {
    Query = 0,
    InverseQuery = 1,
    ServerStatusRequest = 2,
    _, // all other values (3-15) are reserved for now
};

const Header = packed struct {
    id: u16,
    type: RRType,
};

const RR = packed struct {
    header: Header,
};

pub fn main() !void {
    const address = try std.net.Address.parseIp("127.0.0.1", 5353);

    const tpe: u32 = posix.SOCK.DGRAM;
    const protocol = posix.IPPROTO.UDP;
    const socket = try posix.socket(address.any.family, tpe, protocol);
    defer posix.close(socket);

    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(socket, &address.any, address.getOsSockLen());

    var buf: [512]u8 = undefined;

    while (true) {
        var client_address: net.Address = undefined;
        var client_address_len: posix.socklen_t = @sizeOf(net.Address);

        const read = posix.recvfrom(socket, &buf, 0, &client_address.any, &client_address_len) catch |err| {
            std.debug.print("error reading: {}\n", .{err});
            continue;
        };

        if (read == 0) {
            continue;
        }

        std.debug.print("[{}] -> ", .{client_address});

        const data = buf[0..read];

        std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(data)});

        const wrote = posix.sendto(socket, data, 0, &client_address.any, client_address_len) catch |err| {
            std.debug.print("error writing: {}\n", .{err});
            continue;
        };

        if (wrote != read) {
            std.debug.print("couldn't write the whole response back, exiting!", .{});
            break;
        }
    }
}
