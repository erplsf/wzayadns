const std = @import("std");
const net = std.net;
const posix = std.posix;

// const RRType = enum(u1) {
//     Query = 0,
//     Response = 1,
// };

const Opcode = enum(u4) {
    Query = 0,
    InverseQuery = 1,
    ServerStatusRequest = 2,
    _, // all other values (3-15) are reserved for future use
};

const Flags = packed struct(u4) {
    AA: bool = false,
    TC: bool = false,
    RD: bool = false,
    RA: bool = false,
};

const ResponseCode = enum(u4) {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    _, // all other values (6-15) are reserved for future use
};

const Header = packed struct(u96) {
    id: u16, // 16 bits
    response: bool, // 1 bit
    opcode: Opcode, // 4 bits
    flags: Flags, // 4 bits
    Z: u3 = 0, // 3 bits, reserved for future use
    rcode: ResponseCode, // 4 bits
    QCount: u16, // 16 bits
    ANCount: u16, // 16 bits
    NSCount: u16, // 16 bits
    ARCount: u16, // 16 bits

    pub fn decode(buf: []const u8) Header {
        var pos: usize = 0;

        const id: u16 = std.mem.readInt(u16, buf[pos .. pos + 2][0..2], .big);
        pos += 2;

        const response = buf[pos] & 0b10000000 == 1; // 1 bit

        const opcode: Opcode = @enumFromInt(@as(u4, @truncate(@shrExact(buf[pos] & 0b01111000, 3)))); // 4 bits

        const part: u8 = @shlExact(buf[pos .. pos + 1][0], 1);
        pos += 1;
        const second_part: u8 = buf[pos .. pos + 1][0] >> 7;
        const flags: Flags = @bitCast(@bitReverse(@as(u4, @truncate(part | second_part)))); // bit reverse is needed because of endian/order shenenigans, 4 bits

        const z: u3 = @as(u3, @truncate(@shrExact(buf[pos] & 0b01110000, 4))); // 3 bits

        const rcode: ResponseCode = @enumFromInt(@as(u4, @truncate(buf[pos] & 0b00001111))); // 4 bits
        pos += 1;

        const qcount: u16 = std.mem.readInt(u16, buf[pos .. pos + 2][0..2], .big);
        pos += 2;

        const ancount: u16 = std.mem.readInt(u16, buf[pos .. pos + 2][0..2], .big);
        pos += 2;

        const nscount: u16 = std.mem.readInt(u16, buf[pos .. pos + 2][0..2], .big);
        pos += 2;

        const arcount: u16 = std.mem.readInt(u16, buf[pos .. pos + 2][0..2], .big);
        pos += 2;

        return .{
            .id = id,
            .response = response,
            .opcode = opcode,
            .flags = flags,
            .Z = z,
            .rcode = rcode,
            .QCount = qcount,
            .ANCount = ancount,
            .NSCount = nscount,
            .ARCount = arcount,
        };
    }
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
        const raw_header = data[0..12];
        std.debug.print("{b:0>8}\n", .{raw_header});

        // const h = Header{
        //     .id = 2,
        //     .response = false,
        //     .opcode = Opcode.Query,
        //     .flags = Flags{ .RD = true },
        //     .Z = 0b010,
        //     .rcode = ResponseCode.NoError,
        //     .QCount = 1,
        //     .ANCount = 0,
        //     .NSCount = 0,
        //     .ARCount = 0,
        // };
        // std.debug.print("{b:0>8}\n", .{@as(u96, @bitCast(h))});

        const header: Header = Header.decode(raw_header);
        std.debug.print("{}\n", .{header});

        // const request: *Header = @alignCast(@ptrCast(header));

        // std.debug.print("{}\n", .{request});
        // std.debug.print("{b}\n", .{@as(u96, @bitCast(request))});
        // std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(data)});

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
