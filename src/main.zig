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

const FBType = std.io.FixedBufferStream([]const u8);

// TODO: make it proper packed struct, to be able to @bitCast it (and maybe @bitReverse before/after)
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

    pub fn decode(buf: *FBType) !Header {
        const reader = buf.reader();
        const id: u16 = try reader.readInt(u16, .big);

        var byte = try reader.readByte();
        const response: bool = byte & 0b10000000 == 1; // 1 bit
        const opcode: Opcode = @enumFromInt(@as(u4, @truncate(@shrExact(byte & 0b01111000, 3)))); // 4 bits

        const part: u8 = @shlExact(byte, 1);

        byte = try reader.readByte();
        const second_part: u8 = byte >> 7;

        const flags: Flags = @bitCast(@bitReverse(@as(u4, @truncate(part | second_part)))); // bit reverse is needed because of endian/order shenenigans, 4 bits

        const z: u3 = @as(u3, @truncate(@shrExact(byte & 0b01110000, 4))); // 3 bits

        const rcode: ResponseCode = @enumFromInt(@as(u4, @truncate(byte & 0b00001111))); // 4 bits

        const qcount: u16 = try reader.readInt(u16, .big);
        const ancount: u16 = try reader.readInt(u16, .big);
        const nscount: u16 = try reader.readInt(u16, .big);
        const arcount: u16 = try reader.readInt(u16, .big);

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

const Type = enum(u16) {
    // Regular types
    A = 1,
    NS = 2,
    MD = 3, // obsolete, use MX
    MF = 4, // obsolete, use MX
    CNAME = 5,
    SOA = 6,
    MB = 7, // experimental
    MG = 8, // experimental
    MR = 9, // experimental
    NULL = 10, // experimental
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,

    // Only appear in questions
    AXFR = 252,
    MAILB = 253,
    MAILA = 254, // obsolete, see MX
    @"*" = 255, // a request for all records

    _,
};

const Class = enum(u16) {
    // Regular classes
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,

    @"*" = 255, // a request for all classes

    _,
};

// TODO: add DoS protection - limit maximum jumps
// FIXME: leaks memory
pub fn decode_name(allocator: std.mem.Allocator, buf: *FBType) ![]const u8 {
    const reader = buf.reader();

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    while (true) {
        const length = try reader.readByte();
        if (length == 0) break; // null byte, end of label, break out

        if (length & 0b11000000 == 1) { // it's an offset
            try buf.seekBy(-1); // move back one byte
            const offset = try reader.readInt(u16, .big) ^ 0b11000000_00000000; // clean offset
            try buf.seekTo(offset); // move cursor to correct position
            continue; // start loop again
        }

        try result.appendSlice(buf.buffer[buf.pos .. buf.pos + length]);
        try result.append('.');

        try buf.seekBy(length); // move the cursor forward
    }

    return try result.toOwnedSlice();
}

const Question = struct {
    name: []const u8,
    type: Type,
    class: Class,

    pub fn decode(allocator: std.mem.Allocator, buf: *FBType) !Question {
        const reader = buf.reader();

        const name = try decode_name(allocator, buf);
        const @"type": Type = @enumFromInt(try reader.readInt(u16, .big));
        const class: Class = @enumFromInt(try reader.readInt(u16, .big));

        return .{
            .name = name,
            .type = @"type",
            .class = class,
        };
    }

    pub fn format(self: Question, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print("[Q: {s}, T: {}, C: {}]", .{ self.name, self.type, self.class });
    }
};

const ResourceRecord = struct {
    name: []const u8,
    type: Type,
    class: Class,
    ttl: i32,
    rdlength: u16,
    rdata: []const u8,
};

const RequestResponse = struct {
    header: Header,
    questions: []Question,
    // answer: []ResourceRecord,
    // authority: []ResourceRecord,
    // additional: []ResourceRecord,

    // FIXME: leaks memory
    pub fn decode(allocator: std.mem.Allocator, buf: []const u8) !RequestResponse {
        var bufStream = std.io.fixedBufferStream(buf);

        const header = try Header.decode(&bufStream);

        const questions = try allocator.alloc(Question, header.QCount);
        errdefer allocator.free(questions);

        for (0..header.QCount) |idx| {
            questions[idx] = try Question.decode(allocator, &bufStream);
        }

        return .{
            .header = header,
            .questions = questions,
        };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
        // const raw_header = data[0..12];
        // std.debug.print("{b:0>8}\n", .{raw_header});

        const rr: RequestResponse = try RequestResponse.decode(allocator, data);
        std.debug.print("{}\n", .{rr});

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
