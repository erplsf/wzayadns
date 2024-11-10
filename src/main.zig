const std = @import("std");
const net = std.net;
const posix = std.posix;

const dns_type = @import("type.zig");
const Type = dns_type.Type;
const AData = dns_type.AData;
const RData = dns_type.RData;

const Opcode = enum(u4) {
    Query = 0,
    InverseQuery = 1,
    ServerStatusRequest = 2,
    _, // all other values (3-15) are reserved for future use
};

const Flags = packed struct(u4) {
    AA: bool = false, // Authorative Answer
    TC: bool = false, // TrunCation
    RD: bool = false, // Recursion Desired
    RA: bool = false, // Recursion Available
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
        const opcode: Opcode = @enumFromInt(@as(u4, @truncate((byte & 0b01111000) >> 3))); // 4 bits

        const part: u8 = byte << 1;

        byte = try reader.readByte();
        const second_part: u8 = byte >> 7;

        const flags: Flags = @bitCast(@bitReverse(@as(u4, @truncate(part | second_part)))); // bit reverse is needed because of endian/order shenenigans, 4 bits

        const z: u3 = @as(u3, @truncate((byte & 0b01110000) >> 4)); // 3 bits

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

    pub fn encode(self: Header, allocator: std.mem.Allocator, writer: anytype) !void {
        _ = allocator;

        try writer.writeInt(u16, self.id, .big); // write id, 16 bits

        var first_part: u8 = 0;
        var second_part: u8 = 0;
        first_part |= @as(u8, @intCast(@as(u1, @bitCast(self.response)))) << 7; // 1 bit
        first_part |= @as(u8, @intFromEnum(self.opcode)) << 3; // 4 bits
        first_part |= @as(u8, @bitReverse(@as(u4, @bitCast(self.flags)))) >> 1; // 3 bits of flags go into first byte
        second_part |= @as(u8, @bitReverse(@as(u4, @bitCast(self.flags)))) << 7; // 1 bits of flags go into second byte
        second_part |= @as(u8, @intCast(@as(u3, @bitCast(self.Z)))) << 4; // 3 bits
        second_part |= @as(u8, @intFromEnum(self.rcode)); // 4 bits
        try writer.writeByte(first_part);
        try writer.writeByte(second_part);

        try writer.writeInt(u16, self.QCount, .big);
        try writer.writeInt(u16, self.ANCount, .big);
        try writer.writeInt(u16, self.NSCount, .big);
        try writer.writeInt(u16, self.ARCount, .big);
    }

    // pub fn format(self: Header, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    //     _ = options;

    //     if (comptime std.mem.eql(u8, fmt, "w")) {} else {
    //         const kind = if (self.response) "RS" else "RQ";
    //         try writer.print("Header{{ID: {}, RQ/RS: {s}, OP: {}, FL: {}, Z: {}, RC: {}, QC: {}, ANC: {}, NSC: {}, ARC: {}}}", .{
    //             self.id,
    //             kind,
    //             self.opcode,
    //             self.flags,
    //             self.Z,
    //             self.rcode,
    //             self.QCount,
    //             self.ANCount,
    //             self.NSCount,
    //             self.ARCount,
    //         });
    //     }
    // }
};

test "header decodes/encodes to the same byte sequence" {
    const raw_header: []const u8 = &[_]u8{
        0xee, 0x9c, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    var fb = std.io.fixedBufferStream(raw_header);

    const allocator = std.testing.allocator;

    var list = std.ArrayListUnmanaged(u8){};
    defer list.deinit(allocator);

    const writer = list.writer(allocator);

    const header = try Header.decode(&fb);
    try header.encode(allocator, writer);

    try std.testing.expectEqualSlices(u8, raw_header, list.items);
}

const Class = enum(u16) {
    // Regular classes
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,

    @"*" = 255, // a request for all classes

    _,
};

const NameParsingError = error{
    NameTooLong,
    JumpForwardPresent,
    SameJumpEncountered,
};

// TODO: add more protections from another RFC document: https://datatracker.ietf.org/doc/rfc9267/
// implemented checks:
// * name length validation
// * loops detection
// * prevention of forward jumps
/// The caller owns the returned memory.
pub fn decode_name(allocator: std.mem.Allocator, buf: *FBType) ![]const u8 {
    const reader = buf.reader();

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var encountered_jumps = std.ArrayListUnmanaged(u16){};
    defer encountered_jumps.deinit(allocator);

    var ret_address: usize = 0; // HACK: jump address itself can be possibly zero, but i use zero here to determine base case
    while (true) {
        const length = try reader.readByte();
        if (length == 0) break; // null byte, end of label, break out

        if (length & 0b11000000 == 0b11000000) { // it's an offset / compression pointer
            try buf.seekBy(-1); // move back one byte
            const offset = try reader.readInt(u16, .big) ^ 0b11000000_00000000; // clean offset

            if (offset > try buf.getPos()) return NameParsingError.JumpForwardPresent;

            if (std.mem.indexOfScalar(u16, encountered_jumps.items, offset)) |_| {
                return NameParsingError.SameJumpEncountered;
            }

            ret_address = try buf.getPos(); // save return address
            try buf.seekTo(offset); // move cursor to correct position
            try encountered_jumps.append(allocator, offset);

            continue; // start loop again
        }

        try result.appendSlice(buf.buffer[buf.pos .. buf.pos + length]);
        try result.append('.');

        if (result.items.len > 255) return NameParsingError.NameTooLong;

        try buf.seekBy(length); // move the cursor forward
    }

    if (ret_address != 0)
        try buf.seekTo(ret_address); // if we jumped, return to after the jump

    return try result.toOwnedSlice();
}

test "decodes simple name" {
    const raw_name: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
    };
    const name: []const u8 = "www.google.com.";

    var fb = std.io.fixedBufferStream(raw_name);

    const allocator = std.testing.allocator;

    const decoded_name = try decode_name(allocator, &fb);
    defer allocator.free(decoded_name);

    try std.testing.expectEqualStrings(name, decoded_name);
}

test "decodes names with a pointer" {
    const raw_name: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0b11000000, 0b00000000, // www.google.com.
        0b11000000, 0b00000100, // google.com.
        0b11000000, 0b00001011, // com.
    };

    var fb = std.io.fixedBufferStream(raw_name);

    const allocator = std.testing.allocator;

    try fb.seekTo(raw_name.len - 6);
    var decoded_name = try decode_name(allocator, &fb);
    try std.testing.expectEqualStrings("www.google.com.", decoded_name);
    allocator.free(decoded_name);

    try fb.seekTo(raw_name.len - 4);
    decoded_name = try decode_name(allocator, &fb);
    try std.testing.expectEqualStrings("google.com.", decoded_name);
    allocator.free(decoded_name);

    try fb.seekTo(raw_name.len - 2);
    decoded_name = try decode_name(allocator, &fb);
    try std.testing.expectEqualStrings("com.", decoded_name);
    allocator.free(decoded_name);
}

test "decode errors" {
    const raw_name: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0b11111111, 0b00000000, // jump forward
        0b11000000, 18, // loop
    };
    const too_long_name: []const u8 = ((&[_]u8{63} ++ &[_]u8{'o'} ** 63) ** 4) ++ &[_]u8{0};

    var fb = std.io.fixedBufferStream(raw_name);
    var fb_too_long = std.io.fixedBufferStream(too_long_name);

    const allocator = std.testing.allocator;

    try fb.seekTo(16);
    try std.testing.expectError(
        NameParsingError.JumpForwardPresent,
        decode_name(allocator, &fb),
    );

    try fb.seekTo(18);
    try std.testing.expectError(
        NameParsingError.SameJumpEncountered,
        decode_name(allocator, &fb),
    );

    try std.testing.expectError(
        NameParsingError.NameTooLong,
        decode_name(allocator, &fb_too_long),
    );
}

/// The caller owns the returned memory.
pub fn encode_name(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    var result = std.ArrayListUnmanaged(u8){};
    errdefer result.deinit(allocator);

    const writer = result.writer(allocator);

    var it = std.mem.splitScalar(u8, name, '.');

    var last_len: usize = 0;

    while (it.next()) |part| {
        try writer.writeInt(u8, @intCast(part.len), .big);
        try writer.writeAll(part);
        last_len = part.len;
    }

    if (last_len != 0) { // if the user didn't provide a dot at the end, append the end of the name of an empty byte
        try writer.writeByte(0x0);
    }

    return try result.toOwnedSlice(allocator);
}

test "encodes simple name" {
    const raw_name: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
    };
    const name: []const u8 = "www.google.com.";

    const allocator = std.testing.allocator;

    const encoded_name = try encode_name(allocator, name);
    defer allocator.free(encoded_name);

    try std.testing.expectEqualSlices(u8, raw_name, encoded_name);
}

const Question = struct {
    name: []const u8,
    type: Type,
    class: Class,

    /// The caller must call deinit().
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

    pub fn encode(self: Question, allocator: std.mem.Allocator, writer: anytype) !void {
        const name = try encode_name(allocator, self.name);
        defer allocator.free(name);

        try writer.writeAll(name);
        try writer.writeInt(u16, @intFromEnum(self.type), .big);
        try writer.writeInt(u16, @intFromEnum(self.class), .big);
    }

    pub fn deinit(self: *Question, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }

    // pub fn format(self: Question, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    //     _ = options;

    //     if (comptime std.mem.eql(u8, fmt, "w")) {
    //     } else {
    //         try writer.print("[Q: {s}, T: {}, C: {}]", .{ self.name, self.type, self.class });
    //     }
    // }
};

test "decodes question" {
    const raw_question: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1, // type A
        0, 1, // class IN
    };

    var fb = std.io.fixedBufferStream(raw_question);

    const allocator = std.testing.allocator;

    var q = try Question.decode(allocator, &fb);
    defer q.deinit(allocator);

    try std.testing.expectEqualStrings("www.google.com.", q.name);
    try std.testing.expectEqual(Type.A, q.type);
    try std.testing.expectEqual(Class.IN, q.class);
}

test "encodes simple question" {
    const raw_question: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 6, // type SOA
        0, 1, // class IN
    };

    var q: Question = Question{ .name = "www.google.com.", .type = .SOA, .class = .IN };

    const allocator = std.testing.allocator;
    var r = std.ArrayListUnmanaged(u8){};
    defer r.deinit(allocator);

    const writer = r.writer(allocator);
    try q.encode(allocator, writer);

    try std.testing.expectEqualSlices(u8, raw_question, r.items);
}

const ResourceRecord = struct {
    name: []const u8,
    type: Type, // 16 bits
    class: Class, // 16 bits
    ttl: u32,
    rdlength: u16,
    rdata: RData,

    /// The caller must call deinit().
    pub fn decode(allocator: std.mem.Allocator, buf: *FBType) !ResourceRecord {
        const reader = buf.reader();

        const name = try decode_name(allocator, buf);
        const @"type": Type = @enumFromInt(try reader.readInt(u16, .big));
        const class: Class = @enumFromInt(try reader.readInt(u16, .big));
        const ttl: u32 = try reader.readInt(u32, .big);
        const rdlength = try reader.readInt(u16, .big);

        var rdata: RData = undefined;

        switch (@"type") {
            .A => {
                const addr = try reader.readInt(u32, .big);
                rdata = try AData.decode(allocator, addr);
            },
            else => {
                // return error.CannotHandleThisDnsType;
            },
        }

        return .{
            .name = name,
            .type = @"type",
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = rdata,
        };
    }

    pub fn deinit(self: *ResourceRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);

        switch (self.rdata) {
            inline else => |*d| {
                const T = @TypeOf(d.*);
                if (std.meta.hasFn(T, "deinit")) {
                    d.deinit(allocator);
                }
            },
        }
    }

    // FIXME: leaks memory
    pub fn build(allocator: std.mem.Allocator) void {
        _ = allocator;
    }

    pub fn encode(self: ResourceRecord, allocator: std.mem.Allocator, writer: anytype) !void {
        const name = try encode_name(allocator, self.name);
        defer allocator.free(name);

        try writer.writeAll(name);
        try writer.writeInt(u16, @intFromEnum(self.type), .big);
        try writer.writeInt(u16, @intFromEnum(self.class), .big);
        try writer.writeInt(u32, self.ttl, .big);
        try writer.writeInt(u16, 4, .big); // FIXME: hardcoded size for this type
        try writer.print("{w}", .{self.rdata.A}); // FIXME: hardcoded union type
    }

    // HACK: doesn't do compression
    // pub fn format(self: ResourceRecord, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    //     _ = options;

    //     if (comptime std.mem.eql(u8, fmt, "w")) {} else {
    //         try writer.print("[N: {s}, T: {}, C: {}, TTL: {d}, RDL: {d}: RD: {}]", .{ self.name, self.type, self.class, self.ttl, self.rdlength, self.rdata });
    //     }
    // }
};

test "decodes RR" {
    const raw_rr: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1, // type A
        0, 1, // class IN
        0, 0, 0b1, 0b00101100, // ttl 300 s
        0,    4, // RDATA length
        0x7F, 0,
        0,
        0x01, // 127.0.0.1
    };

    var fb = std.io.fixedBufferStream(raw_rr);

    const allocator = std.testing.allocator;
    var rr = try ResourceRecord.decode(allocator, &fb);
    defer rr.deinit(allocator);

    try std.testing.expectEqualStrings("www.google.com.", rr.name);
    try std.testing.expectEqual(.A, rr.type);
    try std.testing.expectEqual(.IN, rr.class);
    try std.testing.expectEqual(300, rr.ttl);
    try std.testing.expectEqualStrings("127.0.0.1", rr.rdata.A.ipv4);
}

test "encodes RR" {
    const rr = ResourceRecord{ .name = "www.google.com.", .type = .SOA, .class = .IN, .ttl = 300, .rdlength = 4, .rdata = .{ .A = .{ .ipv4 = "127.127.127.127" } } };

    const allocator = std.testing.allocator;
    var r = std.ArrayListUnmanaged(u8){};
    defer r.deinit(allocator);

    const writer = r.writer(allocator);

    try rr.encode(allocator, writer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 6, // type SOA
        0, 1, // class IN
        0, 0, 0b1, 0b00101100, // ttl 300 s
        0,    4, // RDATA length
        0x7F, 0x7F,
        0x7F, 0x7F, // 127.0.0.1
    }, r.items);
}

const RequestResponse = struct {
    allocator: std.mem.Allocator,

    header: Header,
    questions: []Question,
    answers: std.ArrayListUnmanaged(ResourceRecord),
    authorities: []ResourceRecord,
    additionals: []ResourceRecord,

    /// The caller must call deinit().
    pub fn decode(allocator: std.mem.Allocator, buf: []const u8) !RequestResponse {
        var bufStream = std.io.fixedBufferStream(buf);

        const header = try Header.decode(&bufStream);

        const questions = try allocator.alloc(Question, header.QCount);
        errdefer allocator.free(questions);

        var answers = try std.ArrayListUnmanaged(ResourceRecord).initCapacity(allocator, header.ANCount);
        errdefer answers.deinit(allocator);

        const authorities = try allocator.alloc(ResourceRecord, header.NSCount);
        errdefer allocator.free(authorities);

        const additionals = try allocator.alloc(ResourceRecord, header.ARCount);
        errdefer allocator.free(additionals);

        for (0..header.QCount) |idx| {
            questions[idx] = try Question.decode(allocator, &bufStream);
        }

        for (0..header.ANCount) |_| {
            try answers.append(allocator, try ResourceRecord.decode(allocator, &bufStream));
        }

        for (0..header.NSCount) |idx| {
            authorities[idx] = try ResourceRecord.decode(allocator, &bufStream);
        }

        for (0..header.ARCount) |idx| {
            additionals[idx] = try ResourceRecord.decode(allocator, &bufStream);
        }

        return .{
            .allocator = allocator,
            .header = header,
            .questions = questions,
            .answers = answers,
            .authorities = authorities,
            .additionals = additionals,
        };
    }

    pub fn encode(self: RequestResponse, writer: anytype) !void {
        try self.header.encode(self.allocator, writer);
        for (self.questions) |i| {
            try i.encode(self.allocator, writer);
        }
        for (self.answers.items) |i| {
            try i.encode(self.allocator, writer);
        }
        for (self.authorities) |i| {
            try i.encode(self.allocator, writer);
        }
        for (self.additionals) |i| {
            try i.encode(self.allocator, writer);
        }
    }

    pub fn deinit(self: *RequestResponse) void {
        for (self.questions) |*i| i.deinit(self.allocator);
        self.allocator.free(self.questions);

        for (self.answers.items) |*i| i.deinit(self.allocator);
        self.answers.deinit(self.allocator);

        for (self.authorities) |*i| i.deinit(self.allocator);
        self.allocator.free(self.authorities);

        for (self.additionals) |*i| i.deinit(self.allocator);
        self.allocator.free(self.additionals);
    }

    pub fn addAnswer(self: *RequestResponse, record: ResourceRecord) !void {
        try self.answers.append(self.allocator, record);
    }

    // pub fn format(self: RequestResponse, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    //     _ = options;

    //     if (comptime std.mem.eql(u8, fmt, "w")) {} else {
    //         try writer.print("{}", .{self.header});
    //         for (self.questions) |i| {
    //             try writer.print("{}", .{i});
    //         }
    //         for (self.answers.items) |i| {
    //             try writer.print("{}", .{i});
    //         }
    //         for (self.authorities) |i| {
    //             try writer.print("{}", .{i});
    //         }
    //         for (self.additionals) |i| {
    //             try writer.print("{}", .{i});
    //         }
    //     }
    // }
};

test "decodes request" {
    const raw_request: []const u8 = &[_]u8{ 0xee, 0x9c, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };

    const allocator = std.testing.allocator;

    var rr = try RequestResponse.decode(allocator, raw_request);
    defer rr.deinit();

    const raw_question: []const u8 = &[_]u8{
        3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1, // type A
        0, 1, // class IN
    };

    var fb = std.io.fixedBufferStream(raw_question);

    var q = try Question.decode(allocator, &fb);
    defer q.deinit(allocator);

    var qs = try allocator.alloc(Question, 1);
    defer allocator.free(qs);
    qs[0] = q;

    const r: RequestResponse = .{
        .allocator = allocator,
        .header = .{ .id = 61084, .response = false, .opcode = .Query, .flags = .{ .AA = false, .TC = false, .RD = true, .RA = false }, .Z = 2, .rcode = .NoError, .QCount = 1, .ANCount = 0, .NSCount = 0, .ARCount = 0 },
        .questions = qs,
        .answers = std.ArrayListUnmanaged(ResourceRecord){},
        .authorities = &[_]ResourceRecord{},
        .additionals = &[_]ResourceRecord{},
    };

    try std.testing.expectEqualDeep(r.header, rr.header);
    try std.testing.expectEqualDeep(r.questions, qs);
    try std.testing.expectEqual(@as(u16, 0), r.answers.items.len);
    try std.testing.expectEqual(@as(u16, 0), r.authorities.len);
    try std.testing.expectEqual(@as(u16, 0), r.additionals.len);
}

test "encodes response" {
    const allocator = std.testing.allocator;

    const raw_question: []const u8 = &[_]u8{
        6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1, // type A
        0, 1, // class IN
    };

    var fb = std.io.fixedBufferStream(raw_question);

    var q = try Question.decode(allocator, &fb);
    defer q.deinit(allocator);

    var qs = try allocator.alloc(Question, 1);
    defer allocator.free(qs);

    qs[0] = q;

    var r: RequestResponse = .{
        .allocator = allocator,
        .header = .{ .id = 61084, .response = true, .opcode = .Query, .flags = .{ .AA = true, .TC = false, .RD = false, .RA = false }, .Z = 0, .rcode = .NoError, .QCount = 1, .ANCount = 1, .NSCount = 0, .ARCount = 0 },
        .questions = qs,
        .answers = std.ArrayListUnmanaged(ResourceRecord){},
        .authorities = &[_]ResourceRecord{},
        .additionals = &[_]ResourceRecord{},
    };
    defer r.answers.deinit(allocator);

    try r.addAnswer(.{
        .name = "google.com.",
        .type = .A,
        .class = .IN,
        .ttl = 300,
        .rdlength = 4,
        .rdata = .{ .A = .{ .ipv4 = "127.0.0.1" } },
    });

    const raw_response: []const u8 = &[_]u8{
        0xee, 0x9c, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01,
    };

    var re = std.ArrayListUnmanaged(u8){};
    defer re.deinit(allocator);

    const writer = re.writer(allocator);

    try r.encode(writer);

    try std.testing.expectEqualSlices(u8, raw_response, re.items);
}

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

    var request_buffer: [512]u8 = undefined;
    var response_buffer: [512]u8 = undefined;

    while (true) {
        var client_address: net.Address = undefined;
        var client_address_len: posix.socklen_t = @sizeOf(net.Address);

        const read = posix.recvfrom(socket, &request_buffer, 0, &client_address.any, &client_address_len) catch |err| {
            std.debug.print("error reading: {}\n", .{err});
            continue;
        };

        if (read == 0) {
            continue;
        }

        std.debug.print("[{}] -> ", .{client_address});

        const request = request_buffer[0..read];

        var rr: RequestResponse = try RequestResponse.decode(allocator, request);
        std.debug.print("{}\n", .{rr});

        rr.header.response = true;
        rr.header.flags = .{ .AA = true };
        rr.header.Z = 0;
        rr.header.ANCount = 1;

        const adata: AData = AData{ .ipv4 = "66.66.66.66" };
        const record: ResourceRecord = ResourceRecord{ .class = .IN, .type = .A, .ttl = 300, .name = rr.questions[0].name, .rdlength = 4, .rdata = .{ .A = adata } };

        try rr.addAnswer(record);
        std.debug.print("{}\n", .{rr});

        var stream = std.io.fixedBufferStream(response_buffer[0..]);
        const writer = stream.writer();

        try rr.encode(writer);

        _ = posix.sendto(socket, stream.getWritten(), 0, &client_address.any, client_address_len) catch |err| {
            std.debug.print("error writing: {}\n", .{err});
            continue;
        };

        // std.debug.print("wrote: {d}\n", .{wrote});

        // if (wrote != read) {
        //     std.debug.print("couldn't write the whole response back, exiting!", .{});
        //     break;
        // }
    }
}

test {
    _ = @import("type.zig");
}

// TODO: add errors for other/unsupported types/classes
