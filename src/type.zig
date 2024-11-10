const std = @import("std");

pub const Type = enum(u16) {
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

pub const AData = struct {
    ipv4: []const u8,

    /// The caller must call deinit().
    pub fn decode(allocator: std.mem.Allocator, addr: u32) !RData {
        const data = try AData.decode_ipv4(allocator, addr);

        return .{ .A = .{ .ipv4 = data } };
    }

    pub fn deinit(self: *AData, allocator: std.mem.Allocator) void {
        allocator.free(self.ipv4);
    }

    pub fn decode_ipv4(allocator: std.mem.Allocator, addr: u32) ![]const u8 {
        const a = (addr & 0xff000000) >> 24;
        const b = (addr & 0x00ff0000) >> 16;
        const c = (addr & 0x0000ff00) >> 8;
        const d = addr & 0x000000ff;

        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(allocator);

        const writer = result.writer(allocator);
        try writer.print("{d}.{d}.{d}.{d}", .{ a, b, c, d });

        const data = try result.toOwnedSlice(allocator);

        return data;
    }

    pub fn encode_ipv4(ipv4: []const u8) !u32 {
        var it = std.mem.splitScalar(u8, ipv4, '.');
        var addr: u32 = 0;
        var shift_amt: u5 = 24;
        while (it.next()) |part| : (shift_amt -= 8) {
            const num = try std.fmt.parseUnsigned(u32, part, 10);
            addr |= num << shift_amt;
            if (shift_amt == 0) break;
        }
        return addr;
    }

    pub fn format(self: AData, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;

        if (comptime std.mem.eql(u8, fmt, "w")) {
            const addr = try AData.encode_ipv4(self.ipv4);
            try writer.writeInt(u32, addr, .big);
        } else {
            try writer.print("{s}", .{self.ipv4});
        }
    }
};

test "encode_ipv4" {
    try std.testing.expectEqual(2130706433, try AData.encode_ipv4("127.0.0.1"));
    try std.testing.expectEqual(4294967295, try AData.encode_ipv4("255.255.255.255"));
}

test "decode_ipv4" {
    const allocator = std.testing.allocator;

    var ipv4 = try AData.decode_ipv4(allocator, 2130706433);
    try std.testing.expectEqualStrings("127.0.0.1", ipv4);
    allocator.free(ipv4);

    ipv4 = try AData.decode_ipv4(allocator, 4294967295);
    try std.testing.expectEqualStrings("255.255.255.255", ipv4);
    allocator.free(ipv4);
}

pub const RData = union(Type) {
    A: AData,
    NS: struct {},
    MD: struct {},
    MF: struct {},
    CNAME: struct {},
    SOA: struct {},
    MB: struct {},
    MG: struct {},
    MR: struct {},
    NULL: struct {},
    WKS: struct {},
    PTR: struct {},
    HINFO: struct {},
    MINFO: struct {},
    MX: struct {},
    TXT: struct {},

    AXFR: struct {},
    MAILB: struct {},
    MAILA: struct {},
    @"*": struct {},
};
