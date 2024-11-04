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

    // FIXME: leaks memory
    pub fn decode(allocator: std.mem.Allocator, addr: u32) !RData {
        const a = (addr & 0xff000000) >> 24;
        const b = (addr & 0x00ff0000) >> 16;
        const c = (addr & 0x0000ff00) >> 8;
        const d = addr & 0x000000ff;

        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(allocator);

        const writer = result.writer(allocator);
        try writer.print("{d}.{d}.{d}.{d}", .{ a, b, c, d });

        const data = try result.toOwnedSlice(allocator);

        return .{ .A = .{ .ipv4 = data } };
    }

    pub fn format(self: AData, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print("{s}", .{self.ipv4});
    }
};

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
