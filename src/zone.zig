const std = @import("std");

pub const Zone = struct {};

pub fn parse_zone_file(path: []const u8) !Zone {
    _ = path;
    const zone: Zone = .{};
    return zone;
}
