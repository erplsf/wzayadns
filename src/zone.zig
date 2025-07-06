const std = @import("std");

const T = @import("type.zig");
const M = @import("main.zig");

pub const Zone = struct {};

pub const ZoneParsingError = error{
    SecondFieldIsNotATTLNorAClass,
    ThirdFieldIsNotATTL,
    ThirdFieldIsNotAClass,
    FourthFieldIsNotAType,
};

/// Caller owns returned memory.
pub fn get_next_entry(allocator: std.mem.Allocator, reader: anytype) !?[]u8 {
    const maybe_line = reader.readUntilDelimiterAlloc(allocator, '\n', 1024);
    if (maybe_line) |line| {
        defer allocator.free(line);

        if (line.len == 0) return line; // it's safe to return (and free) a zero-sized slice

        var buffer = std.ArrayListUnmanaged(u8){};
        defer buffer.deinit(allocator);

        const writer = buffer.writer(allocator);

        const maybe_comment = std.mem.indexOfScalar(u8, line, ';');
        var clean_line: []u8 = undefined;
        clean_line = if (maybe_comment) |pos| line[0..pos] else line[0..]; // if the semicolon is present, trim the line to exclude it for the ser

        try writer.writeAll(clean_line);

        if (std.mem.indexOfScalar(u8, clean_line, '(')) |_| { // if there's an opening bracket present, read the file until we find the closing bracket
            while (true) {
                const next_line = try reader.readUntilDelimiterAlloc(allocator, '\n', 1024);
                defer allocator.free(next_line);

                var next_clean_line: []u8 = undefined;
                const maybe_comment_next_line = std.mem.indexOfScalar(u8, next_line, ';');
                next_clean_line = if (maybe_comment_next_line) |pos| next_line[0..pos] else next_line[0..];

                try writer.writeAll(next_clean_line);

                if (std.mem.indexOfScalar(u8, next_clean_line, ')')) |_| break;
            }
        }

        // std.debug.print("{s}\n", .{buffer.items});

        std.mem.replaceScalar(u8, buffer.items, '(', ' ');
        std.mem.replaceScalar(u8, buffer.items, ')', ' ');

        const collapsed = std.mem.collapseRepeats(u8, buffer.items, ' '); // collapse whitespace

        return try allocator.dupe(u8, collapsed);
    } else |err| switch (err) {
        error.EndOfStream => {
            return null;
        },
        else => {
            return err;
        },
    }
}

pub fn parse_zone_file(allocator: std.mem.Allocator, path: []const u8) !Zone {
    const zone: Zone = .{};

    const file = try std.fs.cwd().openFile(path, .{});
    const reader = file.reader();

    var count: usize = 0;
    while (try get_next_entry(allocator, reader)) |entry| : (allocator.free(entry)) {
        if (entry.len == 0) continue;

        count += 1;

        var it = std.mem.splitScalar(u8, entry, ' ');

        var name: []const u8 = undefined;
        if (it.next()) |n| {
            name = n;
        }

        var ttl_found: bool = false;
        var class_found: bool = false;

        var ttl: usize = undefined;
        var class: M.Class = undefined;

        if (it.next()) |ttl_or_class| {
            const maybe_ttl = std.fmt.parseUnsigned(usize, ttl_or_class, 10);
            if (maybe_ttl) |t| {
                ttl = t;
                ttl_found = true;
            } else |_| {
                const maybe_class = std.meta.stringToEnum(M.Class, ttl_or_class);
                if (maybe_class) |c| {
                    class = c;
                    class_found = true;
                } else {
                    return ZoneParsingError.SecondFieldIsNotATTLNorAClass;
                }
            }
        }

        if (it.next()) |ttl_or_class| {
            if (ttl_found) {
                const maybe_class = std.meta.stringToEnum(M.Class, ttl_or_class);
                if (maybe_class) |c| {
                    class = c;
                } else {
                    return ZoneParsingError.ThirdFieldIsNotAClass;
                }
            } else { // it's definitely a ttl
                const maybe_ttl = std.fmt.parseUnsigned(usize, ttl_or_class, 10);
                if (maybe_ttl) |t| {
                    ttl = t;
                } else |_| {
                    return ZoneParsingError.ThirdFieldIsNotATTL;
                }
            }
        }

        var @"type": T.Type = undefined;
        if (it.next()) |t| {
            const maybe_type = std.meta.stringToEnum(T.Type, t);
            if (maybe_type) |tt| {
                @"type" = tt;
            } else {
                return ZoneParsingError.FourthFieldIsNotAType;
            }
        }

        std.debug.print("rest: {s}\n", .{it.rest()});

        std.debug.print("entry: {s}\n", .{entry});
        std.debug.print("name: {s}, class: {}, type: {}, ttl: {d}\n", .{ name, class, @"type", ttl });
    }

    return zone;
}
