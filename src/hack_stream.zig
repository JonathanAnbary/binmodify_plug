const std = @import("std");

pub fn HackStream(T: type) type {
    return struct {
        stream: T,
        // TODO: change this once you figure out the sdk, no reason this should allocate.
        write_record: std.ArrayListUnmanaged(WriteRecord),
        alloc: std.mem.Allocator,

        const Self = @This();

        pub const WriteRecord = struct {
            bytes: []const u8,
            pos: u64,
        };

        pub fn init(stream: T, alloc: std.mem.Allocator) Self {
            return .{
                .stream = stream,
                .write_record = std.ArrayListUnmanaged(WriteRecord){},
                .alloc = alloc,
            };
        }

        pub fn deinit(self: *Self) void {
            self.write_record.deinit(self.alloc);
        }

        pub fn seekTo(self: *Self, pos: u64) !void {
            try self.stream.seekTo(pos);
        }

        pub fn seekBy(self: *Self, pos: u64) !void {
            try self.stream.seekBy(pos);
        }

        pub fn read(self: *Self, dest: []u8) !usize {
            return self.stream.read(dest);
        }

        pub fn getPos(self: *Self) !u64 {
            return self.stream.getPos();
        }

        pub fn getEndPos(self: *Self) !u64 {
            return self.stream.getEndPos();
        }

        pub fn write(self: *Self, bytes: []const u8) !usize {
            const pos = try self.stream.getPos();
            const res = try self.stream.write(bytes);
            try self.write_record.append(self.alloc, .{
                .bytes = try self.alloc.dupe(u8, bytes[0..res]),
                .pos = pos,
            });
            return res;
        }
    };
}
