const std = @import("std");

const ida = @cImport(@cInclude("ida.h"));

pub fn HackStream(T: type, Modder: type) type {
    return struct {
        stream: T,
        modder: *const Modder,

        const Self = @This();

        pub fn init(stream: T, modder: *const Modder) Self {
            return .{
                .stream = stream,
                .modder = modder,
            };
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
            ida.put_bytes(try self.modder.off_to_addr(pos), @ptrCast(bytes[0..res]), res);
            return res;
        }
    };
}
