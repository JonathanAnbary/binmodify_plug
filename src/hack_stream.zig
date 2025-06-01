const std = @import("std");

const ida = @cImport(@cInclude("ida.h"));

pub fn HackStream(Modder: type) type {
    return struct {
        file: *std.fs.File,
        modder: *const Modder,

        const Self = @This();

        pub const Writer = std.io.Writer(*Self, std.fs.File.WriteError || std.fs.File.SeekError || Modder.Error, write);

        pub fn init(file: *std.fs.File, modder: *const Modder) Self {
            return .{
                .file = file,
                .modder = modder,
            };
        }

        pub fn seekTo(self: *Self, pos: u64) !void {
            try self.file.seekTo(pos);
        }

        pub fn seekBy(self: *Self, pos: i64) !void {
            try self.file.seekBy(pos);
        }

        pub fn read(self: *Self, dest: []u8) !usize {
            return self.file.read(dest);
        }

        pub fn getPos(self: *Self) !u64 {
            return self.file.getPos();
        }

        pub fn getEndPos(self: *Self) !u64 {
            return self.file.getEndPos();
        }

        pub fn write(self: *Self, bytes: []const u8) !usize {
            const pos = try self.file.getPos();
            const res = try self.file.write(bytes);
            ida.put_bytes(@intCast(try self.modder.off_to_addr(pos)), @ptrCast(bytes[0..res]), res);
            return res;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}
