const std = @import("std");
const builtin = @import("builtin");
const ida = @cImport(@cInclude("ida.h"));

const hack_stream = @import("hack_stream.zig");

const binmodify = @import("binmodify");

const ElfModder = binmodify.ElfModder;
const CoffModder = binmodify.CoffModder;
const common = binmodify.common;

pub fn Modder(T: type) type {
    return struct {
        modder: T,

        const Self = @This();
        pub const Error = error{
            AdjustSegmFailed,
        } || T.Error;
        const Edge = if (T == ElfModder) ElfModder.SegEdge else if (T == CoffModder) CoffModder.SecEdge else unreachable;

        pub fn init(gpa: std.mem.Allocator, parsed: anytype, reader: anytype) !Self {
            return .{
                .modder = try T.init(gpa, parsed, reader),
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.modder.deinit(gpa);
        }

        pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: common.FileRangeFlags) Error!?Edge {
            return self.modder.get_cave_option(wanted_size, flags);
        }

        pub fn create_cave(self: *Self, size: u64, edge: Edge, stream: anytype) Error!void {
            // this is the segment start if edge.is_end == false else segment end.
            const old_addr = try self.modder.off_to_addr(self.modder.cave_to_off(edge, 1));
            try self.modder.create_cave(size, edge, stream.stream);
            if (edge.is_end) {
                if (!ida.set_segm_end(@intCast(old_addr), @intCast(try self.modder.off_to_addr(self.modder.cave_to_off(edge, 1))), 0)) return Error.AdjustSegmFailed;
            } else {
                if (!ida.set_segm_start(@intCast(old_addr), @intCast(try self.modder.off_to_addr(self.modder.cave_to_off(edge, 1))), 0)) return Error.AdjustSegmFailed;
            }
        }

        pub fn addr_to_off(self: *const Self, addr: u64) Error!u64 {
            return self.modder.addr_to_off(addr);
        }

        pub fn off_to_addr(self: *const Self, off: u64) Error!u64 {
            return self.modder.off_to_addr(off);
        }
        pub fn cave_to_off(self: Self, cave: Edge, size: u64) u64 {
            return self.modder.cave_to_off(cave, size);
        }
    };
}
