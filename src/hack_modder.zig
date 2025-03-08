const std = @import("std");
const builtin = @import("builtin");
const ida = @cImport(@cInclude("ida.h"));

const hack_stream = @import("hack_stream.zig");

const binmodify = @import("binmodify");

const patch = binmodify.patch;
const ElfModder = binmodify.ElfModder;
const CoffModder = binmodify.CoffModder;
const ElfParsed = binmodify.ElfParsed;
const CoffParsed = binmodify.CoffParsed;
const common = binmodify.common;

pub fn Modder(T: type) type {
    return struct {
        modder: T,

        const Self = @This();
        const Error = error{
            AdjustSegmFailed,
        } || ElfModder.Error || CoffModder.Error;
        const Edge = if (T == ElfModder) ElfModder.SegEdge else if (T == CoffModder) CoffModder.SecEdge else unreachable;

        pub fn init(gpa: std.mem.Allocator, parsed: if (T == ElfModder) *const ElfParsed else if (T == CoffModder) *const CoffParsed else unreachable, stream: anytype) !Self {
            return .{
                .modder = try T.init(gpa, parsed, stream),
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

test "elf Modder create cave same output" {
    if (builtin.os.tag != .linux) {
        error.SkipZigTest;
    }
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave = "./hack_modder_create_cave_same_output_elf";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_cave[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    // check regular output.
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        var f = try cwd.openFile(test_with_cave, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        var hacked_stream = hack_stream.HackStream(*std.io.StreamSource).init(&stream, std.testing.allocator);
        defer hacked_stream.deinit();
        const wanted_size = 0xfff;
        const parsed = try ElfParsed.init(&stream);
        var elf_hack_modder: Modder(ElfModder) = try Modder(ElfModder).init(std.testing.allocator, &parsed, &hacked_stream);
        defer elf_hack_modder.deinit(std.testing.allocator);
        const option = (try elf_hack_modder.get_cave_option(wanted_size, common.FileRangeFlags{ .execute = true, .read = true })) orelse return error.NoCaveOption;
        try elf_hack_modder.create_cave(wanted_size, option, &hacked_stream);
        try std.testing.expectEqual(elf_hack_modder.cave_change, Modder(ElfModder).CaveChange{ .is_end = false, .old_addr = 0x1001B34, .new_addr = 0x1000B35 });
    }

    // check output with a cave
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term.Exited == no_cave_result.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
}
