const std = @import("std");

const binmodify = @import("binmodify");

const ida = @cImport(@cInclude("ida.h"));

const patch = binmodify.patch;
const ElfModder = binmodify.ElfModder;
const CoffModder = binmodify.CoffModder;
const ElfParsed = binmodify.ElfParsed;
const CoffParsed = binmodify.CoffParsed;

const hack_modder = @import("hack_modder.zig");
const hack_stream = @import("hack_stream.zig");
const IdaDisasm = @import("IdaDisasm.zig");

fn add_func_tail(addr: u64, start: u64, size: u64) void {
    const func = ida.get_func(@intCast(addr));
    _ = ida.append_func_tail(func, @intCast(start), @intCast(start + size));
}

const IdaElfModder = hack_modder.Modder(ElfModder);
const IdaElfPatcher = patch.Patcher(IdaElfModder, IdaDisasm);
const IdaElfStream = hack_stream.HackStream(*std.fs.File, IdaElfModder);

const IdaCoffModder = hack_modder.Modder(CoffModder);
const IdaCoffPatcher = patch.Patcher(IdaCoffModder, IdaDisasm);
const IdaCoffStream = hack_stream.HackStream(*std.fs.File, IdaCoffModder);

pub const Filetype = enum(u8) {
    Elf = 0,
    Coff = 1,
};

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var alloc = gpa.allocator();

const PatcherContext = struct {
    filetype: Filetype,
    patcher: *align(8) anyopaque,
    ida_stream: *align(8) anyopaque,
};

fn init_ida_patcher_inner(path: [*]const u8, len: u32, filetype: Filetype) !*anyopaque {
    const file = try alloc.create(std.fs.File);
    errdefer alloc.destroy(file);
    file.* = try std.fs.cwd().openFile(path[0..len], .{ .mode = .read_write });
    const patcher_context = try alloc.create(PatcherContext);
    errdefer alloc.destroy(patcher_context);
    patcher_context.filetype = filetype;
    switch (filetype) {
        .Elf => {
            const parsed = try ElfParsed.init(file);
            const patcher = try alloc.create(IdaElfPatcher);
            errdefer alloc.destroy(patcher);
            patcher.* = try IdaElfPatcher.init(alloc, file, &parsed);
            patcher_context.patcher = patcher;
            const stream = try alloc.create(IdaElfStream);
            errdefer alloc.destroy(stream);
            stream.* = IdaElfStream.init(file, &patcher.modder);
            patcher_context.ida_stream = stream;
        },
        .Coff => {
            const data = try alloc.alloc(u8, try file.getEndPos());
            defer alloc.free(data);
            const coff = try std.coff.Coff.init(data, false);
            const parsed = CoffParsed.init(coff);
            const patcher = try alloc.create(IdaCoffPatcher);
            errdefer alloc.destroy(patcher);
            patcher.* = try IdaCoffPatcher.init(alloc, file, &parsed);
            patcher_context.patcher = patcher;
            const stream = try alloc.create(IdaCoffStream);
            errdefer alloc.destroy(stream);
            stream.* = IdaCoffStream.init(file, &patcher.modder);
            patcher_context.ida_stream = stream;
        },
    }
    return patcher_context;
}

pub export fn init_ida_patcher(path: [*]const u8, len: u32, filetype: Filetype) ?*anyopaque {
    return init_ida_patcher_inner(path, len, filetype) catch null;
}

pub export fn deinit_ida_patcher(ctx: *PatcherContext) void {
    switch (ctx.filetype) {
        .Elf => {
            const ida_stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const file = ida_stream.stream;
            alloc.destroy(ida_stream);
            const patcher: *IdaElfPatcher = @ptrCast(ctx.patcher);
            patcher.deinit(alloc);
            alloc.destroy(patcher);
            alloc.destroy(ctx);
            file.close();
            alloc.destroy(file);
        },
        .Coff => {
            const ida_stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const file = ida_stream.stream;
            alloc.destroy(ida_stream);
            const patcher: *IdaCoffPatcher = @ptrCast(ctx.patcher);
            patcher.deinit(alloc);
            alloc.destroy(patcher);
            alloc.destroy(ctx);
            file.close();
            alloc.destroy(file);
        },
    }
}

fn pure_patch_inner(ctx: *PatcherContext, addr: u64, patch_bytes: [*]const u8, len: u64) !void {
    switch (ctx.filetype) {
        .Elf => {
            std.debug.print("is elf", .{});
            const patcher: *IdaElfPatcher = @ptrCast(ctx.patcher);
            const stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const patch_info = try patcher.pure_patch(addr, patch_bytes[0..len], stream);
            add_func_tail(addr, patch_info.cave_addr, patch_info.cave_size);
        },
        .Coff => {
            const patcher: *IdaCoffPatcher = @ptrCast(ctx.patcher);
            const stream: *IdaCoffStream = @ptrCast(ctx.ida_stream);
            const patch_info = try patcher.pure_patch(addr, patch_bytes[0..len], stream);
            add_func_tail(addr, patch_info.cave_addr, patch_info.cave_size);
        },
    }
}

pub export fn pure_patch(ctx: *PatcherContext, addr: u64, patch_bytes: [*]const u8, len: u64) u64 {
    std.debug.print("pure patch {X} {X}\n", .{ addr, patch_bytes[0..len] });
    pure_patch_inner(ctx, addr, patch_bytes, len) catch |err| return @intFromError(err);
    return 0;
}
