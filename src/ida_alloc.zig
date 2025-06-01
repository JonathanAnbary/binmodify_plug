const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;

const ida = @cImport(@cInclude("ida.h"));

pub const ida_allocator: Allocator = .{
    .ptr = undefined,
    .vtable = &ida_allocator_vtable,
};

const ida_allocator_vtable: Allocator.VTable = .{
    .alloc = idaAlloc,
    .resize = idaResize,
    .remap = idaRemap,
    .free = idaFree,
};

fn idaAlloc(
    context: *anyopaque,
    len: usize,
    alignment: mem.Alignment,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = return_address;
    assert(alignment.compare(.lte, comptime .fromByteUnits(@alignOf(std.c.max_align_t))));
    // Note that this pointer cannot be aligncasted to max_align_t because if
    // len is < max_align_t then the alignment can be smaller. For example, if
    // max_align_t is 16, but the user requests 8 bytes, there is no built-in
    // type in C that is size 8 and has 16 byte alignment, so the alignment may
    // be 8 bytes rather than 16. Similarly if only 1 byte is requested, malloc
    // is allowed to return a 1-byte aligned pointer.
    return @ptrCast(ida.qalloc(len));
}

fn idaResize(
    context: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    _ = context;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    return false;
}

fn idaRemap(
    context: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = alignment;
    _ = return_address;
    return @ptrCast(ida.qrealloc(memory.ptr, new_len));
}

fn idaFree(
    context: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    return_address: usize,
) void {
    _ = context;
    _ = alignment;
    _ = return_address;
    ida.qfree(memory.ptr);
}
