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
const ida_allocator = @import("ida_alloc.zig").ida_allocator;

fn add_func_tail(addr: u64, start: u64, size: u64) void {
    const func = ida.get_func(@intCast(addr));
    _ = ida.append_func_tail(func, @intCast(start), @intCast(start + size));
}

const IdaElfModder = hack_modder.Modder(ElfModder);
const IdaElfPatcher = patch.Patcher(IdaElfModder, IdaDisasm);
const IdaElfStream = hack_stream.HackStream(IdaElfModder);

const IdaCoffModder = hack_modder.Modder(CoffModder);
const IdaCoffPatcher = patch.Patcher(IdaCoffModder, IdaDisasm);
const IdaCoffStream = hack_stream.HackStream(IdaCoffModder);

pub const Filetype = enum(u8) {
    Elf = 0,
    Coff = 1,
};

const PatcherContext = struct {
    filetype: Filetype,
    patcher: *align(8) anyopaque,
    ida_stream: *align(8) anyopaque,
};

const Status = enum(u64) {
    Ok = 0,
    OutOfMemory,
    SharingViolation,
    PathAlreadyExists,
    FileNotFound,
    AccessDenied,
    PipeBusy,
    NoDevice,
    NameTooLong,
    InvalidUtf8,
    InvalidWtf8,
    BadPathName,
    Unexpected,
    NetworkNotFound,
    AntivirusInterference,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    FileTooBig,
    IsDir,
    NoSpaceLeft,
    NotDir,
    DeviceBusy,
    FileLocksNotSupported,
    FileBusy,
    WouldBlock,
    Unseekable,
    InputOutput,
    OperationAborted,
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,
    Canceled,
    ProcessNotFound,
    LockViolation,
    EndOfStream,
    InvalidElfMagic,
    InvalidElfVersion,
    InvalidElfClass,
    InvalidElfEndian,
    EdgeNotFound,
    InvalidEdge,
    InvalidHeader,
    OffsetNotLoaded,
    AddrNotMapped,
    NoMatchingOffset,
    IntersectingFileRanges,
    InvalidElfRanges,
    OverlappingMemoryRanges,
    UnexpectedEof,
    CantExpandPhdr,
    FileszBiggerThenMemsz,
    OutOfBoundField,
    UnmappedRange,
    FieldNotAdjustable,
    PhdrTablePhdrNotFound,
    NoSpaceToExtendPhdrTable,
    TooManyFileRanges,
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
    ArchNotSupported,
    ModeNotSupported,
    ArchEndianMismatch,
    MissingPEHeader,
    NoCaveOption,
    InvalidOptionalHeaderMagic,
    VirtualSizeLessThenFileSize,
    StartAfterEnd,
    DiskQuota,
    InvalidArgument,
    NotOpenForWriting,
    InvalidPEMagic,
    InvalidPEHeader,
    InvalidMachine,
    MissingCoffSection,
    MissingStringTable,
    PatchTooLarge,
    AdjustSegmFailed,
    RequestedFileAlignmentDisagreeWithHeader,
    AddSegmFailed,
};

const AllError = error{
    OutOfMemory,
    SharingViolation,
    PathAlreadyExists,
    FileNotFound,
    AccessDenied,
    PipeBusy,
    NoDevice,
    NameTooLong,
    InvalidUtf8,
    InvalidWtf8,
    BadPathName,
    Unexpected,
    NetworkNotFound,
    AntivirusInterference,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    FileTooBig,
    IsDir,
    NoSpaceLeft,
    NotDir,
    DeviceBusy,
    FileLocksNotSupported,
    FileBusy,
    WouldBlock,
    Unseekable,
    InputOutput,
    OperationAborted,
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,
    Canceled,
    ProcessNotFound,
    LockViolation,
    EndOfStream,
    InvalidElfMagic,
    InvalidElfVersion,
    InvalidElfClass,
    InvalidElfEndian,
    EdgeNotFound,
    InvalidEdge,
    InvalidHeader,
    OffsetNotLoaded,
    AddrNotMapped,
    NoMatchingOffset,
    IntersectingFileRanges,
    InvalidElfRanges,
    OverlappingMemoryRanges,
    UnexpectedEof,
    CantExpandPhdr,
    FileszBiggerThenMemsz,
    OutOfBoundField,
    UnmappedRange,
    FieldNotAdjustable,
    PhdrTablePhdrNotFound,
    NoSpaceToExtendPhdrTable,
    TooManyFileRanges,
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
    ArchNotSupported,
    ModeNotSupported,
    ArchEndianMismatch,
    MissingPEHeader,
    NoCaveOption,
    InvalidOptionalHeaderMagic,
    VirtualSizeLessThenFileSize,
    StartAfterEnd,
    DiskQuota,
    InvalidArgument,
    NotOpenForWriting,
    InvalidPEMagic,
    InvalidPEHeader,
    InvalidMachine,
    MissingCoffSection,
    MissingStringTable,
    PatchTooLarge,
    AdjustSegmFailed,
    RequestedFileAlignmentDisagreeWithHeader,
    AddSegmFailed,
};

fn err_to_enum(err: AllError) Status {
    return switch (err) {
        AllError.OutOfMemory => .OutOfMemory,
        AllError.SharingViolation => .SharingViolation,
        AllError.PathAlreadyExists => .PathAlreadyExists,
        AllError.FileNotFound => .FileNotFound,
        AllError.AccessDenied => .AccessDenied,
        AllError.PipeBusy => .PipeBusy,
        AllError.NoDevice => .NoDevice,
        AllError.NameTooLong => .NameTooLong,
        AllError.InvalidUtf8 => .InvalidUtf8,
        AllError.InvalidWtf8 => .InvalidWtf8,
        AllError.BadPathName => .BadPathName,
        AllError.Unexpected => .Unexpected,
        AllError.NetworkNotFound => .NetworkNotFound,
        AllError.AntivirusInterference => .AntivirusInterference,
        AllError.SymLinkLoop => .SymLinkLoop,
        AllError.ProcessFdQuotaExceeded => .ProcessFdQuotaExceeded,
        AllError.SystemFdQuotaExceeded => .SystemFdQuotaExceeded,
        AllError.SystemResources => .SystemResources,
        AllError.FileTooBig => .FileTooBig,
        AllError.IsDir => .IsDir,
        AllError.NoSpaceLeft => .NoSpaceLeft,
        AllError.NotDir => .NotDir,
        AllError.DeviceBusy => .DeviceBusy,
        AllError.FileLocksNotSupported => .FileLocksNotSupported,
        AllError.FileBusy => .FileBusy,
        AllError.WouldBlock => .WouldBlock,
        AllError.Unseekable => .Unseekable,
        AllError.InputOutput => .InputOutput,
        AllError.OperationAborted => .OperationAborted,
        AllError.BrokenPipe => .BrokenPipe,
        AllError.ConnectionResetByPeer => .ConnectionResetByPeer,
        AllError.ConnectionTimedOut => .ConnectionTimedOut,
        AllError.NotOpenForReading => .NotOpenForReading,
        AllError.SocketNotConnected => .SocketNotConnected,
        AllError.Canceled => .Canceled,
        AllError.ProcessNotFound => .ProcessNotFound,
        AllError.LockViolation => .LockViolation,
        AllError.EndOfStream => .EndOfStream,
        AllError.InvalidElfMagic => .InvalidElfMagic,
        AllError.InvalidElfVersion => .InvalidElfVersion,
        AllError.InvalidElfClass => .InvalidElfClass,
        AllError.InvalidElfEndian => .InvalidElfEndian,
        AllError.EdgeNotFound => .EdgeNotFound,
        AllError.InvalidEdge => .InvalidEdge,
        AllError.InvalidHeader => .InvalidHeader,
        AllError.OffsetNotLoaded => .OffsetNotLoaded,
        AllError.AddrNotMapped => .AddrNotMapped,
        AllError.NoMatchingOffset => .NoMatchingOffset,
        AllError.IntersectingFileRanges => .IntersectingFileRanges,
        AllError.InvalidElfRanges => .InvalidElfRanges,
        AllError.OverlappingMemoryRanges => .OverlappingMemoryRanges,
        AllError.UnexpectedEof => .UnexpectedEof,
        AllError.CantExpandPhdr => .CantExpandPhdr,
        AllError.FileszBiggerThenMemsz => .FileszBiggerThenMemsz,
        AllError.OutOfBoundField => .OutOfBoundField,
        AllError.UnmappedRange => .UnmappedRange,
        AllError.FieldNotAdjustable => .FieldNotAdjustable,
        AllError.PhdrTablePhdrNotFound => .PhdrTablePhdrNotFound,
        AllError.NoSpaceToExtendPhdrTable => .NoSpaceToExtendPhdrTable,
        AllError.TooManyFileRanges => .TooManyFileRanges,
        AllError.ArchNotEndianable => .ArchNotEndianable,
        AllError.ArchModeMismatch => .ArchModeMismatch,
        AllError.NoFreeSpace => .NoFreeSpace,
        AllError.ArchNotSupported => .ArchNotSupported,
        AllError.ModeNotSupported => .ModeNotSupported,
        AllError.ArchEndianMismatch => .ArchEndianMismatch,
        AllError.MissingPEHeader => .MissingPEHeader,
        AllError.NoCaveOption => .NoCaveOption,
        AllError.InvalidOptionalHeaderMagic => .InvalidOptionalHeaderMagic,
        AllError.VirtualSizeLessThenFileSize => .VirtualSizeLessThenFileSize,
        AllError.StartAfterEnd => .StartAfterEnd,
        AllError.DiskQuota => .DiskQuota,
        AllError.InvalidArgument => .InvalidArgument,
        AllError.NotOpenForWriting => .NotOpenForWriting,
        AllError.InvalidPEMagic => .InvalidPEMagic,
        AllError.InvalidPEHeader => .InvalidPEHeader,
        AllError.InvalidMachine => .InvalidMachine,
        AllError.MissingCoffSection => .MissingCoffSection,
        AllError.MissingStringTable => .MissingStringTable,
        AllError.PatchTooLarge => .PatchTooLarge,
        AllError.AdjustSegmFailed => .AdjustSegmFailed,
        AllError.RequestedFileAlignmentDisagreeWithHeader => .RequestedFileAlignmentDisagreeWithHeader,
        AllError.AddSegmFailed => .AddSegmFailed,
    };
}

fn init_ida_patcher_inner(path: [*]const u8, len: u32, filetype: Filetype) !*anyopaque {
    const file = try ida_allocator.create(std.fs.File);
    errdefer ida_allocator.destroy(file);
    file.* = try std.fs.cwd().openFile(path[0..len], .{ .mode = .read_write });
    const patcher_context = try ida_allocator.create(PatcherContext);
    errdefer ida_allocator.destroy(patcher_context);
    patcher_context.filetype = filetype;
    switch (filetype) {
        .Elf => {
            const parsed = try ElfParsed.init(file);
            const patcher = try ida_allocator.create(IdaElfPatcher);
            errdefer ida_allocator.destroy(patcher);
            patcher.* = try IdaElfPatcher.init(ida_allocator, file, &parsed);
            patcher_context.patcher = patcher;
            const stream = try ida_allocator.create(IdaElfStream);
            errdefer ida_allocator.destroy(stream);
            stream.* = IdaElfStream.init(file, &patcher.modder);
            patcher_context.ida_stream = stream;
        },
        .Coff => {
            const data = try ida_allocator.alloc(u8, try file.getEndPos());
            defer ida_allocator.free(data);
            _ = try file.readAll(data);
            const coff = try std.coff.Coff.init(data, false);
            const parsed = CoffParsed.init(coff);
            const patcher = try ida_allocator.create(IdaCoffPatcher);
            errdefer ida_allocator.destroy(patcher);
            patcher.* = try IdaCoffPatcher.init(ida_allocator, file, &parsed);
            patcher_context.patcher = patcher;
            const stream = try ida_allocator.create(IdaCoffStream);
            errdefer ida_allocator.destroy(stream);
            stream.* = IdaCoffStream.init(file, &patcher.modder);
            patcher_context.ida_stream = stream;
        },
    }
    return patcher_context;
}

pub export fn init_ida_patcher(patcher: *?*anyopaque, path: [*]const u8, len: u32, filetype: Filetype) Status {
    patcher.* = init_ida_patcher_inner(path, len, filetype) catch |err| return err_to_enum(err);
    return .Ok;
}

pub export fn deinit_ida_patcher(ctx: *PatcherContext) void {
    switch (ctx.filetype) {
        .Elf => {
            const ida_stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const file = ida_stream.file;
            ida_allocator.destroy(ida_stream);
            const patcher: *IdaElfPatcher = @ptrCast(ctx.patcher);
            patcher.deinit(ida_allocator);
            ida_allocator.destroy(patcher);
            ida_allocator.destroy(ctx);
            file.close();
            ida_allocator.destroy(file);
        },
        .Coff => {
            const ida_stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const file = ida_stream.file;
            ida_allocator.destroy(ida_stream);
            const patcher: *IdaCoffPatcher = @ptrCast(ctx.patcher);
            patcher.deinit(ida_allocator);
            ida_allocator.destroy(patcher);
            ida_allocator.destroy(ctx);
            file.close();
            ida_allocator.destroy(file);
        },
    }
}

fn try_patch_inner(ctx: *PatcherContext, addr: u64, patch_bytes: [*]const u8, len: u64) !void {
    switch (ctx.filetype) {
        .Elf => {
            const patcher: *IdaElfPatcher = @ptrCast(ctx.patcher);
            const stream: *IdaElfStream = @ptrCast(ctx.ida_stream);
            const patch_info = try patcher.try_patch(ida_allocator, addr, patch_bytes[0..len], stream);
            add_func_tail(addr, patch_info.cave_addr, patch_info.cave_size);
        },
        .Coff => {
            const patcher: *IdaCoffPatcher = @ptrCast(ctx.patcher);
            const stream: *IdaCoffStream = @ptrCast(ctx.ida_stream);
            const patch_info = try patcher.try_patch(ida_allocator, addr, patch_bytes[0..len], stream);
            add_func_tail(addr, patch_info.cave_addr, patch_info.cave_size);
        },
    }
}

pub export fn pure_patch(ctx: *PatcherContext, addr: u64, patch_bytes: [*]const u8, len: u64) Status {
    try_patch_inner(ctx, addr, patch_bytes, len) catch |err| return err_to_enum(err);
    return .Ok;
}
