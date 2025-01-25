const std = @import("std");
const testing = std.testing;

const cbinmodify = @import("cbinmodify");

const patch = cbinmodify.patch;
const ElfModder = cbinmodify.ElfModder;
const CoffModder = cbinmodify.CoffModder;
const ElfParsed = cbinmodify.ElfParsed;
const CoffParsed = cbinmodify.CoffParsed;

const hack_modder = @import("hack_modder.zig");
const hack_stream = @import("hack_stream.zig");

pub const Result = enum(u8) {
    Ok = @intFromEnum(cbinmodify.Result.Ok),
    UnknownFileType = @intFromEnum(cbinmodify.Result.UnknownFileType),
    BrokenPipe = @intFromEnum(cbinmodify.Result.BrokenPipe),
    ConnectionResetByPeer = @intFromEnum(cbinmodify.Result.ConnectionResetByPeer),
    ConnectionTimedOut = @intFromEnum(cbinmodify.Result.ConnectionTimedOut),
    NotOpenForReading = @intFromEnum(cbinmodify.Result.NotOpenForReading),
    SocketNotConnected = @intFromEnum(cbinmodify.Result.SocketNotConnected),
    WouldBlock = @intFromEnum(cbinmodify.Result.WouldBlock),
    Canceled = @intFromEnum(cbinmodify.Result.Canceled),
    AccessDenied = @intFromEnum(cbinmodify.Result.AccessDenied),
    ProcessNotFound = @intFromEnum(cbinmodify.Result.ProcessNotFound),
    LockViolation = @intFromEnum(cbinmodify.Result.LockViolation),
    Unexpected = @intFromEnum(cbinmodify.Result.Unexpected),
    NoSpaceLeft = @intFromEnum(cbinmodify.Result.NoSpaceLeft),
    DiskQuota = @intFromEnum(cbinmodify.Result.DiskQuota),
    FileTooBig = @intFromEnum(cbinmodify.Result.FileTooBig),
    DeviceBusy = @intFromEnum(cbinmodify.Result.DeviceBusy),
    InvalidArgument = @intFromEnum(cbinmodify.Result.InvalidArgument),
    NotOpenForWriting = @intFromEnum(cbinmodify.Result.NotOpenForWriting),
    NoDevice = @intFromEnum(cbinmodify.Result.NoDevice),
    Unseekable = @intFromEnum(cbinmodify.Result.Unseekable),
    UNKNOWN_CS_ERR = @intFromEnum(cbinmodify.Result.UNKNOWN_CS_ERR),
    ArchNotSupported = @intFromEnum(cbinmodify.Result.ArchNotSupported),
    ModeNotSupported = @intFromEnum(cbinmodify.Result.ModeNotSupported),
    ArchEndianMismatch = @intFromEnum(cbinmodify.Result.ArchEndianMismatch),
    AddrNotMapped = @intFromEnum(cbinmodify.Result.AddrNotMapped),
    NoMatchingOffset = @intFromEnum(cbinmodify.Result.NoMatchingOffset),
    OffsetNotLoaded = @intFromEnum(cbinmodify.Result.OffsetNotLoaded),
    NoCaveOption = @intFromEnum(cbinmodify.Result.NoCaveOption),
    InvalidPEMagic = @intFromEnum(cbinmodify.Result.InvalidPEMagic),
    InvalidPEHeader = @intFromEnum(cbinmodify.Result.InvalidPEHeader),
    InvalidMachine = @intFromEnum(cbinmodify.Result.InvalidMachine),
    MissingPEHeader = @intFromEnum(cbinmodify.Result.MissingPEHeader),
    MissingCoffSection = @intFromEnum(cbinmodify.Result.MissingCoffSection),
    MissingStringTable = @intFromEnum(cbinmodify.Result.MissingStringTable),
    EdgeNotFound = @intFromEnum(cbinmodify.Result.EdgeNotFound),
    InvalidEdge = @intFromEnum(cbinmodify.Result.InvalidEdge),
    InvalidHeader = @intFromEnum(cbinmodify.Result.InvalidHeader),
    InvalidElfMagic = @intFromEnum(cbinmodify.Result.InvalidElfMagic),
    InvalidElfVersion = @intFromEnum(cbinmodify.Result.InvalidElfVersion),
    InvalidElfEndian = @intFromEnum(cbinmodify.Result.InvalidElfEndian),
    InvalidElfClass = @intFromEnum(cbinmodify.Result.InvalidElfClass),
    EndOfStream = @intFromEnum(cbinmodify.Result.EndOfStream),
    OutOfMemory = @intFromEnum(cbinmodify.Result.OutOfMemory),
    InputOutput = @intFromEnum(cbinmodify.Result.InputOutput),
    SystemResources = @intFromEnum(cbinmodify.Result.SystemResources),
    IsDir = @intFromEnum(cbinmodify.Result.IsDir),
    OperationAborted = @intFromEnum(cbinmodify.Result.OperationAborted),
    CS_ERR_MEM = @intFromEnum(cbinmodify.Result.CS_ERR_MEM),
    CS_ERR_ARCH = @intFromEnum(cbinmodify.Result.CS_ERR_ARCH),
    CS_ERR_HANDLE = @intFromEnum(cbinmodify.Result.CS_ERR_HANDLE),
    CS_ERR_CSH = @intFromEnum(cbinmodify.Result.CS_ERR_CSH),
    CS_ERR_MODE = @intFromEnum(cbinmodify.Result.CS_ERR_MODE),
    CS_ERR_OPTION = @intFromEnum(cbinmodify.Result.CS_ERR_OPTION),
    CS_ERR_DETAIL = @intFromEnum(cbinmodify.Result.CS_ERR_DETAIL),
    CS_ERR_MEMSETUP = @intFromEnum(cbinmodify.Result.CS_ERR_MEMSETUP),
    CS_ERR_VERSION = @intFromEnum(cbinmodify.Result.CS_ERR_VERSION),
    CS_ERR_DIET = @intFromEnum(cbinmodify.Result.CS_ERR_DIET),
    CS_ERR_SKIPDATA = @intFromEnum(cbinmodify.Result.CS_ERR_SKIPDATA),
    CS_ERR_X86_ATT = @intFromEnum(cbinmodify.Result.CS_ERR_X86_ATT),
    CS_ERR_X86_INTEL = @intFromEnum(cbinmodify.Result.CS_ERR_X86_INTEL),
    CS_ERR_X86_MASM = @intFromEnum(cbinmodify.Result.CS_ERR_X86_MASM),
    ArchNotEndianable = @intFromEnum(cbinmodify.Result.ArchNotEndianable),
    ArchModeMismatch = @intFromEnum(cbinmodify.Result.ArchModeMismatch),
    NoFreeSpace = @intFromEnum(cbinmodify.Result.NoFreeSpace),
    InvalidOptionalHeaderMagic = @intFromEnum(cbinmodify.Result.InvalidOptionalHeaderMagic),
    IntersectingFileRanges = @intFromEnum(cbinmodify.Result.IntersectingFileRanges),
    IntersectingMemoryRanges = @intFromEnum(cbinmodify.Result.IntersectingMemoryRanges),
    IllogicalInsnToMove = @intFromEnum(cbinmodify.Result.IllogicalInsnToMove),
    IllogicalJmpSize = @intFromEnum(cbinmodify.Result.IllogicalJmpSize),
    UnexpectedEof = @intFromEnum(cbinmodify.Result.UnexpectedEof),
    VirtualSizeLessThenFileSize = @intFromEnum(cbinmodify.Result.VirtualSizeLessThenFileSize),
    InvalidElfRanges = @intFromEnum(cbinmodify.Result.InvalidElfRanges),
    CantExpandPhdr = @intFromEnum(cbinmodify.Result.CantExpandPhdr),
    FileszBiggerThenMemsz = @intFromEnum(cbinmodify.Result.FileszBiggerThenMemsz),
    StartAfterEnd = @intFromEnum(cbinmodify.Result.StartAfterEnd),
    NoLastCaveChange,
    NoNextWriteRecord,
};

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var alloc = gpa.allocator();

pub export fn create_ElfPatcher() ?*patch.Patcher(ElfModder) {
    return alloc.create(patch.Patcher(ElfModder)) catch return null;
}

pub export fn destroy_ElfPatcher(patcher: *patch.Patcher(ElfModder)) void {
    alloc.destroy(patcher);
}

pub export fn create_CoffPatcher() ?*patch.Patcher(CoffModder) {
    return alloc.create(patch.Patcher(CoffModder)) catch return null;
}

pub export fn destroy_CoffPatcher(patcher: *patch.Patcher(CoffModder)) void {
    alloc.destroy(patcher);
}

pub export fn create_HackPatcher() ?*patch.Patcher(hack_modder.Modder(ElfModder)) {
    return alloc.create(patch.Patcher(hack_modder.Modder(ElfModder))) catch return null;
}

pub export fn destroy_HackPatcher(patcher: *patch.Patcher(hack_modder.Modder(ElfModder))) void {
    alloc.destroy(patcher);
}

pub export fn create_stream(path: [*]const u8, len: u64) ?*std.io.StreamSource {
    // weird stuff since Im getting a compile error otherwise.
    const stream = alloc.create(std.io.StreamSource) catch return null;
    const stream_cpy = std.io.StreamSource{ .file = std.fs.cwd().openFile(path[0..len], std.fs.File.OpenFlags{ .mode = .read_write }) catch {
        alloc.destroy(stream);
        return null;
    } };
    stream.* = stream_cpy;
    return stream;
}

pub export fn destroy_stream(stream: *std.io.StreamSource) void {
    stream.file.close();
    alloc.destroy(stream);
}

pub export fn create_HackStream() ?*hack_stream.HackStream(*std.io.StreamSource) {
    return alloc.create(hack_stream.HackStream(*std.io.StreamSource)) catch return null;
}

pub export fn destroy_HackStream(stream: *hack_stream.HackStream(*std.io.StreamSource)) void {
    alloc.destroy(stream);
}

pub export fn HackStream_init(out: *hack_stream.HackStream(*std.io.StreamSource), stream: *std.io.StreamSource) void {
    out.* = hack_stream.HackStream(*std.io.StreamSource).init(stream, alloc);
}

pub export fn HackStream_deinit(out: *hack_stream.HackStream(*std.io.StreamSource)) void {
    out.deinit();
}

fn inner_HackPatcher_init(out: *patch.Patcher(hack_modder.Modder(ElfModder)), stream: *hack_stream.HackStream(*std.io.StreamSource)) !void {
    const parsed = try ElfParsed.init(stream.stream);
    out.* = try patch.Patcher(hack_modder.Modder(ElfModder)).init(alloc, stream, &parsed);
}

pub export fn HackPatcher_init(out: *patch.Patcher(hack_modder.Modder(ElfModder)), stream: *hack_stream.HackStream(*std.io.StreamSource)) cbinmodify.Result {
    inner_HackPatcher_init(out, stream) catch |err| return cbinmodify.err_to_res(err);
    return .Ok;
}

pub export fn HackPatcher_deinit(patcher: *patch.Patcher(hack_modder.Modder(ElfModder))) void {
    patcher.deinit(alloc);
}

pub export fn HackPatcher_pure_patch(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), addr: u64, patch_data: [*]const u8, patch_data_len: u64, stream: *hack_stream.HackStream(*std.io.StreamSource)) cbinmodify.Result {
    patcher.pure_patch(addr, patch_data[0..patch_data_len], stream) catch |err| return cbinmodify.err_to_res(err);
    return .Ok;
}

pub export fn HackPatcher_get_old_addr(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), addr: *u64) Result {
    if (patcher.modder.cave_change) |cave_change| {
        addr.* = cave_change.old_addr;
        return .Ok;
    } else {
        return .NoLastCaveChange;
    }
}

pub export fn HackPatcher_get_new_addr(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), addr: *u64) Result {
    if (patcher.modder.cave_change) |cave_change| {
        addr.* = cave_change.new_addr;
        return .Ok;
    } else {
        return .NoLastCaveChange;
    }
}

pub export fn HackPatcher_get_is_end(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), is_end: *bool) Result {
    if (patcher.modder.cave_change) |cave_change| {
        is_end.* = cave_change.is_end;
        return .Ok;
    } else {
        return .NoLastCaveChange;
    }
}

pub export fn HackStream_get_next_write_record(stream: *hack_stream.HackStream(*std.io.StreamSource), pos: *u64, bytes: *[*]const u8, bytes_len: *u64) Result {
    if (stream.write_record.items.len != 0) {
        const temp = stream.write_record.pop();
        pos.* = temp.pos;
        bytes.* = temp.bytes.ptr;
        bytes_len.* = temp.bytes.len;
        return .Ok;
    } else {
        return .NoNextWriteRecord;
    }
}

fn inner_HackPatcher_off_to_addr(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), off: u64) !u64 {
    return patcher.modder.off_to_addr(off);
}

pub export fn HackPatcher_off_to_addr(patcher: *patch.Patcher(hack_modder.Modder(ElfModder)), off: u64, addr: *u64) cbinmodify.Result {
    addr.* = inner_HackPatcher_off_to_addr(patcher, off) catch |err| return cbinmodify.err_to_res(err);
    return .Ok;
}

// test "temp" {
//     inline for (std.meta.fields(Result)) |res_field| {
//         std.debug.print("{s} = {}\n", .{ res_field.name, res_field.value });
//     }
// }
