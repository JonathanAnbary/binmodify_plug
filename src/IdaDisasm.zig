const ida = @cImport(@cInclude("ida.h"));
const arch = @import("binmodify").arch;

const Self = @This();

pub const Error = error{};

pub fn init(farch: arch.Arch, fmode: arch.Mode, fendian: arch.Endian) !Self {
    _ = farch;
    _ = fmode;
    _ = fendian;
    return .{};
}

pub fn deinit(self: Self) void {
    _ = self;
}

pub fn min_insn_size(self: Self, size: u64, code: []const u8, addr: u64) u64 {
    _ = self;
    _ = code;
    var insn: [ida.SIZEOF_INSN_T]u8 align(64) = undefined;
    var min_size: u64 = 0;
    while (min_size < size) {
        const temp = ida.decode_insn(&insn, addr + min_size);
        if (temp < 0) return size;
        min_size += @intCast(temp);
    }
    return min_size;
}
