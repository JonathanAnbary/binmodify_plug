const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const idasdk = b.option([]const u8, "idasdk", "relative path to installation of the ida sdk") orelse return error.MustProvideIdaSdk;
    const idasdkpath = b.path(idasdk);

    const libdir = switch (target.result.os.tag) {
        .linux => switch (target.result.cpu.arch) {
            .x86 => "x64_linux_gcc_32",
            .x86_64 => "x64_linux_gcc_64",
            else => return error.ArchNotSupported,
        },
        else => return error.OsNotSupported,
    };

    const binmodify = b.dependency("binmodify", .{
        .target = target,
        .optimize = optimize,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    switch (target.result.ptrBitWidth()) {
        64 => lib_mod.addCMacro("__EA64__", "1"),
        32 => {},
        else => return error.PtrBitWidthNotSupported,
    }

    lib_mod.addImport("binmodify", binmodify.module("binmodify"));
    lib_mod.addIncludePath(b.path("src"));

    const lib_obj = b.addObject(.{
        .name = "zigobj",
        .root_module = lib_mod,
    });

    const plugin = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });

    switch (target.result.ptrBitWidth()) {
        64 => plugin.addCMacro("__EA64__", "1"),
        32 => {},
        else => return error.PtrBitWidthNotSupported,
    }

    plugin.addCSourceFile(.{ .file = b.path("src/plugin.cpp") });
    plugin.addObject(lib_obj);
    plugin.addIncludePath(idasdkpath.path(b, "include"));
    plugin.addLibraryPath(idasdkpath.path(b, "lib").path(b, libdir));
    plugin.linkSystemLibrary("ida64", .{});

    const plugin_lib = b.addSharedLibrary(.{
        .name = "binmodify",
        .root_module = plugin,
    });

    b.installArtifact(plugin_lib);

    const unit_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    unit_tests_mod.addImport("binmodify", binmodify.module("binmodify"));

    const unit_tests = b.addTest(.{
        .root_module = unit_tests_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
