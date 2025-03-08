const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const idasdk_path_opt = b.option([]const u8, "idasdk", "path to installation of the ida sdk") orelse return error.MustProvideIdaSdk;
    const idasdk_ea_64_opt = b.option(bool, "EA64", "target IDA64") orelse false;

    const idasdk = b.dependency("idasdk", .{
        .target = target,
        .optimize = optimize,
        .idasdk = idasdk_path_opt,
        .EA64 = idasdk_ea_64_opt,
    });

    const binmodify = b.dependency("binmodify", .{
        .target = target,
        .optimize = optimize,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const idamod = idasdk.module("ida");
    for (idamod.c_macros.items) |macro| {
        lib_mod.c_macros.append(b.allocator, macro) catch @panic("OOM");
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

    for (idamod.include_dirs.items) |include_dir| {
        plugin.addIncludePath(include_dir.path);
    }
    for (idamod.c_macros.items) |macro| {
        plugin.c_macros.append(b.allocator, macro) catch @panic("OOM");
    }
    plugin.linkLibrary(idasdk.artifact(if (idasdk_ea_64_opt) "ida64" else "ida"));
    plugin.addCSourceFile(.{ .file = b.path("src/plugin.cpp") });
    plugin.addObject(lib_obj);

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
