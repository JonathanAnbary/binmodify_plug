const std = @import("std");

pub fn build(b: *std.Build) !void {
    // b.verbose = true;
    b.verbose_cc = true;
    // b.verbose_link = true;
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const idasdk_path_opt = b.option([]const u8, "idasdk", "path to installation of the ida sdk") orelse return error.MustProvideIdaSdk;
    const idasdk_ea_64_opt = b.option(bool, "EA64", "target IDA64 (default)") orelse true;

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

    const objmod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .stack_check = false,
    });

    const idamod = idasdk.module("ida");
    for (idamod.c_macros.items) |macro| {
        objmod.c_macros.append(b.allocator, macro) catch @panic("OOM");
    }

    objmod.addImport("binmodify", binmodify.module("binmodify"));
    objmod.addIncludePath(b.path("src"));

    const lib_obj = b.addObject(.{
        .name = "zigobj",
        .root_module = objmod,
    });

    const plugin = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });

    for (idamod.c_macros.items) |macro| {
        plugin.c_macros.append(b.allocator, macro) catch @panic("OOM");
    }
    plugin.linkLibrary(idasdk.artifact("ida"));
    // const cflag_to_add = try std.fmt.allocPrint(
    //     b.allocator,
    //     "-Wl,--version-script={s}",
    //     .{idasdk.namedLazyPath("exports.def").getPath(b)},
    // );
    // plugin.addObjectFile(idasdk.namedLazyPath("ida"));
    plugin.addCSourceFile(.{ .file = b.path("src/plugin.cpp") });
    plugin.addObject(lib_obj);

    const plugin_lib = b.addSharedLibrary(.{
        .name = if (idasdk_ea_64_opt) "binmodify64" else "binmodify",
        .root_module = plugin,
    });

    b.installArtifact(plugin_lib);
}
