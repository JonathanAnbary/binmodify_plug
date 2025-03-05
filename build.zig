const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    cosnt idasdk = b.option([]const u8, "idasdk", "relative path to installation of the ida sdk") orelse return error.MustProvideIdaSdk;
    const idasdkpath = b.path(idasdk);

    const libdir = switch (target.result.os.tag) {
        .linux => switch (target.result.cpu.arch) {
            .x86 => "x64_linux_gcc_32",
            .x86_64 => "x64_linux_gcc_64",
            else => return error.ArchNotSupported,
        },
        else => return error.OsNotSupported,
    };

    const lib_mod = b.createModule(.{
        .roo
        .target = target,
        .optimize = optimize,
    });

    const binmodify = b.dependency("binmodify", .{
        .target = target,
        .optimize = optimize,
    });

    lib_mod.addImport("cbinmodify", binmodify.module("cbinmodify"));

    lib_mod.addIncludePath(b.path("include/ida/"));

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const shared_lib = b.addSharedLibrary(.{
        .name = "ida_binmodify",
        .root_module = lib_mod,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(shared_lib);

    const unit_tests_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    unit_tests_mod.addImport("cbinmodify", binmodify.module("cbinmodify"));

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
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
