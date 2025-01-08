BinModify Plugin
================

Bin(ary) Mod(ify) is a lightweight tool for patching binary executables, this is a plugin for using binmodify from ida.

Features:

- Creating code caves (not yet exposed).
- Inserting inline hooks (Shift+I).

Together these features allow for writing to binary files as though they were textual files! Inserting extra code inbetween existing instructions.

Installation
============

run `zig build -Doptimize=ReleaseSafe`.

copy (or link) `zig-out/lib/libida_binmodify.a` into the `binmodify` directory.

copy (or link) the entire binmodify direcory into the ida plugins directory (`~/.idapro/plugins/` on linux).

copy (or link) the `binmodify_plugin_stub.py` file into the ida plugins directory.

Testing
=======

There are no tests for the idapython scripts.

In order to test the zig lib run `zig build test`.

Planned features
================

Take a look at the planned features of binmodify.

In addtion the idapython plugin porition still needs to expose:

- PE patching.
- Cave creation.
