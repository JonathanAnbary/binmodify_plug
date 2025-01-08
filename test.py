import shutil

import binmodify

if __name__ == '__main__':
    path = b"test_python_hack_patch"
    shutil.copy("tests/hello_world", path)
    with binmodify.ZigStream(path) as zs, binmodify.HackStream(zs) as hs, binmodify.HackPatcher(hs) as hp:
        hp.pure_patch(0x1001B3C, b"\x90"*100 + b"\x00", hs)
        print(f"{hp.get_old_addr():X}")
        print(f"{hp.get_new_addr():X}")
        temp = hs.get_next_write_record()
        while temp is not None:
            pos, bts = temp
            print(f"writing {bts} at {pos:X}")
            temp = hs.get_next_write_record()

