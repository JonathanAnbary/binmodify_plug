import ctypes
from enum import IntEnum, auto, Enum

from typing import Tuple

_binmodify = ctypes.CDLL("./binmodify/libida_binmodify.so")

_ElfPatcher_init = _binmodify.ElfPatcher_init
_ElfPatcher_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_ElfPatcher_init.restype = ctypes.c_uint8

_ElfPatcher_deinit = _binmodify.ElfPatcher_deinit
_ElfPatcher_deinit.argtypes = [ctypes.c_void_p]
_ElfPatcher_deinit.restype = None

_ElfPatcher_pure_patch = _binmodify.ElfPatcher_pure_patch
_ElfPatcher_pure_patch.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
_ElfPatcher_pure_patch.restype = ctypes.c_uint8

_CoffPatcher_init = _binmodify.CoffPatcher_init
_CoffPatcher_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_CoffPatcher_init.restype = ctypes.c_uint8

_CoffPatcher_deinit = _binmodify.CoffPatcher_deinit
_CoffPatcher_deinit.argtypes = [ctypes.c_void_p]
_CoffPatcher_deinit.restype = None 

_CoffPatcher_pure_patch = _binmodify.CoffPatcher_pure_patch
_CoffPatcher_pure_patch.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
_CoffPatcher_pure_patch.restype = ctypes.c_uint8

_ElfHackPatcher_init = _binmodify.ElfHackPatcher_init
_ElfHackPatcher_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_ElfHackPatcher_init.restype = ctypes.c_uint8

_ElfHackPatcher_deinit = _binmodify.ElfHackPatcher_deinit
_ElfHackPatcher_deinit.argtypes = [ctypes.c_void_p]
_ElfHackPatcher_deinit.restype = None

_ElfHackPatcher_pure_patch = _binmodify.ElfHackPatcher_pure_patch
_ElfHackPatcher_pure_patch.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_void_p]
_ElfHackPatcher_pure_patch.restype = ctypes.c_uint8

_ElfHackPatcher_get_old_addr = _binmodify.ElfHackPatcher_get_old_addr
_ElfHackPatcher_get_old_addr.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
_ElfHackPatcher_get_old_addr.restype = ctypes.c_uint8

_ElfHackPatcher_get_new_addr = _binmodify.ElfHackPatcher_get_new_addr
_ElfHackPatcher_get_new_addr.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
_ElfHackPatcher_get_new_addr.restype = ctypes.c_uint8

_ElfHackPatcher_get_is_end = _binmodify.ElfHackPatcher_get_is_end
_ElfHackPatcher_get_is_end.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]
_ElfHackPatcher_get_is_end.restype = ctypes.c_uint8

_ElfHackPatcher_off_to_addr = _binmodify.ElfHackPatcher_off_to_addr
_ElfHackPatcher_off_to_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
_ElfHackPatcher_off_to_addr.restype = ctypes.c_uint8

_CoffHackPatcher_init = _binmodify.CoffHackPatcher_init
_CoffHackPatcher_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_CoffHackPatcher_init.restype = ctypes.c_uint8

_CoffHackPatcher_deinit = _binmodify.CoffHackPatcher_deinit
_CoffHackPatcher_deinit.argtypes = [ctypes.c_void_p]
_CoffHackPatcher_deinit.restype = None

_CoffHackPatcher_pure_patch = _binmodify.CoffHackPatcher_pure_patch
_CoffHackPatcher_pure_patch.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64, ctypes.c_void_p]
_CoffHackPatcher_pure_patch.restype = ctypes.c_uint8

_CoffHackPatcher_get_old_addr = _binmodify.CoffHackPatcher_get_old_addr
_CoffHackPatcher_get_old_addr.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
_CoffHackPatcher_get_old_addr.restype = ctypes.c_uint8

_CoffHackPatcher_get_new_addr = _binmodify.CoffHackPatcher_get_new_addr
_CoffHackPatcher_get_new_addr.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
_CoffHackPatcher_get_new_addr.restype = ctypes.c_uint8

_CoffHackPatcher_get_is_end = _binmodify.CoffHackPatcher_get_is_end
_CoffHackPatcher_get_is_end.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]
_CoffHackPatcher_get_is_end.restype = ctypes.c_uint8

_CoffHackPatcher_off_to_addr = _binmodify.CoffHackPatcher_off_to_addr
_CoffHackPatcher_off_to_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
_CoffHackPatcher_off_to_addr.restype = ctypes.c_uint8

_HackStream_init = _binmodify.HackStream_init
_HackStream_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_HackStream_init.restype = None

_HackStream_get_next_write_record = _binmodify.HackStream_get_next_write_record
_HackStream_get_next_write_record.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_uint64)]
_HackStream_get_next_write_record.restype = ctypes.c_uint8

_create_ElfPatcher = _binmodify.create_ElfPatcher
_create_ElfPatcher.argtypes = []
_create_ElfPatcher.restype = ctypes.c_void_p

_destroy_ElfPatcher = _binmodify.destroy_ElfPatcher
_destroy_ElfPatcher.argtypes = [ctypes.c_void_p]
_destroy_ElfPatcher.restype = None

_create_CoffPatcher = _binmodify.create_CoffPatcher
_create_CoffPatcher.argtypes = []
_create_CoffPatcher.restype = ctypes.c_void_p

_destroy_CoffPatcher = _binmodify.destroy_CoffPatcher
_destroy_CoffPatcher.argtypes = [ctypes.c_void_p]
_destroy_CoffPatcher.restype = None

_create_ElfHackPatcher = _binmodify.create_ElfHackPatcher
_create_ElfHackPatcher.argtypes = []
_create_ElfHackPatcher.restype = ctypes.c_void_p

_destroy_ElfHackPatcher = _binmodify.destroy_ElfHackPatcher
_destroy_ElfHackPatcher.argtypes = [ctypes.c_void_p]
_destroy_ElfHackPatcher.restype = None

_create_CoffHackPatcher = _binmodify.create_CoffHackPatcher
_create_CoffHackPatcher.argtypes = []
_create_CoffHackPatcher.restype = ctypes.c_void_p

_destroy_CoffHackPatcher = _binmodify.destroy_CoffHackPatcher
_destroy_CoffHackPatcher.argtypes = [ctypes.c_void_p]
_destroy_CoffHackPatcher.restype = None

_create_HackStream = _binmodify.create_HackStream
_create_HackStream.argtypes = []
_create_HackStream.restype = ctypes.c_void_p

_destroy_HackStream = _binmodify.destroy_HackStream
_destroy_HackStream.argtypes = [ctypes.c_void_p]
_destroy_HackStream.restype = None

_create_stream = _binmodify.create_stream
_create_stream.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
_create_stream.restype = ctypes.c_void_p

_destroy_stream = _binmodify.destroy_stream
_destroy_stream.argtypes = [ctypes.c_void_p]
_destroy_stream.restype = None


class Result(IntEnum):
    Ok = 0
    UnknownFileType = 1
    BrokenPipe = 2
    ConnectionResetByPeer = 3
    ConnectionTimedOut = 4
    NotOpenForReading = 5
    SocketNotConnected = 6
    WouldBlock = 7
    Canceled = 8
    AccessDenied = 9
    ProcessNotFound = 10
    LockViolation = 11
    Unexpected = 12
    NoSpaceLeft = 13
    DiskQuota = 14
    FileTooBig = 15
    DeviceBusy = 16
    InvalidArgument = 17
    NotOpenForWriting = 18
    NoDevice = 19
    Unseekable = 20
    UNKNOWN_CS_ERR = 21
    ArchNotSupported = 22
    ModeNotSupported = 23
    ArchEndianMismatch = 24
    AddrNotMapped = 25
    NoMatchingOffset = 26
    OffsetNotLoaded = 27
    NoCaveOption = 28
    InvalidPEMagic = 29
    InvalidPEHeader = 30
    InvalidMachine = 31
    MissingPEHeader = 32
    MissingCoffSection = 33
    MissingStringTable = 34
    EdgeNotFound = 35
    InvalidEdge = 36
    InvalidHeader = 37
    InvalidElfMagic = 38
    InvalidElfVersion = 39
    InvalidElfEndian = 40
    InvalidElfClass = 41
    EndOfStream = 42
    OutOfMemory = 43
    InputOutput = 44
    SystemResources = 45
    IsDir = 46
    OperationAborted = 47
    CS_ERR_MEM = 48
    CS_ERR_ARCH = 49
    CS_ERR_HANDLE = 50
    CS_ERR_CSH = 51
    CS_ERR_MODE = 52
    CS_ERR_OPTION = 53
    CS_ERR_DETAIL = 54
    CS_ERR_MEMSETUP = 55
    CS_ERR_VERSION = 56
    CS_ERR_DIET = 57
    CS_ERR_SKIPDATA = 58
    CS_ERR_X86_ATT = 59
    CS_ERR_X86_INTEL = 60
    CS_ERR_X86_MASM = 61
    ArchNotEndianable = 62
    ArchModeMismatch = 63
    NoFreeSpace = 64
    InvalidOptionalHeaderMagic = 65
    IntersectingFileRanges = 66
    IntersectingMemoryRanges = 67
    IllogicalInsnToMove = 68
    IllogicalJmpSize = 69
    UnexpectedEof = 70
    VirtualSizeLessThenFileSize = 71
    InvalidElfRanges = 72
    CantExpandPhdr = 73
    FileszBiggerThenMemsz = 74
    StartAfterEnd = 75
    NoLastCaveChange = 76
    NoNextWriteRecord = 77


class ZigStream:
    def __init__(self, path: bytes) -> None:
        self._this = _create_stream(path, len(path))
        if self._this == 0:
            raise Exception("create failed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _destroy_stream(self._this)

class ElfPatcher:
    def __init__(self, stream: ZigStream) -> None:
        self._this = _create_ElfPatcher()
        if self._this == 0:
            raise Exception("create failed")
        if Result.Ok != (res := Result(_ElfPatcher_init(self._this, stream._this))):
            _destroy_ElfPatcher(self._this)
            raise Exception(f"init failed {repr(res)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _ElfPatcher_deinit(self._this)
        _destroy_ElfPatcher(self._this)


    def pure_patch(self, addr: int, patch: bytes, stream: ZigStream) -> None:
        if Result.Ok != (res := Result(_ElfPatcher_pure_patch(self._this, addr, patch, stream._this))):
            raise Exception(f"pure patch failed {repr(res)}")

class CoffPatcher:
    def __init__(self, stream: ZigStream) -> None:
        self._this = _create_CoffPatcher()
        if self._this == 0:
            raise Exception("create failed")
        if Result.Ok != (res := Result(_CoffPatcher_init(self._this, stream._this))):
            _destroy_CoffPatcher(self._this)
            raise Exception(f"init failed {repr(res)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _CoffPatcher_deinit(self._this)
        _destroy_CoffPatcher(self._this)

    def pure_patch(self, addr: int, patch: bytes, stream: ZigStream) -> None:
        if Result.Ok != (res := Result(_CoffPatcher_pure_patch(self._this, addr, patch, stream._this))):
            raise Exception(f"pure patch failed {repr(res)}")

class HackStream:
    def __init__(self, stream: ZigStream) -> None:
        self._this = _create_HackStream()
        if self._this == 0:
            raise Exception("create failed")
        _HackStream_init(self._this, stream._this)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        _destroy_HackStream(self._this)

    def get_next_write_record(self) -> Tuple[int, bytes] | None:
        out_pos = ctypes.c_uint64()
        out_bytes = ctypes.POINTER(ctypes.c_ubyte)()
        out_bytes_len = ctypes.c_uint64()
        res = Result(_HackStream_get_next_write_record(self._this, ctypes.byref(out_pos), ctypes.byref(out_bytes), ctypes.byref(out_bytes_len)))
        if res == Result.NoNextWriteRecord:
            return None
        elif res == Result.Ok:
            return (out_pos.value, bytes(out_bytes[:out_bytes_len.value]))
        else:
            raise Exception(f"get_last_write_pos failed {repr(res)}")


class FileType(Enum):
    Elf = 0
    Coff = 1

class HackPatcher:
    def __init__(self, stream: HackStream, filetype: FileType) -> None:
        self.filetype = filetype
        match filetype:
            case FileType.Elf:
                self._this = _create_ElfHackPatcher()
                if self._this == 0:
                    raise Exception("create failed")
                if Result.Ok != (res := Result(_ElfHackPatcher_init(self._this, stream._this))):
                    _destroy_ElfHackPatcher(self._this)
                    raise Exception(f"init failed {repr(res)}")
            case FileType.Coff:
                self._this = _create_CoffHackPatcher()
                if self._this == 0:
                    raise Exception("create failed")
                if Result.Ok != (res := Result(_CoffHackPatcher_init(self._this, stream._this))):
                    _destroy_CoffHackPatcher(self._this)
                    raise Exception(f"init failed {repr(res)}")


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        match self.filetype:
            case FileType.Elf:
                _ElfHackPatcher_deinit(self._this)
                _destroy_ElfHackPatcher(self._this)
            case FileType.Coff:
                _CoffHackPatcher_deinit(self._this)
                _destroy_CoffHackPatcher(self._this)

    def pure_patch(self, addr: int, patch: bytes, stream: HackStream) -> None:
        cpatch = (ctypes.c_ubyte * len(patch))(*patch)
        match self.filetype:
            case FileType.Elf:
                if Result.Ok != (res := Result(_ElfHackPatcher_pure_patch(self._this, addr, cpatch, len(patch), stream._this))):
                    raise Exception(f"pure patch failed {repr(res)}")
            case FileType.Coff:
                if Result.Ok != (res := Result(_CoffHackPatcher_pure_patch(self._this, addr, cpatch, len(patch), stream._this))):
                    raise Exception(f"pure patch failed {repr(res)}")

    def get_old_addr(self) -> int:
        out = ctypes.c_uint64()
        match self.filetype:
            case FileType.Elf:
                if Result.Ok != (res := Result(_ElfHackPatcher_get_old_addr(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_old_addr failed {repr(res)}")
                return out.value
            case FileType.Coff:
                if Result.Ok != (res := Result(_CoffHackPatcher_get_old_addr(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_old_addr failed {repr(res)}")
                return out.value
    
    def get_new_addr(self) -> int:
        out = ctypes.c_uint64()
        match self.filetype:
            case FileType.Elf:
                if Result.Ok != (res := Result(_ElfHackPatcher_get_new_addr(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_new_addr failed {repr(res)}")
                return out.value
            case FileType.Coff:
                if Result.Ok != (res := Result(_CoffHackPatcher_get_new_addr(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_new_addr failed {repr(res)}")
                return out.value

    def get_is_end(self) -> bool:
        out = ctypes.c_bool()
        match self.filetype:
            case FileType.Elf:
                if Result.Ok != (res := Result(_ElfHackPatcher_get_is_end(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_new_addr failed {repr(res)}")
                return out.value
            case FileType.Coff:
                if Result.Ok != (res := Result(_CoffHackPatcher_get_is_end(self._this, ctypes.byref(out)))):
                    raise Exception(f"get_new_addr failed {repr(res)}")
                return out.value

    def off_to_addr(self, off: int) -> int:
        out = ctypes.c_uint64()
        match self.filetype:
            case FileType.Elf:
                if Result.Ok != (res := Result(_ElfHackPatcher_off_to_addr(self._this, off, ctypes.byref(out)))):
                    raise Exception(f"_HackPatcher_off_to_addr failed {repr(res)}")
                return out.value
            case FileType.Coff:
                if Result.Ok != (res := Result(_CoffHackPatcher_off_to_addr(self._this, off, ctypes.byref(out)))):
                    raise Exception(f"_HackPatcher_off_to_addr failed {repr(res)}")
                return out.value

