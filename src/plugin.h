#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

enum Filetype {
  Elf = 0,
  Coff = 1,
};

enum Status {
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
};

extern "C" Status init_ida_patcher(void** patcher, char* path, uint32_t len, Filetype filetype);
extern "C" void deinit_ida_patcher(void* ctx);
extern "C" Status pure_patch(void* ctx, uint64_t addr, const uint8_t* patch_bytes, uint64_t len);

struct plugin_ctx_t;

//-------------------------------------------------------------------------
// The main action to invoke the plugin
struct inline_hook_ah_t : public action_handler_t
{
  plugin_ctx_t &ctx;
  inline_hook_ah_t(plugin_ctx_t &_ctx) : ctx(_ctx) {}
  virtual int idaapi activate(action_activation_ctx_t *) override; 

  virtual action_state_t idaapi update(action_update_ctx_t * update_ctx) override; 
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  void* patch_ctx;
  plugin_ctx_t(Filetype ftype, void* _patch_ctx);
  ~plugin_ctx_t();
  inline_hook_ah_t inline_hook_ah = inline_hook_ah_t(*this);
  const action_desc_t inline_hook_act;
  bool register_main_action();
  virtual bool idaapi run(size_t arg) override;
};
