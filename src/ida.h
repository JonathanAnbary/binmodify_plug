#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

//---------------------------------------------------------------------------
// Linux C mode compiler already has these types defined
#if !defined(__LINUX__) || defined(__cplusplus)
typedef unsigned char  uchar;   ///< unsigned 8 bit value
typedef unsigned short ushort;  ///< unsigned 16 bit value
typedef unsigned int   uint;    ///< unsigned 32 bit value
#endif

#if defined(_MSC_VER)
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#elif defined(__GNUC__)
typedef unsigned long long uint64;
typedef          long long int64;
#endif

typedef          char   int8;   ///< signed 8 bit value
typedef signed   char   sint8;  ///< signed 8 bit value
typedef unsigned char   uint8;  ///< unsigned 8 bit value
typedef          short  int16;  ///< signed 16 bit value
typedef unsigned short  uint16; ///< unsigned 16 bit value
typedef          int    int32;  ///< signed 32 bit value
typedef unsigned int    uint32; ///< unsigned 32 bit value


/// \typedef{ea_t,    effective address}
/// \typedef{sel_t,   segment selector}
/// \typedef{asize_t, memory chunk size}
/// \typedef{adiff_t, address difference}
/// \def{SVAL_MIN, minimum value for an object of type int}
/// \def{SVAL_MAX, maximum value for an object of type int}
/// \def{FMT_EA,   format specifier for ::ea_t values}
#ifdef __EA64__
  typedef uint64 ea_t;
  typedef uint64 sel_t;
  typedef uint64 asize_t;
  typedef int64 adiff_t;
  #define FMT_EA FMT_64
  #ifdef __GNUC__
    #define SVAL_MIN LLONG_MIN
    #define SVAL_MAX LLONG_MAX
  #else
    #define SVAL_MIN _I64_MIN
    #define SVAL_MAX _I64_MAX
  #endif
#else
  typedef uint32 ea_t;
  typedef uint32 sel_t;
  typedef uint32 asize_t;
  typedef int32 adiff_t;
  #define SVAL_MIN INT_MIN
  #define SVAL_MAX INT_MAX
  #define FMT_EA ""
#endif

// segment.hpp
bool set_segm_end(ea_t ea, ea_t newend, int flags);
bool set_segm_start(ea_t ea, ea_t newstart, int flags);
/// \defgroup ADDSEG_ Add segment flags
/// Passed as 'flags' parameter to add_segm_ex()
///@{
#define ADDSEG_NOSREG   0x0001  ///< set all default segment register values to #BADSEL
                                ///< (undefine all default segment registers)
#define ADDSEG_OR_DIE   0x0002  ///< qexit() if can't add a segment
#define ADDSEG_NOTRUNC  0x0004  ///< don't truncate the new segment at the beginning of the next segment if they overlap.
                                ///< destroy/truncate old segments instead.
#define ADDSEG_QUIET    0x0008  ///< silent mode, no "Adding segment..." in the messages window
#define ADDSEG_FILLGAP  0x0010  ///< fill gap between new segment and previous one.
                                ///< i.e. if such a gap exists, and this gap is less
                                ///< than 64K, then fill the gap by extending the
                                ///< previous segment and adding .align directive
                                ///< to it. This way we avoid gaps between segments.
                                ///< too many gaps lead to a virtual array failure.
                                ///< it cannot hold more than ~1000 gaps.
#define ADDSEG_SPARSE   0x0020  ///< use sparse storage method for the new ranges
                                ///< of the created segment. please note that the
                                ///< ranges that were already enabled before
                                ///< creating the segment will not change their
                                ///< storage type.
#define ADDSEG_NOAA     0x0040  ///< do not mark new segment for auto-analysis
#define ADDSEG_IDBENC   0x0080  ///< 'name' and 'sclass' are given in the IDB encoding;
                                ///< non-ASCII bytes will be decoded accordingly
/// Add a new segment, second form.
/// Segment alignment is set to #saRelByte.
/// Segment combination is "public" or "stack" (if segment class is "STACK").
/// Addressing mode of segment is taken as default (16bit or 32bit).
/// Default segment registers are set to #BADSEL.
/// If a segment already exists at the specified range of addresses,
/// this segment will be truncated. Instructions and data in the old
/// segment will be deleted if the new segment has another addressing
/// mode or another segment base address.
/// \param para    segment base paragraph.
///                if paragraph can't fit in 16bit, then a new selector is
///                allocated and mapped to the paragraph.
/// \param start   start address of the segment.
///                if start==#BADADDR then start <- to_ea(para,0).
/// \param end     end address of the segment. end address should be higher than
///                start address. For emulate empty segments, use #SEG_NULL segment
///                type. If the end address is lower than start address, then fail.
///                If end==#BADADDR, then a segment up to the next segment
///                will be created (if the next segment doesn't exist, then
///                1 byte segment will be created).
///                If 'end' is too high and the new segment would overlap
///                the next segment, 'end' is adjusted properly.
/// \param name    name of new segment. may be nullptr
/// \param sclass  class of the segment. may be nullptr.
///                type of the new segment is modified if class is one of
///                predefined names:
///                 - "CODE"  -> #SEG_CODE
///                 - "DATA"  -> #SEG_DATA
///                 - "CONST" -> #SEG_DATA
///                 - "STACK" -> #SEG_BSS
///                 - "BSS"   -> #SEG_BSS
///                 - "XTRN"  -> #SEG_XTRN
///                 - "COMM"  -> #SEG_COMM
///                 - "ABS"   -> #SEG_ABSSYM
/// \param flags   \ref ADDSEG_
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed

bool add_segm(
        ea_t para,
        ea_t start,
        ea_t end,
        const char *name,
        const char *sclass,
        int flags);



// bytes.hpp
void put_bytes(ea_t ea, const void *buf, size_t size);

typedef void func_t;
func_t * get_func(ea_t ea);
bool append_func_tail(func_t *pfn, ea_t ea1, ea_t ea2);

typedef void insn_t;

#ifdef __EA64__
#define SIZEOF_INSN_T 360
#else
#define SIZEOF_INSN_T 216
#endif


int decode_insn(insn_t *out, ea_t ea);

void * qalloc(size_t size);                              ///< System independent malloc
void * qrealloc(void *alloc, size_t newsize);            ///< System independent realloc
void * qcalloc(size_t nitems, size_t itemsize);          ///< System independent calloc
void   qfree(void *alloc);                               ///< System independent free
