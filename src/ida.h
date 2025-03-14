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
