// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#ifndef _LDR_H_
#define _LDR_H_

#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include "pe.h"
#include "types.h"
# include "structs.h"

/*  expection handle    */
#define LDR_ERROR1(info1, info2) \
    if (DEBUG) \
    printf("LDR ERROR:%s %s\n", info1, info2) \

#define LDR_ERROR2(info1, info2) { \
    if (DEBUG) \
    printf("LDR ERROR:%s %s\n", info1, info2); \
    return NULL; \
}

#define LDR_ERROR3(info1, info2) { \
    if (DEBUG) \
    printf("LDR ERROR:%s %s\n", info1, info2); \
    return; \
}

/*  elf format  */
#define ELF_MAGIC 0x464c457f
#define ELF_CLASS_INDEX  sizeof(uint32_t)
#define E32_flag 1
#define E64_flag 2

typedef Elf32_Ehdr E32_fh;
typedef Elf64_Ehdr E64_fh;
typedef Elf32_Shdr E32_sh;
typedef Elf64_Shdr E64_sh;
typedef Elf32_Sym E32_sym;
typedef Elf64_Sym E64_sym;
typedef Elf32_Phdr E32_ph;
typedef Elf64_Phdr E64_ph;
typedef Elf32_Dyn E32_dyn;
typedef Elf64_Dyn E64_dyn;

/*  pe format   */
#define MZ_MAGIC 0x5a4d

/*  do not forget the () */
#define PE_ENTRY_OFFSET (sizeof(uint32_t) <<2)

typedef struct mz_hdr MZ_fh;
typedef struct pe_hdr PE_fh;
typedef struct section_header PE_sh;
typedef struct data_directory DD;

/*  enum type   */
typedef enum {
    BIN_TYPE_UNKNOWN = -1,
    BIN_TYPE_EXEC,
    BIN_TYPE_DYN,
}bin_type;

typedef enum {
    BIN_FORMAT_UNKNOWN = -1,
    BIN_FORMAT_ELF32,
    BIN_FORMAT_ELF64,
    BIN_FORMAT_PE
}bin_format;

typedef enum {
    ARCH_UNKNOWN = -1,
    ARCH_X86,
    ARCH_X64,
    ARCH_ARM64
}bin_arch;

typedef enum {
    SYM_TYPE_FUNC = 0,
    SYM_TYPE_DYN_FUNC,
}sym_type;

typedef enum {
    SECT_TYPE_CODE = 0,
    SECT_TYPE_DATA,
}sect_type;

typedef enum {
    PH_UNKNOWN = -1,
    PH_DYNAMIC,
    PH_GNU_RELRO,
    PH_GNU_STACK,
    PH_LOAD,
    PH_INTERP,
}ph_type;

/*  struct Symbol: Section: Binary  */
typedef struct Symbol {
    sym_type sym_type;
    /*  function name or string content */
    const char *sym_name;
    uint64_t sym_addr;
}Symbol;

typedef struct Section {
    sect_type sect_type;
    const char *sect_name;
    uintptr_t sect_vma;
    uint64_t sect_size;
    /*  contents    */
    uint8_t *sect_bytes;
}Section;

typedef struct {
    MZ_fh *mz_fh;
    PE_fh *pe_fh;
}Winfh;

typedef struct Programh {
    /*  segments type   */
    ph_type sgm_type;
    /*  segments vma    */
    uintptr_t sgm_vma;
    /*  segment flag    */
    uint64_t sgm_flag;
}Programh;

typedef struct Header {
    /*  file header */
    union{
        /*  elf file header */
        E32_fh *e32fh;
        E64_fh *e64fh;
        /*  win file header  */
        Winfh *winfh;
    }Fileheader;
    /*  loading view  */
    union{
        /*  Programh Link  */
        Link *ph;
        DD *dd;
    }View;
}Header;

typedef struct Binary {
    /*  mmap address    */
    void *mem;
    /* file format */
    bin_type bin_type;
    /* file type */
    bin_format bin_format;
    /*   arch  */
    bin_arch bin_arch;
    /*   binary name */
    const char *bin_name;
    /*   binary size */
    uint64_t bin_size;
    /*   entry point */
    uint64_t entry;
    /*  Symbol Link  */
    Link *sym;
    /*  Section Link */
    Link *sect;
    /*  binary headers */
    Header *hd;
}Binary;

typedef struct {
  char *insn_buffer;
  unsigned int reenter;
}stream_state;

#endif