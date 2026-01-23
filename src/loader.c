// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

/*  for asprintf, vasprintf */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include "loader.h"
#include "types.h"
#include "structs.h"

/*  global flag */
extern bool DEBUG;

ph_type load_elf_programh_types(uint64_t flags) {

    /*  elf ph flags  */
    switch (flags)
    {
    case PT_LOAD:
        return PH_LOAD;
    case PT_DYNAMIC:
        return PH_DYNAMIC;
    case PT_INTERP:
        return PH_INTERP;
    case PT_GNU_RELRO:
        return PH_GNU_RELRO;
    case PT_GNU_STACK:
        return PH_GNU_STACK;
    default:
        return PH_UNKNOWN;
    }
}

void load_elf_programhs(Binary *elf, uint64_t *ph_info) {

    void *mem = elf->mem;

    /*  program headers addr    */
    uintptr_t ph_addr = (uintptr_t)mem + ph_info[0];

    /*  Programh link  */
    Link *ph_link = link_init();
    elf->hd->View.ph = ph_link;

    for(uint16_t ph_num = 0; ph_num < ph_info[2]; ph_num++) {

        Programh *ph = MALLOC(1, Programh);
        uintptr_t addr = ph_addr + ph_num * ph_info[1];

        /*  uninit  */
        ph_type sgm_type;
        uintptr_t sgm_vma;
        uint64_t sgm_flag;

        switch (elf->bin_format)
        {
        case BIN_FORMAT_ELF32:
            E32_ph *ph32 = (E32_ph*)addr;
            sgm_type = load_elf_programh_types(ph32->p_type);
            sgm_vma = ph32->p_vaddr;
            sgm_flag = ph32->p_flags;
            break;

        case BIN_FORMAT_ELF64:
            E64_ph *ph64 = (E64_ph*)addr;
            sgm_type = load_elf_programh_types(ph64->p_type);
            sgm_vma = ph64->p_vaddr;
            sgm_flag = ph64->p_flags;
            break;
        }

        ph->sgm_type = sgm_type;
        ph->sgm_vma = sgm_vma;
        ph->sgm_flag = sgm_flag;

        link_append(ph_link, ph);
    }
}

void load_elf_symbol_funcs(Binary *elf, uintptr_t sym_addr, uint64_t upper, uint64_t str_addr, sym_type type) {

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        for(uint64_t sym_num = 0; sym_num < upper; sym_num += sizeof(E32_sym)) {

            E32_sym *sym_st = (E32_sym*)(sym_addr + sym_num);
            Symbol *sym = NULL;

            /*  skip  */
            if (sym_st->st_info & STT_FUNC)
                sym = MALLOC(1, Symbol);
            else continue;

            sym->sym_type=type;

            /*  name from strtab or dynstr  */
            uint64_t offset = sym_st->st_name;

            sym->sym_name = (char *)str_addr + offset;
            sym->sym_addr = sym_st->st_value;

            link_append(elf->sym, sym);
        }
        break;

    case BIN_FORMAT_ELF64:

        for(uint64_t sym_num = 0; sym_num < upper; sym_num += sizeof(E64_sym)) {

            E64_sym *sym_st = (E64_sym*)(sym_addr + sym_num);
            Symbol *sym = NULL;

            /*  skip  */
            if (sym_st->st_info & STT_FUNC)
                sym = MALLOC(1, Symbol);
            else continue;

            sym->sym_type=type;

            /*  name from strtab or dynstr  */
            uint64_t offset = sym_st->st_name;

            sym->sym_name = (char *)str_addr + offset;
            sym->sym_addr = sym_st->st_value;

            link_append(elf->sym, sym);
        }
        break;
    }
}

void load_elf_symbols(Binary *elf) {

    /*  load function symbols  */
    LinkNode *sect_head = elf->sect->head;

    /*  symtab, dynsym, strtab, dynstr and their size  */
    uintptr_t sym_addr[4] = {0};
    uint64_t size[4] = {0};

    while (sect_head) {

        Section *sect = sect_head->data;
        const char *name = sect->sect_name;

        if (strcmp(name,".symtab") == 0) {
            sym_addr[0] = (uintptr_t)sect->sect_bytes;
            size[0] = sect->sect_size;
        }
        else if (strcmp(name,".dynsym") == 0) {
            sym_addr[1] = (uintptr_t)sect->sect_bytes;
            size[1] = sect->sect_size;
        }
        else if (strcmp(name,".strtab") == 0) {
            sym_addr[2] = (uintptr_t)sect->sect_bytes;
            size[2] = sect->sect_size;
        }
        else if (strcmp(name,".dynstr") == 0) {
            sym_addr[3] = (uintptr_t)sect->sect_bytes;
            size[3] = sect->sect_size;
        }

        sect_head = sect_head->next;
    }

    /*  init sym */
    Link *sym_link = link_init();
    elf->sym = sym_link;

    /*  symtab  */
    if (sym_addr[0] != 0) load_elf_symbol_funcs(elf,sym_addr[0],size[0],sym_addr[2],SYM_TYPE_FUNC);

    /*  dynsym  */
    if (sym_addr[1] != 0) load_elf_symbol_funcs(elf,sym_addr[1],size[1],sym_addr[3],SYM_TYPE_DYN_FUNC);

    /* error handle  */
    if (!sym_addr[0] && !sym_addr[1]) LDR_ERROR1(elf->bin_name, "no symbols.");
}

uintptr_t load_elf_section_shstrtab(Binary *elf, uint64_t *sh_info) {

    void *mem = elf->mem;
    char *name = ".shstrtab";
    uint64_t size, flags;

    /*  section contents addr and section vma*/
    uintptr_t sc_addr, vma;
    Section *shstrtab = MALLOC(1, Section);

    /*  section header (.shstrtab) addr  */
    uintptr_t sh_addr = (uintptr_t)mem + sh_info[0] + sh_info[3] * sh_info[2];

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:
        E32_sh *sh32 = (E32_sh*)sh_addr;
        size = sh32->sh_size;
        vma = sh32->sh_addr;
        sc_addr = sh32->sh_offset + (uintptr_t)mem;
        flags = sh32->sh_flags;
        break;

    case BIN_FORMAT_ELF64:
        E64_sh *sh64 = (E64_sh*)sh_addr;
        size = sh64->sh_size;
        vma = sh64->sh_addr;
        sc_addr = sh64->sh_offset + (uintptr_t)mem;
        flags = sh64->sh_flags;
        break;
    }

    shstrtab->sect_name = name;
    shstrtab->sect_size = size;
    shstrtab->sect_vma = vma;
    shstrtab->sect_type = SECT_TYPE_DATA;

    /*  load section contents   */
    uint8_t *bytes = MALLOC(size, uint8_t);
    shstrtab->sect_bytes = bytes;

    for (uint64_t offset = 0; offset < size; offset++)
        bytes[offset] = *(uint8_t*)(sc_addr + offset);
    
    link_append(elf->sect, shstrtab);

    return sc_addr;
}

void load_elf_sections(Binary *elf, uint64_t *sh_info) {

    void *mem = elf->mem;
    char *name;
    uint64_t size, flags;

    /*  section contents addr and section vma*/
    uintptr_t sc_addr, vma;

    /*  section link  */
    Link *sect_link = link_init();
    elf->sect = sect_link;

    /*  we need .shstrtab first */
    uintptr_t shstrtab_addr = load_elf_section_shstrtab(elf, sh_info);

    for (uint64_t sh_num = 0; sh_num < sh_info[1]; sh_num++) {

        /*  we had .shstrtab    */
        if (sh_num == sh_info[3]) continue;

        Section *sect = MALLOC(1,Section);

        /*  section header addr*/
        uintptr_t sh_addr = (uintptr_t)mem + sh_info[0] + sh_num * sh_info[2];

        /*  section name string table addr*/
        uintptr_t sn_addr;

        switch (elf->bin_format)
        {
        case BIN_FORMAT_ELF32:

            E32_sh *sh32 = (E32_sh*)sh_addr;
            sn_addr = shstrtab_addr + sh32->sh_name;
            name = (char *)sn_addr;
            size = sh32->sh_size;
            vma = sh32->sh_addr;
            sc_addr = sh32->sh_offset + (uintptr_t)mem;
            flags = sh32->sh_flags;
            break;

        case BIN_FORMAT_ELF64:

            E64_sh *sh64 = (E64_sh*)sh_addr;
            sn_addr = shstrtab_addr + sh64->sh_name;
            name = (char *)sn_addr;
            size = sh64->sh_size;
            vma = sh64->sh_addr;
            sc_addr = sh64->sh_offset + (uintptr_t)mem;
            flags = sh64->sh_flags;
            break;
        }
        sect->sect_name = name;
        sect->sect_size = size;
        sect->sect_vma = vma;

        if (flags & SHF_EXECINSTR)
            sect->sect_type = SECT_TYPE_CODE;
        else
            sect->sect_type = SECT_TYPE_DATA;

        /*  load section contents   */
        /*  do not load .bss ,IT IS NOBITS  */
        if (strcmp(name, ".bss") != 0) {

            /*  plus one for '\0'   */
            uint8_t *bytes = MALLOC(size + 1, uint8_t);
            sect->sect_bytes = bytes;

            for (uint64_t offset = 0; offset < size; offset++)
                bytes[offset] = *(uint8_t*)(sc_addr + offset);
            bytes[size] = '\0';
        }
        else sect->sect_bytes = NULL;

        link_append(sect_link, sect);
    }
}

void load_elf(Binary *elf) {

    void *mem = elf->mem;

    /*  section headers */
    /*  uint64_t [shtb_addr,sh_num,sh_size,shstr_offset] */
    uint64_t sh_info[4];

    /*  program headers [offset,size,num]  */
    uint64_t ph_info[3];

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        E32_fh *elf32_fh = elf->hd->Fileheader.e32fh;

        /*  section header information  */
        sh_info[0] = elf32_fh->e_shoff;
        sh_info[1] = elf32_fh->e_shnum;
        sh_info[2] = elf32_fh->e_shentsize;
        sh_info[3] = elf32_fh->e_shstrndx;

        /*  program header information   */
        ph_info[0] = elf32_fh->e_phoff;
        ph_info[1] = elf32_fh->e_phentsize;
        ph_info[2] = elf32_fh->e_phnum;
        break;

    case BIN_FORMAT_ELF64:

        E64_fh *elf64_fh = elf->hd->Fileheader.e64fh;

        /*  section header information  */
        sh_info[0] = elf64_fh->e_shoff;
        sh_info[1] = elf64_fh->e_shnum;
        sh_info[2] = elf64_fh->e_shentsize;
        sh_info[3] = elf64_fh->e_shstrndx;

        /*  program header information   */
        ph_info[0] = elf64_fh->e_phoff;
        ph_info[1] = elf64_fh->e_phentsize;
        ph_info[2] = elf64_fh->e_phnum;
        break;
    }

    /*  load program headers */
    load_elf_programhs(elf,ph_info);

    /*  load sections   */
    load_elf_sections(elf,sh_info);
    if(elf->sect->head == NULL) return;

    /*  load symbols    */
    load_elf_symbols(elf);
}


//void load_pe_data_directory(Binary *pe){
//    PE_fh *peh=pe->hd->Fileheader.winfh->pe_fh;
//    uintptr_t option_size=pe->hd->Fileheader.winfh->pe_fh->opt_hdr_size;
//    if(option_size > 0){
//        uintptr_t peh_addr=pe->hd->Fileheader.winfh->mz_fh->peaddr;
//        DD *dd=MALLOC(1,DD);
//        pe->hd->View.dd=dd;
//        *dd=*(DD*)(peh_addr+sizeof(PE_fh));
//    }
//    else pe->hd->View.dd=NULL;
//}

//void load_pe_symbols(Binary *pe){
//    /* todo */
//    pe->sym=NULL;
//}

//void load_pe_sections(Binary *pe,uintptr_t *sh_info){
//    char *name;
//    uint64_t size,flags;
//    uintptr_t vma,sc_addr;
//    Section *sect=MALLOC(1,Section);
//    /*  tail insert */
//    /*  head    */
//    pe->sect=sect;
//    for(int sh_num=0;sh_num < sh_info[2];sh_num++){
//        uintptr_t sh_addr=sh_info[1]+sh_num*sizeof(PE_sh);
//        PE_sh *sh=(PE_sh*)sh_addr;
//        Section *new=MALLOC(1,Section);
//        name=sh->name;
//        size=sh->raw_data_size;
//        vma=sh->virtual_address;
//        flags=sh->flags;
//        sc_addr=sh_info[0]+sh->data_addr;
//        /*  init Section    */
//        new->sect_name=name;
//        new->sect_size=size;
//        new->sect_vma=vma;
//        if(flags & IMAGE_SCN_CNT_CODE)
//            new->sect_type=SECT_TYPE_CODE;
//        else
//            new->sect_type=SECT_TYPE_DATA;
//        /*  load section contents   */
//        /* do not load .bss ,IT IS NOBITS   */
//        if(flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;
//        uint8_t *bytes=MALLOC(size,uint8_t);
//        new->sect_bytes=bytes;
//        for(uint64_t offset=0;offset < size;offset++)
//            bytes[offset]=*(uint8_t*)(sc_addr+offset);
//        sect->sect_next=new;
//        sect=new;
//    }
//    /*  tail    */
//    sect->sect_next=NULL;
//}

//void load_pe(Binary *pe){
//    void *mem=pe->mem;
//    /*  section headers */
//    /*  sh_info [sh_addr,sh_num]   */
//    uintptr_t sh_info[2];
//    /*  section header addr  */
//    uintptr_t peh_addr=pe->hd->Fileheader.winfh->mz_fh->peaddr;
//    uintptr_t option_size=pe->hd->Fileheader.winfh->pe_fh->opt_hdr_size;
//    sh_info[1]=sh_info[0]+sizeof(PE_fh)+peh_addr+option_size;
//    /*  section num */
//    sh_info[2]=pe->hd->Fileheader.winfh->pe_fh->sections;
//    /*  load data directory */
//    load_pe_data_directory(pe);
//    /*  load sections   */
//    load_pe_sections(pe,sh_info);
//    /*  load symbols    */
//    load_pe_symbols(pe);
//}

void load_info_type(Binary *bin, uint64_t type) {

    switch(bin->bin_format)
    {
    case BIN_FORMAT_PE:

        if(type & IMAGE_FILE_EXECUTABLE_IMAGE)
            bin->bin_type = BIN_TYPE_EXEC;
        else if (type & IMAGE_FILE_DLL)
            bin->bin_type = BIN_TYPE_DYN;
        else 
            bin->bin_type = BIN_TYPE_UNKNOWN;
        break;

    case BIN_FORMAT_ELF32:case BIN_FORMAT_ELF64:

        if (type == ET_EXEC || type == ET_REL)
            bin->bin_type = BIN_TYPE_EXEC;
        else if (type == ET_DYN)
            bin->bin_type = BIN_TYPE_DYN;
        else 
            bin->bin_type = BIN_TYPE_UNKNOWN;
        break;
    }
}

void load_info_arch(Binary *bin, uint64_t machine){

    switch(bin->bin_format)
    {
    case BIN_FORMAT_PE:

        switch(machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            bin->bin_arch = ARCH_X86;
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            bin->bin_arch = ARCH_X64;
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            bin->bin_arch = ARCH_ARM64;
            break;
        default:
            bin->bin_arch = ARCH_UNKNOWN;
        }
         
    case BIN_FORMAT_ELF32:case BIN_FORMAT_ELF64:

        switch(machine)
        {
        case EM_386:
            bin->bin_arch = ARCH_X86;
            break;
        case EM_X86_64:
            bin->bin_arch = ARCH_X64;
            break;
        default:
            bin->bin_arch = ARCH_UNKNOWN;
        }
    }
}

void load_info(Binary *bin){

    void *mem = bin->mem;

    /*  explicit type conversion */
    uint16_t *mz = (uint16_t*)mem;
    uint32_t *elf = (uint32_t*)mem;

    /*  elf class uint8  */
    uintptr_t elfclass_addr = (uintptr_t)mem + ELF_CLASS_INDEX;
    uint8_t *elfclass = (uint8_t*)elfclass_addr;
    Header *hd = NULL;

    if (*mz == MZ_MAGIC) {

        bin->bin_format = BIN_FORMAT_PE;
        hd = MALLOC(1,Header);

        /*  load Win file header */
        Winfh *winfh = MALLOC(1,MZ_fh);
        hd->Fileheader.winfh = winfh;

        /*  mz file header  */
        MZ_fh *mzfh = winfh->mz_fh;
        *mzfh = *(MZ_fh*)mem;

        /*  pe file header */
        uintptr_t peh_addr = (uintptr_t)mem + mzfh->peaddr;
        PE_fh *peh = winfh->pe_fh;
        *peh = *(PE_fh*)peh_addr;

        load_info_arch(bin, peh->machine);
        load_info_type(bin, peh->flags);

        /*  DLL has entry   */
        if (peh->opt_hdr_size > 0) { 

            /*  pe entry addr */
            uintptr_t pe_entry_addr = peh_addr + sizeof(PE_fh) + PE_ENTRY_OFFSET;
            bin->entry = *(uint32_t*)pe_entry_addr;
        }
        else bin->entry = 0;
    }
    else if (*elf == ELF_MAGIC && *elfclass == E32_flag) {

        bin->bin_format = BIN_FORMAT_ELF32;
        hd = MALLOC(1,Header);

        /*  ELF file header loaded  */
        hd->Fileheader.e32fh = MALLOC(1,E32_fh);
        E32_fh *e32fh = hd->Fileheader.e32fh;
        *e32fh = *(E32_fh*)mem;

        load_info_arch(bin, e32fh->e_machine);
        load_info_type(bin, e32fh->e_type);

        /*  DSO do not have entry    */
        /*  EXEC is DYN if -fPIE is enabled */
        if (e32fh->e_entry) {
            bin->bin_type = BIN_TYPE_EXEC;
            bin->entry = e32fh->e_entry;
        }
    }
    else if (*elf == ELF_MAGIC && *elfclass == E64_flag) {

        bin->bin_format = BIN_FORMAT_ELF64;
        hd = MALLOC(1,Header);

        /*  ELF file header loaded  */
        hd->Fileheader.e64fh = MALLOC(1,E64_fh);
        E64_fh *e64fh = hd->Fileheader.e64fh;
        *e64fh = *(E64_fh*)mem;

        load_info_arch(bin, e64fh->e_machine);
        load_info_type(bin, e64fh->e_type);

        /*  DSO do not have entry    */
        /*  EXEC is DYN if -fPIE is enabled */
        if (e64fh->e_entry){
            bin->bin_type = BIN_TYPE_EXEC;
            bin->entry = e64fh->e_entry;
        }
    }
    else bin->bin_format = BIN_FORMAT_UNKNOWN;

    /*  Header  loaded  */
    bin->hd = hd;
}

Binary *load_binary(char *fn) {

    /*  file init */
    if (!fn) return NULL;

    /*  open file error  */
    int fd = open(fn,O_RDONLY);
    if (fd < 0) LDR_ERROR2(fn, "file is not exist or not readable");

    /*  fstat error  */
    struct stat file_stat;
    void *file_mem;
    int file_size;
    char *file_name;
    int fs = fstat(fd,&file_stat);
    if (fs < 0) LDR_ERROR2(fn, "fstat failed");

    /*  mmap error  */
    file_size = file_stat.st_size;
    file_name = fn;
    file_mem = mmap(NULL, file_size, PROT_READ,MAP_PRIVATE, fd, 0);
    if (file_mem == MAP_FAILED) LDR_ERROR2(fn, "mmap failed.");

    /*  Binary init */
    Binary *bin = MALLOC(1, Binary);
    memset(bin, 0, sizeof(Binary));

    bin->mem = file_mem;
    bin->bin_size = file_size;
    bin->bin_name = file_name;
    load_info(bin);

    /*  load bin error  */
    if (bin->bin_type < 0) LDR_ERROR2(fn, "unsupported binary type.");
    if (bin->bin_format < 0) LDR_ERROR2(fn, "unsupported binary format.");
    if (bin->bin_arch < 0) LDR_ERROR2(fn, "unsupported architecture.");
    if (bin->entry == 0 && bin->bin_type == BIN_TYPE_EXEC) LDR_ERROR1(fn, "cannot find entry point.");

    bin->sect = NULL;
    bin->sym = NULL;

    switch (bin->bin_format)
    {
    case BIN_FORMAT_ELF32:case BIN_FORMAT_ELF64:

        load_elf(bin);
        break;

    // case BIN_FORMAT_PE:
    //    load_pe(bin);
    //    break;
    }

    /*  load elf/pe error  */
    if (bin->sect->head == NULL) LDR_ERROR1(fn, "load sections failed.");
    if (bin->sym->head == NULL) LDR_ERROR1(fn, "load symbols failed.");
    if (bin->hd == NULL) LDR_ERROR1(fn, "load headers failed.");

    return bin;
}

size_t dis_asm(Binary *bin, csh *handle, cs_insn **insn) {

    /*  front two opcodes: 5 bytes  */
    /*  f3 0f 1e fa endbr64 */
    /*  55  push rbp/ebp    */
    unsigned long size = 5;

    Section *text;
    LinkNode *sect_link = bin->sect->head;

    while (sect_link) {

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".text") == 0) {
            text = sect;
            break;
        }

        sect_link = sect_link->next;
    }

    if(!text) LDR_ERROR2(bin->bin_name, "text section not found.");

    /*  func offset */
    unsigned long offset = 0;
    Symbol *main_first_func = NULL;
    LinkNode *sym_link = bin->sym->head;

    switch (bin->bin_type)
    {
    case BIN_TYPE_EXEC:

        /*  locate main */
        while(sym_link){

            /*  addr not 0  */
            Symbol *sym = sym_link->data;

            if (strcmp(sym->sym_name, "main") == 0) {

                main_first_func = sym;
                break;
            }

            sym_link = sym_link->next;
        }

        if(!main_first_func) return 0;
        offset = main_first_func->sym_addr - text->sect_vma;
        break;

    case BIN_TYPE_DYN:

        /*  locate first local func */
        while(sym_link){

            /*  addr not 0  */
            Symbol *sym = sym_link->data;

            if(sym->sym_addr){

                main_first_func = sym;
                break;
            }
            sym_link = sym_link->next;
        }

        offset = main_first_func->sym_addr - text->sect_vma;
        break;
    }

    size_t count;
    enum cs_arch arch;
    enum cs_mode mode;

    switch (bin->bin_arch)
    {
    case ARCH_X86:
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
        break;
    case ARCH_X64:
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
        break;
    case ARCH_ARM64:
        arch = CS_ARCH_ARM64;
        mode =CS_MODE_ARM;
        break;
    default:
        LDR_ERROR2(bin->bin_name, "disasm arch not support.");
    }

	if (cs_open(arch, mode, handle) != CS_ERR_OK) return -1;
	count = cs_disasm(*handle, text->sect_bytes + offset, size ,0x1000, 0, insn);
    
    return count;
}

void free_binary(Binary *bin) {

    /* free mmap  */
    if (bin->mem)
        munmap(bin->mem, bin->bin_size);
    
    /*  free sym  */
    if (bin->sym) {

        LinkNode *sym = bin->sym->head;

        while(sym){

            LinkNode *tmp = sym;
            sym = sym->next;

            free(tmp->data);
            free(tmp);
        }

        free(bin->sym);
    }

    /* free sect  */
    if (bin->sect) {

        LinkNode *sect = bin->sect->head;

        while(sect){

            LinkNode *tmp = sect;
            sect = sect->next;
            Section *data = tmp->data;

            if(data->sect_bytes) free(data->sect_bytes);

            free(data);
            free(tmp);
        }

        free(bin->sect);
    }

    /* free hd  */
    if (bin->hd) {

        /*  union maybe cause double free   */
        if (bin->hd->View.ph) {

            LinkNode *ph = bin->hd->View.ph->head;

            while(ph){

                LinkNode *tmp = ph;
                ph = ph->next;

                free(tmp->data);
                free(tmp);
            }
        }

        /*  ph and peh use same pointer */
        free(bin->hd->View.ph);

        /*  e32fh e64fh and mzfh use same pointer */
        if(bin->hd->Fileheader.e32fh) free(bin->hd->Fileheader.e32fh);

        free(bin->hd);
    }

    /* free bin  */
    free(bin);
}