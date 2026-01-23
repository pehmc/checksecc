// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "functions.h"
#include "types.h"
#include "loader.h"

/*  global flag */
extern bool EXTENTED;
extern bool DEBUG;

/*  elf name    */
char *chk_elf_name(Binary *elf) {

    char *ret = str_colored(BLUE_FMT, elf->bin_name);
    return ret;
}

/*  check relro */
char *chk_elf_relro(Binary *elf) {

    bool relro = false;
    bool full = false;

    /*  search program header   */
    LinkNode *ph_link = elf->hd->View.ph->head;

    while(ph_link){

        Programh *ph = ph_link->data;

        /*  segment type == GNU_RELRO*/
        if (ph->sgm_type == PH_GNU_RELRO) {

            relro=true;
            break;
        }

        ph_link = ph_link->next;
    }

    /*  search dynamic section  */
    Section *dynamic = NULL;
    LinkNode *sect_link = elf->sect->head;

    while(sect_link){

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".dynamic") == 0) {

            dynamic = sect;
            break;
        }

        sect_link = sect_link->next;
    }

    if(!dynamic) CHK_ERROR4("dynamic section not found.");

    /*  search BIND_NOW falg    */
    uint8_t *bytes = dynamic->sect_bytes;
    uint64_t dyn_size;
    uint16_t dyn_num;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        dyn_size = sizeof(E32_dyn);
        dyn_num = dynamic->sect_size / dyn_size;

        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn32_addr = (uintptr_t)bytes + num * dyn_size;
            E32_dyn *dyn32 = (E32_dyn*)dyn32_addr;

            /*  d_tag == DT_FLAGS   */
            if (dyn32->d_tag == DT_FLAGS)
                /*  d_val == DT_BIND_NOW    */
                if (dyn32->d_un.d_val == DF_BIND_NOW)
                    full=true;
        }
        break;

    case BIN_FORMAT_ELF64:

        dyn_size = sizeof(E64_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn64_addr = (uintptr_t)bytes + num * dyn_size;
            E64_dyn *dyn64 = (E64_dyn*)dyn64_addr;

            /*  d_tag == DT_FLAGS   */
            if (dyn64->d_tag == DT_FLAGS)
                    /*  d_val == DT_BIND_NOW    */
                    if (dyn64->d_un.d_val == DF_BIND_NOW)
                        full=true;
        }
        break;
    }

    if (relro) {

        if(full) return str_colored(GREEN_FMT, "Full RELRO");
        else return str_colored(YELLOW_FMT, "Partial RELRO");
    }
    else return str_colored(RED_FMT, "No RELRO");
}

/*  check stack canary  */
char *chk_elf_stack_canary(Binary *elf) {

    bool canary = false;
    LinkNode *sym_link = elf->sym->head;

    /*  search function symbol  */
    while(sym_link){

        Symbol *sym = sym_link->data;
        const char* name = sym->sym_name;

        if (strcmp(name, "__stack_chk_fail") == 0 || \
            strcmp(name, "__stack_chk_guard") == 0 || \
            strcmp(name, "__intel_security_cookie") == 0)
            canary = true;

        sym_link = sym_link->next;
    }

    if(canary) return str_colored(GREEN_FMT, "Canary found");
    else return str_colored(RED_FMT, "No Canary found");
}

/*  
 *  check nx    
 *  NX depends on CPU NX flag
 */
char *chk_elf_nx(Binary *elf) {

    /*  check cpu nx first  */
    bool nx = chk_cpu_nx();

    if (!nx) CHK_ERROR4("CPU not support nx or Check CPU NX failed");

    bool stack = false;
    bool rwx = false;

    /*  search program header   */
    Programh *gnu_stack  =NULL;
    LinkNode *ph_link = elf->hd->View.ph;

    while(ph_link){

        Programh *ph = ph_link->data;

        /*  segment type == GNU_STACK*/
        if (ph->sgm_type == PH_GNU_STACK) {

            stack = true;
            gnu_stack = ph;
            break;
        }
        ph_link = ph_link->next;
    }

    /*  segment flag == RWE */
    if (gnu_stack && (gnu_stack->sgm_flag & PF_X & PF_W & PF_R))
        rwx=true;
    
    if (stack && !rwx) return str_colored(GREEN_FMT, "NX enabled");
    else return str_colored(RED_FMT, "NX disabled");
}

/*
 * check pie   
 * PIE depends on ASLR
 */
char *chk_elf_pie(Binary *elf) {

    /*  check aslr first  */ 
    unsigned int aslr=chk_user_aslr_flag();

    if (aslr == 0) CHK_ERROR4("Check ASLR failed");
    if (aslr == 48) return str_colored(RED_FMT, "ASLR LEVEL 0");

    uint32_t type;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:
        type = elf->hd->Fileheader.e32fh->e_type;
        break;
    case BIN_FORMAT_ELF64:
        type = elf->hd->Fileheader.e64fh->e_type;
    }

    switch (type)
    {
    case ET_EXEC:
        return str_colored(RED_FMT, "No PIE");
    case ET_DYN:
        goto dyn;
    case ET_REL:
        return str_colored(YELLOW_FMT, "REL");
    default:
        return NULL;
    }

    /*  DYN */
    dyn:

    bool debug = false;

    /*  search dynamic section  */
    Section *dynamic = NULL;
    LinkNode *sect_link = elf->sect->head;

    while(sect_link){

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".dynamic") == 0) {

            dynamic = sect;
            break;
        }

        sect_link = sect_link->next;
    }

    if(!dynamic) CHK_ERROR4("dynamic section not found.");

    /*  search DEBUG    */
    uint8_t *bytes = dynamic->sect_bytes;
    uint64_t dyn_size;
    uint16_t dyn_num;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        dyn_size = sizeof(E32_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn32_addr = (uintptr_t)bytes + num * dyn_size;
            E32_dyn *dyn32 = (E32_dyn*)dyn32_addr;

            /*  d_tag == DT_DEBUG   */
            if (dyn32->d_tag == DT_DEBUG) debug = true;
        }
        break;

    case BIN_FORMAT_ELF64:

        dyn_size = sizeof(E64_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn64_addr = (uintptr_t)bytes + num * dyn_size;
            E64_dyn *dyn64 = (E64_dyn*)dyn64_addr;

            /*  d_tag == DT_DEBUG   */
            if (dyn64->d_tag == DT_DEBUG) debug = true;
        }
        break;
    }

    if(debug) return str_colored(GREEN_FMT, "PIE enabled");
    else return str_colored(YELLOW_FMT, "DSO");
}

/*  check rpath */
char *chk_elf_rpath(Binary *elf) {

    /*  search dynamic section  */
    Section *dynamic = NULL;
    LinkNode *sect_link = elf->sect->head;

    while(sect_link){

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".dynamic") == 0) {

            dynamic = sect;
            break;
        }

        sect_link = sect_link->next;
    }

    if(!dynamic) CHK_ERROR4("dynamic section not found.");

    
    bool rpath = false;

    /*  search RPATH    */
    uint8_t *bytes = dynamic->sect_bytes;
    uint64_t dyn_size;
    uint16_t dyn_num;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        dyn_size = sizeof(E32_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn32_addr = (uintptr_t)bytes + num * dyn_size;
            E32_dyn *dyn32 = (E32_dyn*)dyn32_addr;

            /*  d_tag == DT_RPATH   */
            if(dyn32->d_tag == DT_RPATH) rpath = true;
        }
        break;

    case BIN_FORMAT_ELF64:

        dyn_size = sizeof(E64_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn64_addr = (uintptr_t)bytes + num * dyn_size;
            E64_dyn *dyn64 = (E64_dyn*)dyn64_addr;

            /*  d_tag == DT_RPATH   */
            if(dyn64->d_tag == DT_RPATH) rpath = true;
        }
        break;
    }
    
    if(rpath) return str_colored(RED_FMT, "RPATH");
    else return str_colored(GREEN_FMT, "NO RPATH");
}

/*  check runpath   */
char *chk_elf_runpath(Binary *elf) {

    /*  search dynamic section  */
    Section *dynamic = NULL;
    LinkNode *sect_link = elf->sect->head;

    while(sect_link){

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".dynamic") == 0) {

            dynamic = sect;
            break;
        }

        sect_link = sect_link->next;
    }

    if(!dynamic) CHK_ERROR4("dynamic section not found.");

    
    bool runpath = false;

    /*  search RUNPATH    */
    uint8_t *bytes = dynamic->sect_bytes;
    uint64_t dyn_size;
    uint16_t dyn_num;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        dyn_size = sizeof(E32_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn32_addr = (uintptr_t)bytes + num * dyn_size;
            E32_dyn *dyn32 = (E32_dyn*)dyn32_addr;

            /*  d_tag == DT_RUNPATH   */
            if(dyn32->d_tag == DT_RUNPATH) runpath = true;
        }
        break;

    case BIN_FORMAT_ELF64:

        dyn_size = sizeof(E64_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn64_addr = (uintptr_t)bytes + num * dyn_size;
            E64_dyn *dyn64 = (E64_dyn*)dyn64_addr;

            /*  d_tag == DT_RUNPATH   */
            if(dyn64->d_tag == DT_RUNPATH) runpath = true;
        }
        break;
    }
    
    if(runpath) return str_colored(RED_FMT, "RUNPATH");
    else return str_colored(GREEN_FMT, "NO RUNPATH");
}

/*  check stripped  */
char *chk_elf_stripped(Binary *elf) {

    /*  search FUNC type    */
    bool strip = true;
    LinkNode *sym_link = elf->sym;

    while (sym_link) {

        Symbol *sym = sym_link->data;

        if (sym->sym_type == SYM_TYPE_FUNC) {

            strip = false;
            break;
        }

        sym_link = sym_link->next;
    }

    if(strip) return str_colored(GREEN_FMT, "Stripped");
    else return str_colored(RED_FMT, "Not Stripped");
}

char *chk_elf_frame_pointer(Binary *elf) {

    bool sp = false;

    /*  push rbp / push ebp */
    char *push = "push";
    char *stack_frame = NULL;

    switch (elf->bin_arch)
    {
    case ARCH_X86:
        stack_frame = "ebp";
        break;
    case ARCH_X64:
        stack_frame = "rbp";
        break;
    default:
        return NULL;
    }

    cs_insn *insn;
    csh handle;
    size_t count = dis_asm(elf, &handle, &insn);

    if (count > 0) {

		size_t j;
		for (j = 0; j < count; j++) {

            if (strstr(insn[j].mnemonic,push) && strstr(insn[j].op_str, stack_frame)) {

                sp = true;
                break;
            }
		}

		cs_free(insn, count);
        cs_close(&handle);
	} 
    else {
        cs_close(&handle);
        CHK_ERROR4("Oops! This EXE is Stripped, check frame pointer by yourself.");
    }

    if(sp) return str_colored(RED_FMT, "Not Omit");
    else return str_colored(GREEN_FMT, "Omit");
}

/*  
    check sanitized gcc/llvm
*/
void chk_elf_sanitized(Binary *elf, Link *info) {

    /*  
        CHK_SAN_NUM 7
        [asan, tsan, msan, lsan, 
        ubsan, dfsan, safestack]
    */
    bool san_boolean[CHK_SAN_NUM] = {false};

    char *san_str[CHK_SAN_NUM] = {
        "asan",
        "tsan",
        "msan",
        "lsan",
        "ubsan",
        "dfsan",
        "safestack"
    };

    /*  check dynsym for these strings*/
    LinkNode *sym_link = elf->sym->head;

    while(sym_link){

        Symbol *sym = sym_link->data;

        /*  only need dynamic func*/
        if (sym->sym_type == SYM_TYPE_FUNC) {

            sym_link = sym_link->next;
            continue;
        }

        const char *name = sym->sym_name;

        /*  compare strlen(san_str[.]) bytes */
        for (int i = 0; i < CHK_SAN_NUM; i++) {

            char *str = str_colored("__%s", san_str[i]);
            size_t size = strlen(str);

            if (strncmp(name, str, size) == 0) {
                san_boolean[i] = true;
            }
        }

        sym_link = sym_link->next;
    }
    
    /*  CHK_CET_NUM 2   */
    bool cet_boolean[CHK_CET_NUM] = {false};

    char *cet_str[CHK_CET_NUM] = {
        "cet-ibt",
        "cet-shadow-stack"
    };

    /*  
        check indirect branch trace 
        gcc -fcf-protection=full
        search endbr64 from .text
    */
    cs_insn *insn;
    csh handle;
    size_t count = dis_asm(elf, &handle, &insn);
    char *endbr64 = "endbr64";

    if (count > 0) {

		size_t j;
		for (j = 0; j < count; j++) {

            if(strstr(insn[j].mnemonic,endbr64)) {
                cet_boolean[0] = true;
                break;
            }
		}

		cs_free(insn, count);
        cs_close(&handle);
	} 
    else {
        cs_close(&handle);
        CHK_PRINT1("Oops! This EXE is Stripped, check cet-ibt by yourself.");
    }

    /*  
        check shadow call stack
        now only for aarch64
        so false
    */
    cet_boolean[1] = false;

    /*  san format  */
    char *type = "Sanitized %s";

    /* loop san  */
    for (int i = 0; i < CHK_SAN_NUM; i++) {

        chk_info *san_info = MALLOC(1, chk_info);
        san_info->chk_type = str_colored(type, san_str[i]);

        if (san_boolean[i] ==false) san_info->chk_result = str_colored(RED_FMT, "NO");
        else san_info->chk_result = str_colored(GREEN_FMT, "Yes");

        link_append(info, san_info);
    }

    for (int i = 0; i < CHK_CET_NUM; i++) {

        chk_info *cet_info = MALLOC(1, chk_info);
        cet_info->chk_type = str_colored(type, cet_str[i]);

        if (cet_boolean[i] ==false) cet_info->chk_result = str_colored(RED_FMT, "NO");
        else cet_info->chk_result = str_colored(GREEN_FMT, "Yes");

        link_append(info, cet_info);
    }
}

/*  check fortified */
void chk_elf_fortified(Binary *elf, Link *info) {

    /*  check FORTIFY_SOURCE    */
    /*  search dynamic and dynstr  section*/
    Section *dynamic = NULL;
    Section *dynstr = NULL;

    LinkNode *sect_link = elf->sect->head;

    while (sect_link) {

        Section *sect = sect_link->data;

        if (strcmp(sect->sect_name, ".dynamic") == 0) dynamic = sect;
        if (strcmp(sect->sect_name, ".dynstr") == 0) dynstr = sect;

        sect_link = sect_link->next;
    }

    if (!dynamic) CHK_ERROR4("dynamic section not found.");
    if (!dynstr) CHK_ERROR4("dynstr section not found.");

    /*  search DT_NEEDED on .dynstr    */
    char *libc_version = NULL;
    uint64_t offset, addr;
    char *libc_str = "libc.so";
    size_t libc_str_len = strlen(libc_str);

    uint8_t *bytes = dynamic->sect_bytes;
    uint64_t dyn_size;
    uint16_t dyn_num;

    switch (elf->bin_format)
    {
    case BIN_FORMAT_ELF32:

        dyn_size = sizeof(E32_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn32_addr = (uintptr_t)bytes + num * dyn_size;
            E32_dyn *dyn32 = (E32_dyn*)dyn32_addr;

            /*  d_tag == DT_NEEDED  */
            if (dyn32->d_tag == DT_NEEDED){

                /*  offset = d_un.d_val  */
                offset = dyn32->d_un.d_val;

                /*  so addr */
                addr = dynstr->sect_bytes + offset;

                if (strncmp(libc_str, addr, libc_str_len) == 0) libc_version = addr;
            }
        }
        break;
    case BIN_FORMAT_ELF64:

        dyn_size = sizeof(E64_dyn);
        dyn_num = dynamic->sect_size / dyn_size;
 
        for (uint16_t num = 0; num < dyn_num; num++) {

            uintptr_t dyn64_addr = (uintptr_t)bytes + num * dyn_size;
            E64_dyn *dyn64 = (E64_dyn*)dyn64_addr;

            /*  d_tag == DT_NEEDED  */
            if (dyn64->d_tag == DT_NEEDED){

                /*  offset = d_un.d_val  */
                offset = dyn64->d_un.d_val;

                /*  so addr */
                addr = dynstr->sect_bytes + offset;

                if (strncmp(libc_str, addr, libc_str_len) == 0) libc_version = addr;
            }
        }
        break;
    }

    if (!libc_version) CHK_ERROR4("libc and libstdc++ are not used.");

    /*  lib path    */
    char *lib_path[CHK_LIB_PATH_NUM] = {
        "/lib%s",
        "/lib64%s",
        "/lib32%s"
    };

    /*  load libc version, indexing by bin_arch*/
    char *arch_path[CHK_LIBC_PATH_NUM] = {
        /*  ARCH_X86 = 0    */
        "/i386-linux-gnu/%s",
        "/x86_64-linux-gnu/%s",
        "/aarch64-linux-gnu/%s"
    };

    char *libc_path = NULL;
    Binary *libc = NULL;

    /*  append libc_path  */
    /*  ignore DEBUG flag first  */
    DEBUG = false;

    for(int num = 0; num < CHK_LIB_PATH_NUM; num++) {

        libc_path = str_colored(lib_path[num], arch_path[elf->bin_arch]);
        libc_path = str_colored(libc_path, libc_version);

        /*  load libc   */
        libc = load_binary(libc_path);

        if(libc) break;
    }

    /*  reload DEBUG flag   */
    DEBUG = true;

    if (!libc) CHK_ERROR4("libc and libstdc++ are not found.");

    /*  keep fortify source funcs in hashmap and count it */
    hashmap *hm = hashmap_init();
    size_t fortify_count = 0;

    LinkNode *sym_link = libc->sym->head;

    while (sym_link) {

        char *suffix = "_chk";

        Symbol *sym = sym_link->data;
        char *libc_func_str = sym->sym_name;

        if (strcmp(libc_func_str + strlen(libc_func_str) - strlen(suffix), suffix) == 0 ) {

            /*  insert into hashmap  */
            bool hit = false;
            hashmap_append(hm, hit, libc_func_str);
            fortify_count++;
        }

        sym_link = sym_link->next;
    }

    /*  return chk_info    */
    char *type = "Fortified %s";
    chk_info *info=MALLOC(1,chk_info);

    /*  compare elf funcs with libc funcs   */
    /*  count fortified */
    size_t fortified_count = 0;
    sym_link = elf->sym->head;

    while (sym_link) {

        char *prefix = "__";
        Symbol sym = sym_link->data;
        char *elf_func_str = sym->sym_name;

        size_t elf_func_len = strlen(elf_func_str);
        size_t map_index=(elf_func_len*elf_func_len)%HASHMAP_SIZE;
        /*  search in hashmap   */
        hashmap *hm_tmp=(hm+map_index)->_next;
        while(hm_tmp){
            /*  fortified  */
            if(strcmp(hm_tmp->_str,elf_func_str)==0){
                fortified_count++;
                if(!hm_tmp->_hit){
                    hm_tmp->_hit=true;
                    chk_info *new=MALLOC(1,chk_info);
                    new->chk_type=type;
                    new->chk_result=str_append(hm_tmp->_str," \033[32mFortified\033[m");
                    info->chk_next=new;
                    info=new;
                }
            }
            hm_tmp=hm_tmp->_next;
        }
        elf_sym=elf_sym->sym_next;
    }
    /*  tail    */
    info->chk_next=NULL;
    /*  free hashmap and libc   */
    free_hashmap(hm);
    free_binary(libc);
    /*  head insert */
    chk_info *insert=head;
    /*  first info : whether libc has FORTIFY SOURCE    */
    chk_info *libc_info=MALLOC(1,chk_info);
    libc_info->chk_type=type;
    char *first_info="FORTIFY SOURCE support available (";
    first_info=str_append(first_info,libc_path);
    if(fortify_count) libc_info->chk_result=str_append(first_info,") : \033[32mYes\033[m");
    else libc_info->chk_result=str_append(first_info,") : \033[31mNO\033[m");
    libc_info->chk_next=insert->chk_next;
    insert->chk_next=libc_info;
    insert=libc_info;
    /*  second info : whether target is fortified   */
    chk_info *target_info=MALLOC(1,chk_info);
    target_info->chk_type=type;
    char *second_info="Binary compiled with FORTIFY SOURCE support (";
    second_info=str_append(second_info,elf->bin_name);
    if(fortified_count) target_info->chk_result=str_append(second_info,") : \033[32mYes\033[m");
    else target_info->chk_result=str_append(second_info,") : \033[31mNO\033[m");
    target_info->chk_next=insert->chk_next;
    insert->chk_next=target_info;

    return head;
}

void chk_file_one_elf(Binary *elf, Link *info) {

    /*  We have 8 basic check functions */
    char *(*chk_basic_func[CHK_ELF_BAS_NUM])(Binary*) = {
        chk_elf_name,
        chk_elf_relro,
        chk_elf_stack_canary,
        chk_elf_nx,
        chk_elf_pie,
        chk_elf_rpath,
        chk_elf_runpath,
        chk_elf_stripped,
        chk_elf_frame_pointer,
    };

    char *chk_basic_array[CHK_ELF_BAS_NUM] = {
        "File",
        "RELRO",
        "STACK CANARY",
        "NX",
        "PIE",
        "RPATH",
        "RUNPATH",
        "Stripped",
        "Frame Pointer",
    };

    /*  loop basic  */
    for (int num = 0; num < CHK_ELF_BAS_NUM; num++) {

        chk_info *elf_info = MALLOC(1, chk_info);
        elf_info->chk_type = chk_basic_array[num];

        char *result = chk_basic_func[num](elf);

        /*  null handler   */
        if(!result) elf_info->chk_result = "NULL";
        else elf_info->chk_result=result;

        link_append(info, elf_info);
    }

    /*  We have 2 extented check functions  */
    void (*chk_extented_func[CHK_ELF_EXT_NUM])(Binary*, Link*)={
        chk_elf_sanitized,
        chk_elf_fortified
    };

    if(EXTENTED){
        
        for(int num = 0; num < CHK_ELF_EXT_NUM; num++) {

            chk_extented_func[num](elf, info);
        }
    }
}

/*  pe name    */
//char *chk_pe_name(Binary *pe){
//    return pe->bin_name;
//}

/*  check /delay:nobind */
//char *chk_pe_iat_bind(Binary *pe){
//    /*IAT Bind (/delay:nobind) like relro,but no partial*/
//}

/*  check /gs   */
//char *chk_pe_gs(Binary *pe){};
/*  check /nxcompat */
//char *chk_pe_dep(Binary *pe){};
/*  check /dynamicbase  */
//char *chk_pe_dynamic_base(Binary *pe){};
/*  check /safeseh  */
//char *chk_pe_safeseh(Binary *pe){};
/*  check /cetcompat    */
//char *chk_pe_shadow_stack(Binary *pe){}

//char *chk_pe_frame_pointer(Binary *elf){
//    /*  push rbp / push ebp */
//}

/*  check /guard:xxx  */
//chk_info *chk_pe_guard(Binary *pe){
//    /*
//    rip sign (/guard:signret) only arm64
//    eh protect (/guard:ehcont) only x64
//    cf protect (/guard:cf)
//    */
//}

/*  check /fsanitize=xxx    */
//chk_info *chk_pe_sanitized(Binary *pe){
//    /*asan address、fuzzer (/fsanitize=address fuzzer)*/
//}

// VS 2022 MSVC properties
//void chk_file_one_pe(Binary *pe){
//    /*  We have 7 basic check functions */
//    char *(*chk_basic_func[CHK_PE_BAS_NUM])(Binary*)={
//        chk_pe_name,
//        chk_pe_iat_bind,
//        chk_pe_gs,
//        chk_pe_dep,
//        chk_pe_dynamic_base,
//        chk_pe_safeseh,
//        chk_pe_shadow_stack,
//        chk_pe_frame_pointer,
//    };
//    char *chk_basic_array[CHK_PE_BAS_NUM]={
//        "File",
//        "IAT Bind",
//        "GS",
//        "DEP",
//        "Dynamic Base",
//        "SafeSEH",
//        "CET Shadow Stack",
//        "Frame Pointer",
//    };
//    /*  current   */
//    chk_info *elf_info=MALLOC(1,chk_info);
//    /*  head    */
//    chk_info *head=elf_info;
//    for(int num=0;num < CHK_PE_BAS_NUM;num++){
//        chk_info *new=MALLOC(1,chk_info);
//        new->chk_type=chk_basic_array[num];
//        char *result=chk_basic_func[num](pe);
//        /*  null handler   */
//        if(!result) new->chk_result="NULL";
//        else new->chk_result=result;
//        elf_info->chk_next=new;
//        elf_info=new;
//    }
//    if(EXTENTED){
//        /*  We have 2 extented check functions  */
//        chk_info *(*chk_extented_func[CHK_PE_EXT_NUM])(Binary*)={
//            chk_pe_guard,
//            chk_pe_sanitized,
//        };
//        for(int num=0;num < CHK_PE_EXT_NUM;num++){
//            chk_info *result=chk_extented_func[num](pe);
//            chk_info *tmp=result;
//            elf_info->chk_next=result->chk_next;
//            /*  find the tail   */
//            while(result->chk_next) result=result->chk_next;
//            elf_info=result;
//            /*  free fortify/sanitize's head */
//            free(tmp);
//        }
//    }
//    /*  tail    */
//    elf_info->chk_next=NULL;
//    /*  chk_info head   */
//    return head;
//}

void chk_file_one(Binary *bin, Link *info) {

    /*  elf or pe   */
    switch (bin->bin_format)
    {
    case BIN_FORMAT_ELF32:case BIN_FORMAT_ELF64:
        chk_file_one_elf(bin, info);
    //case BIN_FORMAT_PE:
    //    chk_file_one_pe(bin);
    //    return NULL;
    }
}

void chk_file(char *option, chk_file_option cfo) {

    bool stat;

    switch (cfo)
    {
    case cfo_file:

        /*  load file  */
        Binary *bin = load_binary(option);
        if (bin == NULL) CHK_ERROR1("load file failed");

        /*  check one file  */
        Link *info = link_init();
        chk_file_one(bin, info);

        /*  output with format  */
        format_output(info);

        /*  free load   */
        free_binary(bin);

        break;

    case cfo_dir:

        /*  open dir*/
        DIR *dir;
        if ((dir = opendir(option)) == NULL) CHK_ERROR2(option, "directory is not exist or not accessible");

        /*  check all files   */
        struct dirent *file;

        while ((file=readdir(dir)) != NULL) {
            if (file->d_name == "." || file->d_name == "..") continue;
            chk_file(file->d_name, cfo_file);
        }

        break;

    case cfo_list:

        /*  check file list */
        char *token = "*";
        char *path = strtok(option, token);

        while (path !=NULL) {
            chk_file(path, cfo_file);
            CHK_PRINT3();
            path = strtok(NULL, token);
        }

        break;
    }
}