// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#ifndef _TYPES_H_
#define _TYPES_H_

/*  basic elf check functions   */
#define CHK_ELF_BAS_NUM 9

/*  extented elf check functions    */
#define CHK_ELF_EXT_NUM 2

/*  sanitized num   */
#define CHK_SAN_NUM 7

/*  ibt and shadow-stack    */
#define CHK_CET_NUM 2

/*  basic pe check functions   */
#define CHK_PE_BAS_NUM 8

/*  extented elf check functions    */
#define CHK_PE_EXT_NUM 2

/*  proc check functions    */
#define CHK_PROC_NUM 2

/*  kernel check functions    */
#define CHK_KERN_NUM 9

/*  lib path   */
#define CHK_LIB_PATH_NUM 3

/*  libc path ,up to bin_arch  */
#define CHK_LIBC_PATH_NUM 3

/*  hashmap size    */
#define HASHMAP_SIZE (2 << 6)

/*  max buffer size */
#define MAXBUF 4096

/*  color format string  */
#define RED_FMT "\033[31m%s\033[m"
#define GREEN_FMT "\033[32m%s\033[m"
#define YELLOW_FMT "\033[33m%s\033[m"
#define BLUE_FMT "\033[36m%s\033[m"

/*  cfo enum    */
typedef enum {
    cfo_file,
    cfo_dir,
    cfo_list,
}chk_file_option;

/*  cpo enum    */
typedef enum {
    cpo_list,
    cpo_id,
}chk_proc_option;

/*  output format enum  */
typedef enum {
    cli,
    csv,
    xml,
    json
}output;

/*  check function enum */
typedef enum {
    CHK_UNKNOWN,
    CHK_FILE,
    CHK_PROC,
    CHK_KERNEL,
}chk_func;

/*  chk information struct  */
typedef struct chk_info {
    char *chk_type;
    char *chk_result;
}chk_info;

/*  str struct  */
typedef struct strlink {
    char *str;
}strlink;

#endif