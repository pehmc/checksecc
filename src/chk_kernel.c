// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <zlib.h>
#include <stdbool.h>
#include "functions.h"
#include "types.h"
#include "loader.h"

/*  global flag */
extern bool DEBUG;

/*
 *  linux on x86
 */

/*  chk_elf_pie can use this return 0 48('0') 49('1') 50('2').  */
unsigned int chk_user_aslr_flag() {

    /*  /proc/sys/kernel/randomize_va_space is empty file , read 4 bytes  */
    FILE *fp;
    fp = fopen("/proc/sys/kernel/randomize_va_space", "r");

    if (fp == NULL) CHK_ERROR4("open randomize_va_space failed");

    unsigned int aslr = 0;
    if (fread(&aslr, sizeof(char), 1, fp) < 0) CHK_ERROR4("read randomize_va_space failed");
    fclose(fp);

    return aslr;
}

/*  user space ASLR  */
char *chk_user_aslr(char *) {

    unsigned int aslr = chk_user_aslr_flag();
    if (aslr == 0) return NULL;
    else if (aslr == 48) return str_colored(RED_FMT, "LEVEL 0");
    else if (aslr == 49) return str_colored(YELLOW_FMT, "LEVEL 1");
    else if (aslr == 50) return str_colored(GREEN_FMT, "LEVEL 2");
    else CHK_ERROR4("Unknown ASLR LEVEL");
}

/*  kernel space ASLR  */
char *chk_kernel_aslr(char *info) {

    if (strstr(info, "CONFIG_RANDOMIZE_BASE=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  cpu nx support  */
bool chk_cpu_nx() {

    /*  read /proc/cpuinfo  */
    FILE *fp;
    fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) CHK_ERROR3("open cpuinfo failed");

    /*  /proc/cpuinfo is empty file , read 4096 bytes  */
    char *cpuinfo = MALLOC(MAXBUF + 1, char);
    if (fread(cpuinfo, sizeof(char), MAXBUF, fp) < 0) CHK_ERROR3("read cpuinfo failed");

    /*  need to add '\0'  */
    cpuinfo[MAXBUF] = '\0';
    char *str = strstr(cpuinfo, " nx ");

    fclose(fp);
    free(cpuinfo);

    if(str) return true;
    else return false;
}

/*
 * kernel space nx 
 * code is not writable, data is not executable, and read-only data is neither writable nor executable.
 */
char *chk_kernel_nx(char *info) {

    if (chk_cpu_nx()) {
        if (strstr(info, "CONFIG_STRICT_KERNEL_RWX=y")) return str_colored(GREEN_FMT, "Enabled");
        else return str_colored(YELLOW_FMT, "Disabled");
    }
    else return "CPU not support nx";
}

/*  kernel stack canary  */
char *chk_kernel_stack_canary(char *info) {

    if (strstr(info, "CONFIG_STACKPROTECTOR=y")) {

        if (strstr(info, "CONFIG_STACKPROTECTOR_STRONG=y")) return str_colored(GREEN_FMT, "Strong");
        else return str_colored(GREEN_FMT, "Enabled");
    }
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  poison kernel stack before returning from syscalls  */
char *chk_kernel_stack_poison(char *info) {

    if (strstr(info, "CONFIG_GCC_PLUGIN_STACKLEAK=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  slab freelist hardened  */
char *chk_kernel_slab_freelist_hardened(char *info) {

    if (strstr(info, "CONFIG_SLAB_FREELIST_HARDENED=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  slab freelist random  */
char *chk_kernel_slab_freelist_random(char *info) {

    if(strstr(info,"CONFIG_SLAB_FREELIST_RANDOM=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  Supervisor Mode Access Protection x86  */
char *chk_kernel_smap(char *info) {

    if(strstr(info,"CONFIG_X86_SMAP=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

// PAGE TABLE ISOLATION
char *chk_kernel_pti(char *info) {

    if(strstr(info,"CONFIG_PAGE_TABLE_ISOLATION=y")) return str_colored(GREEN_FMT, "Enabled");
    else return str_colored(YELLOW_FMT, "Disabled");
}

/*  kernel config  */
char *chk_kernel_config(char *option, char **kconfig) {

    char *kernelinfo = NULL;
    /*  config path  */
    char *config = NULL;
    unsigned int size=0;
    FILE *fp;

    if (option == NULL) {

        /*  set CONFIG_IKCONFIG  */
        gzFile gzfp;
        config = "/proc/config.gz";
        gzfp = gzopen(config, "rb");

        if (gzfp != NULL) {

            size = gzFILE_SIZE(gzfp);
            if (size == 0) CHK_ERROR4("/proc/config.gz empty file");

            kernelinfo = MALLOC(size + 1, char);
            size_t result = gzread(gzfp, kernelinfo, size);
            gzclose(gzfp);

            if (result < 0) {
                free(kernelinfo);
                CHK_PRINT1("read /proc/config.gz failed");
            }
            else goto kernelinfo_ok;
        }

        /*  uname -r  */
        struct utsname uts;
        if (uname(&uts) < 0) CHK_ERROR4("uname -r failed");
        char *release = uts.release;

        /*  /boot/config-${release}  */
        config = str_append("/boot/config-", release);
        fp = fopen(config, "r");

        if (fp) {
            size = FILE_SIZE(fp);
            if (size == 0) CHK_ERROR4("/boot/config-${release} empty file");

            kernelinfo = MALLOC(size + 1,char);
            size_t result = fread(kernelinfo, sizeof(char), size,fp);
            fclose(fp);

            if (result < 0) {
                free(kernelinfo);
                CHK_PRINT1("read /boot/config-${release} failed");
            }
            else goto kernelinfo_ok;
        }
        /*  /usr/src/linux-headers-${release}  */
        char *lh_release = str_append("/usr/src/linux-headers-", release);
        config = str_append(lh_release, "/.config");
        fp = fopen(config, "r");

        if (fp) {
            size = FILE_SIZE(fp);
            if (size == 0) CHK_ERROR4("/usr/src/linux-headers-${release} empty file");

            kernelinfo = MALLOC(size + 1, char);
            size_t result = fread(kernelinfo, sizeof(char), size, fp);

            if (result < 0) {
                free(kernelinfo);
                CHK_PRINT1("read /usr/src/linux-headers-${release}/.config failed");
            }
            else goto kernelinfo_ok;
        }
        /*  all failed  */
        CHK_ERROR4("cannot find kernel config");
    }
    else {

        config = option;
        fp = fopen(config, "r");
        if (fp == NULL) CHK_ERROR4("open kconfig failed");

        size = FILE_SIZE(fp);
        if (size == 0) CHK_ERROR4("input kconfig empty file");

        kernelinfo = MALLOC(size + 1, char);
        size_t result = fread(kernelinfo, sizeof(char), size, fp);
        fclose(fp);

        if (result < 0) {
            free(kernelinfo);
            CHK_ERROR4("read kconfig failed");   
        }
    }

    /*  kernelinfo is ready  */
    kernelinfo_ok:

    *kconfig = config;

    /*  need to add '\0'  */
    kernelinfo[size] = '\0';

    return kernelinfo;
}

/*  
 * https://www.kernel.org/doc/html/latest/security/self-protection.html
 * https://www.kernelconfig.io/
 */
void chk_kernel(char *kernelinfo, char *option) {

    /*  kconfig path  */
    char *kconfig = NULL;
    if (kernelinfo == NULL)
        kernelinfo = chk_kernel_config(option, &kconfig);

    /*  chk kernel feature  */
    char *(*chk_kernel_func[CHK_KERN_NUM])(char *) = {
        chk_user_aslr,
        chk_kernel_aslr,
        chk_kernel_nx,
        chk_kernel_stack_canary,
        chk_kernel_stack_poison,
        chk_kernel_slab_freelist_hardened,
        chk_kernel_slab_freelist_random,
        chk_kernel_smap,
        chk_kernel_pti
    };

    char *chk_kernel_array[CHK_KERN_NUM] = {
        "User ASLR",
        "Kernel ASLR",
        "Kernel NX",
        "Kernel Stack Canary",
        "Kernel Stack Poison",
        "Slab Freelist Hardened",
        "Slab Freelist Random",
        "SMAP",
        "PTI"
    };

    if (kernelinfo != NULL) {

        /*  current   */
        Link *info = link_init();

        for (int num = 0; num < CHK_KERN_NUM; num++) {

            chk_info *kern_info = MALLOC(1, chk_info);
            kern_info->chk_type = chk_kernel_array[num];
            char *result = chk_kernel_func[num](kernelinfo);

            /*  null handler   */
            if (!result) kern_info->chk_result = "NULL";
            else kern_info->chk_result = result;

            link_append(info, kern_info);
        }

        /*  head insert kconfig  */
        chk_info *kconfig_info = MALLOC(1,chk_info);
        kconfig_info->chk_type = "Kconfig";
        kconfig_info->chk_result = str_colored(BLUE_FMT, kconfig);

        link_insert(info, kconfig_info);

        /*  format output   */
        format_output(info);

        /*  free kernelinfo  */
        free(kernelinfo);
    }
    else CHK_ERROR1("Check Kernel failed");
}