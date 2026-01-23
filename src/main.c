// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include "functions.h"
#include "types.h"
#include "structs.h"

/*  usage   */
static void help() {

    printf("Usage: checkc [--format={cli,csv,xml,json}] [OPTION]\n\n \
      Options:\n \
      ## Checksecc Options\n \
      --file={file}\n \
      --dir={directory}\n \
      --file-list={file list separated by *}\n \
      --proc-list={proc list separated by *}\n \
      --proc-id={process ID}\n \
      --kernel\n \
      --version\n \
      --help\n\n \
     ## Modifiers\n \
      --format={cli,csv,xml,json}\n \
      --extended\n\n \
For more information, see:\n \
https://github.com/pehmc/checksecc\n\n");
    exit(0);
}

/*  version info    */
static void version() {

    printf("checksecc v1.0,pehmc\n \
https://github.com/pehmc/checksecc\n\n");
    exit(0);
}

/*  long options args   */
static struct option long_options[] = {
    {"file", required_argument,NULL, '0'},
    {"dir", required_argument,NULL, '1'},
    {"file-list", required_argument,NULL, '2'},
    {"proc-list",required_argument,NULL, '3'},
    {"proc-id", required_argument,NULL, '4'},
    {"kernel", optional_argument,NULL, '5'},
    {"version", no_argument,NULL, 'v'},
    {"help", no_argument,NULL, 'h'},
    {"format", required_argument,NULL, 'f'},
    {"extended", no_argument,NULL, 'e'}
};

/*  check function type*/
static chk_func func = CHK_UNKNOWN;
static char *arg;
static uint8_t chk_mode;

/*  extern format.c  */
extern bool EXTENTED;
extern bool DEBUG;
extern output OUTPUT;
extern Link *sl;

/*  parse args  */
static void parse_args(int *pargc, char ***pargv) {

    /*  default global flag */
    DEBUG = true;
    EXTENTED = false;
    OUTPUT = cli;

    /*  init strlink    */
    sl = link_init();

    /*  help page   */
    if (*pargc < 2) help();

    /*  option args */
    char *optstring = "vh";
    int opt;
    int index = 0;

    /*  match option, long option   */
    while ((opt = getopt_long(*pargc, *pargv, optstring, long_options, &index)) != -1) {

        switch (opt)
        {
        case 'v':
            version();
            break;
        case 'h':
            help();
            break;
        case '0':
            func = CHK_FILE;
            arg = optarg;
            chk_mode = cfo_file;
            break;
        case '1':
            func = CHK_FILE;
            arg = optarg;
            chk_mode = cfo_dir;
            break;
        case '2':
            func = CHK_FILE;
            arg = optarg;
            chk_mode = cfo_list;
            break;
        case '3':
            func = CHK_PROC;
            arg = optarg;
            chk_mode = cpo_list;
            break;
        case '4':
            func = CHK_PROC;
            arg = optarg;
            chk_mode = cpo_id;
            break;
        case '5':
            func = CHK_KERNEL;
            arg = optarg;
            break;
        case 'f':
            OUTPUT = set_format(optarg);
            break;
        case 'e':
            EXTENTED = true;
            break;
        case '?':
            printf("\033[31mError:Unknown option %s.\033[m\n\n", &optopt);
            break;
        }
    }
}

/*  main func   */
int main(int argc, char **argv) {

    parse_args(&argc, &argv);
    
    switch (func)
    {
    case CHK_FILE:
        chk_file(arg, chk_mode);
        break;
    case CHK_PROC:
        chk_proc(arg, chk_mode);
        break;
    case CHK_KERNEL:
        chk_kernel(NULL, arg);
        break;
    case CHK_UNKNOWN:
        printf(str_colored(RED_FMT, "Error:Unknown check function."));
        CHK_PRINT3();
        break;
    }

    /*  free str to solve memory leak */
    free_str();
}