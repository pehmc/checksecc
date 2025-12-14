![](https://github.com/fuxxcss/checksecc/blob/main/docs/checksecc.png)
--

* [Why checksecc ?](#why)
* [Introduction](#introduction)
* [How to Install ?](#install)
* [How to Use ?](#check-one-elf-file)
   * [Check File](#check-one-elf-file)
   * [Check Kernel](#check-the-kernel)
   * [Check Process](#check-one-process)
   * [Format Output](#format-output)
* [Version](#version-information)
* [ToDo](#todo)

## why
checksec.sh is a linux specified gadget,because it used Shell and readelf. If you need to check pe, elf in other place, maybe you need checksecc.

## introduction
The checksecc is a c rewrite of checksec and has some highlights. It retains all the core functionality of checksec,you can operate on it just like the original.we removed some uncommon features and added some useful features.
``` shell
> checkc -h or just checkc
Usage: checkc [OPTION] [--format={cli,csv,xml,json}]

      Options:
      ## Checksecc Options
      --file={file}
      --dir={directory}
      --file-list={file list separated by *}
      --proc-list={proc list separated by *}
      --proc-id={process ID}
      --kernel
      --version
      --help

     ## Modifiers
      --format={cli,csv,xml,json}
      --extended

For more information, see:
https://github.com/fuxxcss/checksecc
```

## install 
install checksecc by release:
``` shell
release 1.0 now.
```
install checksecc by source:
``` shell
cd srcs
make && make install
```
if you need to update , make clean first
``` shell
make clean
```

## check one elf file
For example , we compile one file with gcc features.
``` shell
> gcc -z now -fstack-protector-all test.c -o test
```
And then use checkc to check this file.
``` shell
> checkc --file=./test
File                        ./test
RELRO                       Full RELRO
STACK CANARY                Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped
Frame Pointer               Not Omit
```
For example , we compile one file with clang features.
``` shell
> clang -fsanitize=address test.c -o test
```
And then use checkc to check this file with extended features.
``` shell
> checkc --file=./test --extended
File                        ./test
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped
Frame Pointer               Not Omit
Sanitized asan              Yes
Sanitized tsan              NO
Sanitized msan              NO
Sanitized lsan              Yes
Sanitized ubsan             Yes
Sanitized dfsan             NO
Sanitized safestack         NO
Sanitized cet-ibt           NO
Sanitized cet-shadow-stack  NO
Fortified                   FORTIFY SOURCE support available (/lib/x86_64-linux-gnu/libc.so.6) : Yes
Fortified                   Binary compiled with FORTIFY SOURCE support (./test) : Yes
Fortified                   __sprintf_chk Fortified
Fortified                   __longjmp_chk Fortified
Fortified                   __fprintf_chk Fortified
Fortified                   __vsprintf_chk Fortified
Fortified                   __snprintf_chk Fortified
Fortified                   __vsnprintf_chk Fortified
```
check one dynamic elf.
``` shell
> checkc --file=./libchkc.so
File                        ./libchkc.so
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         DSO
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Stripped
Frame Pointer               Not Omit
```

## check file list
We need delim * to check file list
``` shell
> checkc --file-list=test*test1*
File                        test
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Not Stripped
Frame Pointer               Not Omit

File                        test1
RELRO                       Partial RELRO
STACK CANARY                No Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Stripped
Frame Pointer               NULL
```

## check the kernel
For example , we check Linux debian 5.10.0-20-amd64.
``` shell
> checkc --kernel
Kconfig                     /boot/config-5.10.0-20-amd64
User ASLR                   LEVEL 2
Kernel ASLR                 Enabled
Kernel NX                   Enabled
Kernel Stack Canary         Strong
Kernel Stack Poison         Disabled
Slab Freelist Hardened      Enabled
Slab Freelist Random        Enabled
SMAP                        Enabled
PTI                         Enabled
```

## check one process
we focus on selinux and seccomp.
``` shell
> ps -aux | grep upowerd
root        1273  0.0  0.1 320404  8828 ?        Ssl  Jan23   0:01 /usr/libexec/upowerd
> checkc --proc-id=1273
PID                         1273
Selinux                     No Selinux
SECCOMP                     Seccomp-bpf
File                        /usr/libexec/upowerd
RELRO                       Full RELRO
STACK CANARY                Canary found
NX                          NX enabled
PIE                         PIE enabled
RPATH                       NO RPATH
RUNPATH                     NO RUNPATH
Stripped                    Stripped
Frame Pointer               NULL
```

## format output
cli is default.
``` shell
> checkc --file=./test -format=csv
./test,Partial RELRO,No Canary found,NX enabled,PIE enabled,NO RPATH,NO RUNPATH,Not Stripped,Not Omit
> checkc --file=./test -format=xml
<?xml version="1.0" encoding="UTF-8"?>
<File="./test" RELRO="Partial RELRO" STACK CANARY="No Canary found" NX="NX enabled" PIE="PIE enabled" RPATH="NO RPATH" RUNPATH="NO RUNPATH" Stripped="Not Stripped" Frame Pointer="Not Omit" />
> checkc --file=./test -format=json
{"./test":{"RELRO":"Partial RELRO","STACK CANARY":"No Canary found","NX":"NX enabled","PIE":"PIE enabled","RPATH":"NO RPATH","RUNPATH":"NO RUNPATH","Stripped":"Not Stripped","Frame Pointer":"Not Omit"}}
```

## version information
``` shell
> checkc -v
checksecc v1.0,fuxxcss
https://github.com/fuxxcss/checksecc

```

## ToDo
todo in version 2.0:
``` shell
1. `pe` check
2. `windows` check
```



