// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include "functions.h"
#include "types.h"
#include "loader.h"

/*  global flag */
extern bool DEBUG;

// check Seccomp mode
char *chk_linux_proc_seccomp(char *path){
    char *status=str_append(path,"/status");
    FILE *fp;
    // status is empty file, read 4096 bytes
    fp=fopen(status,"r");
    if(fp == NULL) CHK_ERROR4("open /proc/pid/status failed");
    char *seccomp=MALLOC(MAXBUF+1,char);
    if(fread(seccomp,sizeof(char),MAXBUF,fp) < 0) CHK_ERROR4("read /proc/pid/status failed");
    // need to add '\0'
    seccomp[MAXBUF]='\0';
    char *location=strstr(seccomp,"Seccomp:");
    if(location == NULL) CHK_ERROR4("Seccomp flag not found");
    // Seccomp:	x , flag=x
    unsigned int offset=9;
    char flag=*(location+offset);
    // collect resource
    fclose(fp);
    free(seccomp);
    if(flag == '0') return "\033[31mNo Seccomp\033[m";
    else if(flag == '1') return "\033[32mSeccomp strict\033[m";
    else if(flag =='2') return "\033[32mSeccomp-bpf\033[m";
    else return "Unknown Seccomp LEVEL";
}

// check Selinux mode
char *chk_linux_proc_selinux(char *){
    char *config="/etc/selinux/config";
    FILE *fp;
    fp=fopen(config,"r");
    if(fp == NULL) {
        if(errno == ENOENT) return "\033[31mNo Selinux\033[m";
        else CHK_ERROR4("open /etc/selinux/config failed");
    }
    unsigned int size=FILE_SIZE(fp);
    if(size == 0) CHK_ERROR4("empty file");
    char *selinux=MALLOC(size+1,char);
    if(fread(selinux,sizeof(char),size,fp) < 0) CHK_ERROR4("read /etc/selinux/config failed");
    // need to add '\0'
    selinux[size]='\0';
    if(strstr(selinux,"SELINUX=enforcing")) return "\033[32mEnforcing\033[m";
    else if(strstr(selinux,"SELINUX=permissive")) return "\033[32mPermissive\033[m";
    else if(strstr(selinux,"SELINUX=disabled")) return "\033[31mDisabled\033[m";
    else CHK_ERROR4("Unknown Selinux LEVEL");
}

// only linux now
void chk_linux_proc(char *path,char *pid,char *exe){
    // load file
    Binary *bin=load_binary(exe);
    if(bin == NULL) CHK_ERROR1("load file failed");
    // chk_info
    chk_info *head;
    // chk this exe file
    // write this func in functions.h
    head=chk_file_one_elf(bin);
    // chk proc feature
    char *(*chk_proc_func[CHK_PROC_NUM])(char *)={
        chk_linux_proc_seccomp,
        chk_linux_proc_selinux
    };
    char *chk_proc_array[CHK_PROC_NUM]={
        "SECCOMP",
        "Selinux"
    };
    for(int num=0;num < CHK_PROC_NUM;num++){
        chk_info *new=MALLOC(1,chk_info);
        new->chk_type=chk_proc_array[num];
        char *result=chk_proc_func[num](path);
        /*  null handler   */
        if(!result) new->chk_result="NULL";
        else new->chk_result=result;
        // head insert
        new->chk_next=head->chk_next;
        head->chk_next=new;
    }
    // head insert pid
    chk_info *new=MALLOC(1,chk_info);
    new->chk_type="PID";
    pid = str_append("\033[36m",pid);
    pid = str_append(pid,"\033[m");
    new->chk_result=pid;
    new->chk_next=head->chk_next;
    head->chk_next=new;
    //format output
    format_output(head);
    // free load
    free_binary(bin);
}

void chk_proc(char *option,chk_proc_option cpo){
    DIR *dir=NULL;
    switch (cpo)
    {
    case cpo_id:
        char *proc=str_append("/proc/",option);
        dir=opendir(proc);
        if(dir == NULL) CHK_ERROR2(proc,"pid is not exist or not unprivileged(not root)");
        char *link=str_append(proc,"/exe");
        // max len 64
        char exe[64];
        int len=readlink(link,exe,64);
        if(len < 0) CHK_ERROR2(option,"Permission denied. Requested process ID belongs to a kernel thread");
        chk_linux_proc(proc,option,exe);
        break;
    case cpo_list:
        /*  check pid list */
        char *token="*";
        char *pid=strtok(option,token);
        while(pid !=NULL){
            chk_proc(pid,cpo_id);
            CHK_PRINT3();
            pid=strtok(NULL,token);
        }
        break;
    }
    if(dir) closedir(dir);
}