// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "functions.h"
#include "types.h"
#include "loader.h"

/*  global flag   */
bool EXTENTED;
bool DEBUG;
output OUTPUT;

/*  global str link */
Link *sl;

output set_format(char *option) {

    if(strcmp(option,"cli") ==0) return cli;
    if(strcmp(option,"csv") ==0) return csv;
    if(strcmp(option,"xml") ==0) return xml;
    if(strcmp(option,"json") ==0) return json;
    return cli;
}

static void cli_output(LinkNode *info_link) {

    while(info_link){

        chk_info *info = info_link->data;
        printf("%-28s%s\n", info->chk_type, info->chk_result);

        info_link = info_link->next;
    }
}

static void csv_output(LinkNode *info_link) {
    
    chk_info *info = info_link->data;
    size_t len = strlen(info->chk_result);
    printf("%.*s", len - 3, info->chk_result + 5);

    info_link = info_link->next;
    while(info_link){

        info = info_link->data;
        size_t len = strlen(info->chk_result);
        // len of '\033[m' = 3
        // len of '\033[31m' = 5
        printf(",%.*s", len - 3, info->chk_result + 5);

        info_link = info_link->next;
    }

    printf("\n");
}

static void xml_output(LinkNode *info_link) {

    printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    printf("<");

    while(info_link){

        chk_info *info = info_link->data;
        size_t len = strlen(info->chk_result);
        printf("%s=\"%.*s\" ", info->chk_type, len - 3, info->chk_result + 5);

        info_link = info_link->next;
    }

    printf("/>\n");
}

static void json_output(LinkNode *info_link) {

    chk_info *info = info_link->data;
    size_t len = strlen(info->chk_result);
    printf("{\"%.*s\":{", len - 3, info->chk_result + 5);

    info_link = info_link->next;

    info = info_link->data;
    len = strlen(info->chk_result);
    printf("\"%s\":\"%.*s\"", info->chk_type, len - 3, info->chk_result + 5);

    info_link = info_link->next;
    while(info_link){

        info = info_link->data;
        len = strlen(info->chk_result);
        printf(",\"%s\":\"%.*s\"", info->chk_type, len - 3, info->chk_result + 5);

        info_link = info_link->next;
    }

    printf("}}\n");
}

void free_chk_info(Link *l) {

    LinkNode *info_link = l->head;

    while(info_link){

        LinkNode *tmp = info_link;
        info_link = info_link->next;

        free(tmp->data);
        free(tmp);

    }

    free(l);
}

void format_output(Link *l){

    LinkNode *head = l->head;

    switch (OUTPUT)
    {
    case cli:
        cli_output(head);
        break;
    case csv:
        csv_output(head);
        break;
    case xml:
        xml_output(head);
        break;
    case json:
        json_output(head);
        break;
    }

    free_chk_info(l);
}

/*  format string with color  */
char *str_colored(char *color, char *str) {

    /*  needed size  */
    int size = snprintf(NULL, 0, color, str);

    if (size < 0) {
        return "COLOR SIZE ERROR";
    }
    
    /*  colored buffer */
    char *colored = malloc(size + 1);

    if (colored == NULL) {
        printf("Out Of Memory.");
        exit(-1);
    }
    
    /*  format color  */
    snprintf(colored, size + 1, color, str);

    /*  append string  */
    strlink *data = MALLOC(1, strlink);
    data->str = colored;
    link_append(sl, data);

    return colored;
}

/*  free string by strlink  */
void free_str(){

    LinkNode *head = sl->head;

    while(head){

        LinkNode *tmp = head;
        head = head->next;

        free(tmp->data);
        free(tmp);
    }

    free(sl);
}