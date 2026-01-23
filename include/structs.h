// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#ifndef _STRUCTS_H_
#define _STRUCTS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/*  safe malloc */
#define MALLOC(num, type) ({\
    type *ptr = (type *)malloc(num * sizeof(type)); \
    if (ptr == NULL) { \
    printf("Out Of Memory."); \
    exit(-1); } \
    ptr; \
})

/*  common link node  */
typedef struct LinkNode {
    void *data;               
    struct LinkNode *next;    
}LinkNode;

/*  link with head, tail  */
typedef struct {
    LinkNode *head;    
    LinkNode *tail;    
}Link;

Link *link_init();
void link_append(Link *link, void *data);
void link_insert(Link *link, void *data);


typedef struct hashmap{
    bool hit;
    char *str;
    struct hashmap *next;
}hashmap;

hashmap *hashmap_init();
void hashmap_append(hashmap *hm, bool hit, char *str);
hashmap *hashmap_search(hashmap *hm, char *str);
void hashmap_free(hashmap *hm);

#endif