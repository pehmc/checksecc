// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#ifndef _STRUCTS_H_
#define _STRUCTS_H_

#include <stdio.h>
#include <stdlib.h>

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

/*  link funcs  */
Link *link_init() {

    Link *l = MALLOC(1, Link);
    l->head = NULL;
    l->tail = NULL;
    return l;
}

void link_append(Link *link, void *data) {

    LinkNode *l = MALLOC(1, LinkNode);
    l->data = data;
    l->next = NULL;

    /*  empty link  */
    if (!link->head) {
        link->head = l;
    } else {
        link->tail->next = l;
    }
    link->tail = l;
}

void link_insert(Link *link, void *data) {

    LinkNode *l = MALLOC(1, LinkNode);
    l->data = data;

    /*  not empty link  */
    if (link->head) {
        l->next = link->head;
    }
    link->head = l;
}

typedef struct hashmap{
    bool hit;
    char *str;
    struct hashmap *next;
}hashmap;

hashmap *hashmap_init() {

    hashmap *hm = MALLOC(HASHMAP_SIZE, hashmap);
    for (int i=0;i<HASHMAP_SIZE;i++) {
        (hm + i)->next=NULL;
    }
}

void hashmap_append(hashmap *hm, bool hit, char *str) {

    size_t len = strlen(str);
    size_t index = (len * len) % HASHMAP_SIZE;
    
    hashmap *new = MALLOC(1, hashmap);
    new->hit = hit;
    new->str = str;

    new->next = (hm + index)->next;
    (hm + index)->next = new;
}

hashmap *hashmap_search(hashmap *hm, char *str) {

    size_t len = strlen(str);
    size_t index = (len * len) % HASHMAP_SIZE;

    hashmap *hm_link = (hm + index)->next;
    hashmap *ret = NULL;

    while (hm_link) {

        if (strcmp(hm_link->str, str) == 0) {
                
            ret = hm_link;
            break;
        }
        hm_link = hm_link->next;
    }

    return ret;
}

void hashmap_free(hashmap *hm){

    for(int i = 0; i < HASHMAP_SIZE; i++) {

        hashmap *head = (hm + i)->next;

        while (head) {
            hashmap *tmp = head;
            head = head->next;

            free(tmp);
        }
    }
    free(hm);
}

#endif