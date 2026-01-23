// Copyright (c) 2024 pehmc. MIT License.
// See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "structs.h"
#include "types.h"

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

/*  hashmap funcs  */
hashmap *hashmap_init() {

    hashmap *hm = MALLOC(HASHMAP_SIZE, hashmap);
    for (int i = 0; i < HASHMAP_SIZE; i++) {
        (hm + i)->next = NULL;
    }

    return hm;
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