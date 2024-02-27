#pragma once

#include <windows.h>

// I don't fully understand this but it works
#define IS_IN_SEARCH(mb,offset) (mb->searchmask[(offset) / 8] & 1 << ((offset) % 8))
#define REMOVE_FROM_SEARCH(mb,offset) mb->searchmask[(offset) / 8] &= ~(1 << ((offset) % 8))

typedef struct _MEMBLOCK {
    HANDLE hProc;
    unsigned char* addr;
    int size;
    unsigned char* buffer;

    unsigned char* searchmask;
    int matches;
    int data_size;

    struct _MEMBLOCK* next;
} MEMBLOCK;

typedef enum {
    COND_UNDONDITIONAL,
    COND_EQUALS,

    COND_INCREASED,
    COND_DECREASED,
} SEARCH_CONDITION;

MEMBLOCK* create_memblock(HANDLE hProc, MEMORY_BASIC_INFORMATION* meminfo, int data_size);

void free_memblock(MEMBLOCK* mb);

void update_memblock(MEMBLOCK* mb, SEARCH_CONDITION condition, unsigned int val);

MEMBLOCK* create_scan(unsigned int pid, int data_size);

void free_scan(MEMBLOCK *mb_list);

void update_scan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, unsigned int val);

void poke(HANDLE hProc, int data_size, size_t addr, unsigned int val);

unsigned int peek(HANDLE hProc, int data_size, size_t addr);