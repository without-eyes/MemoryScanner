#pragma once

#include <memscan/core/CoreFunctions.h>

void print_matches(MEMBLOCK* mb_list);

int get_match_count (MEMBLOCK *mb_list);

unsigned int str2int (char *s);

MEMBLOCK* ui_new_scan();

void ui_poke (HANDLE hProc, int data_size);

void ui_run_scan ();