#include <memscan/core/CoreFunctions.h>
#include <stdio.h>

MEMBLOCK* create_memblock(HANDLE hProc, MEMORY_BASIC_INFORMATION* meminfo, int data_size) {
    MEMBLOCK* mb = malloc(sizeof(MEMBLOCK));

    if (mb) {
        mb->hProc = hProc;
        mb->addr = meminfo->BaseAddress;
        mb->size = meminfo->RegionSize;
        mb->buffer = malloc(meminfo->RegionSize);
        mb->searchmask = malloc(meminfo->RegionSize/8);
        memset(mb->searchmask, 0xff, meminfo->RegionSize/8);
        mb->matches = meminfo->RegionSize;
        mb->data_size = data_size;
        mb->next = NULL;
    }

    return mb;
}

void free_memblock(MEMBLOCK* mb) {
    if (mb) {
        if (mb->buffer) {
            free(mb->buffer);
        }

        if (mb->searchmask) {
            free(mb->searchmask);
        }

        free(mb);
    }
}

void update_memblock(MEMBLOCK* mb, SEARCH_CONDITION condition, unsigned int val) {
    static unsigned char tempbuf[128 * 1024]; // 128 Kilobytes
    size_t bytes_left;
    size_t total_read;
    size_t bytes_to_read;
    size_t bytes_read;

    if (mb->matches > 0) {
        bytes_left = mb->size;
        total_read = 0;
        mb->matches = 0;

        while (bytes_left) {
            bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;
            ReadProcessMemory(mb->hProc, mb->addr + total_read, tempbuf, bytes_to_read, &bytes_read);

            if (bytes_read != bytes_to_read) {
                break;
            }

            if (condition == COND_UNDONDITIONAL) {
                memset(mb->searchmask + (total_read / 8), 0xff, bytes_read / 8);
                mb->matches += bytes_read;
            } else {
                for (unsigned int offset = 0; offset < bytes_read; offset += mb->data_size) {
                    if (IS_IN_SEARCH(mb,(total_read + offset))) {
                        BOOL is_match = FALSE;
                        unsigned int temp_val;
                        unsigned int prev_val = 0;

                        switch (mb->data_size) { // In bytes
                            case 1:
                                temp_val = tempbuf[offset];
                                prev_val = *((unsigned char*)&mb->buffer[total_read + offset]);
                                break;
                            case 2:
                                temp_val = *((unsigned short*)&tempbuf[offset]);
                                prev_val = *((unsigned short*)&mb->buffer[total_read + offset]);
                                break;
                            case 4:
                            default:
                                temp_val = *((unsigned int*)&tempbuf[offset]);
                                prev_val = *((unsigned int*)&mb->buffer[total_read + offset]);
                                break;
                        }

                        switch (condition) {
                            case COND_EQUALS:
                                is_match = (temp_val == val);
                                break;
                            case COND_INCREASED:
                                is_match = (temp_val > prev_val);
                                break;
                            case COND_DECREASED:
                                is_match = (temp_val < prev_val);
                                break;
                            default:
                                break;
                        }

                        if (is_match) {
                            mb->matches++;
                        } else {
                            REMOVE_FROM_SEARCH(mb, (total_read + offset));
                        }
                    }
                }
            }

            memcpy(mb->buffer + total_read, tempbuf, bytes_read);

            bytes_left -= bytes_read;
            total_read += bytes_read;
        }

        mb->size = total_read;
    }
}

MEMBLOCK* create_scan(unsigned int pid, int data_size) {
    MEMBLOCK* mb_list = NULL;
    MEMORY_BASIC_INFORMATION meminfo;
    unsigned char *addr = 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProc) {
        while (1) {
            // VirtualQueryEx is used to check if region of processes memory is marked as in use by operating system
            // addr is used because VirtualQueryEx return information base on an address EQUAL TO or HIGHER than that
            // if address is too high, VirtualQueryEx will return 0
            if (VirtualQueryEx(hProc, addr, &meminfo, sizeof(meminfo)) == 0) {
                break;
            }

#define WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

            // MEM_COMMIT is a flag that checks if memory block exists for real and haven't been reserved for later use
            if ((meminfo.State & MEM_COMMIT) && (meminfo.Protect & WRITABLE)) {
                MEMBLOCK* mb = create_memblock(hProc, &meminfo, data_size);
                if (mb) {
                    mb->next = mb_list;
                    mb_list = mb;
                }
            }

            addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;

        }
    }

    return mb_list;
}

void free_scan(MEMBLOCK *mb_list) {
    CloseHandle(mb_list->hProc);
    while (mb_list) {
        MEMBLOCK *mb = mb_list;
        mb_list = mb_list->next;
        free_memblock(mb);
    }
}

void update_scan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, unsigned int val) {
    MEMBLOCK* mb = mb_list;

    while (mb) {
        update_memblock(mb, condition, val);
        mb = mb->next;
    }
}

void poke(HANDLE hProc, int data_size, size_t addr, unsigned int val) {
    if (WriteProcessMemory(hProc, (void*)addr, &val, data_size, NULL) == 0) {
        printf("poke failed\r\n");
    }
}

unsigned int peek(HANDLE hProc, int data_size, size_t addr) {
    unsigned int val = 0;

    if(ReadProcessMemory(hProc, (void*)addr, &val, data_size, NULL) == 0) {
        printf("peek failed\r\n");
    }

    return val;
}