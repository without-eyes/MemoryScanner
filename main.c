#include <stdio.h>
#include <windows.h>

// I don't understand it but it is working
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

                        switch (mb->data_size) { // In bytes
                            case 1:
                                temp_val = tempbuf[offset];
                                break;
                            case 2:
                                temp_val = *((unsigned short*)&tempbuf[offset]);
                                break;
                            case 4:
                            default:
                                temp_val = *((unsigned int*)&tempbuf[offset]);
                                break;
                        }

                        switch (condition) {
                            case COND_EQUALS:
                                is_match = (temp_val == val);
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

void dump_scan_info(MEMBLOCK* mb_list) {
    MEMBLOCK *mb = mb_list;

    while (mb) {
        // %08x means: 0 - fill blank spaces with 0; 8 - output width; x - integer.
        printf("0x%08x %d\r\n", mb->addr, mb->size);

        for (int i = 0; i < mb->size; i++) {
            printf("%02x", mb->buffer[i]);
        }
        printf("\r\n");

        mb = mb->next;
    }
}

void print_matches(MEMBLOCK* mb_list) {
    MEMBLOCK* mb = mb_list;

    while (mb) {
        for (unsigned int offset = 0; offset < mb->size; offset += mb->data_size) {
            if (IS_IN_SEARCH(mb,offset)) {
                printf("08%08x\r\n", mb->addr + offset);
            }
        }
        mb = mb->next;
    }
}

int get_match_count (MEMBLOCK *mb_list) {
    MEMBLOCK* mb = mb_list;
    int count = 0;

    while (mb) {
        count += mb->matches;
        mb = mb->next;
    }

    return count;
}

int main (int argc, char *argv[]) {
    MEMBLOCK *scan = create_scan (atoi(argv[1]), 4);

    if (scan) {
        printf("searching for 1000\r\n");
        update_scan(scan, COND_EQUALS, 1000);
        print_matches(scan);

        {
            char s[10];
            gets(s);
        }

        printf("searching for 2000\r\n");
        update_scan(scan, COND_EQUALS, 2000);
        print_matches(scan);

        free_scan(scan);
    }

    return 0;
}