#include <memscan/ui/UserInterface.h>
#include <stdio.h>

void print_matches(MEMBLOCK* mb_list) {
    MEMBLOCK* mb = mb_list;

    while (mb) {
        for (unsigned int offset = 0; offset < mb->size; offset += mb->data_size) {
            if (IS_IN_SEARCH(mb,offset)) {
                unsigned int val = peek(mb->hProc, mb->data_size, (size_t) (mb->addr + offset));
                printf("0x%08x: 0x%08x (%d) \r\n", mb->addr + offset, val, val);
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

unsigned int str2int (char *s) {
    int base = 10;

    if (s[0] == '0' && s[1] == 'x') {
        base = 16;
        s += 2;
    }

    return strtoul(s, NULL, base);
}

MEMBLOCK* ui_new_scan() {
    MEMBLOCK* scan = NULL;
    DWORD pid;
    int data_size;
    unsigned int start_val;
    SEARCH_CONDITION start_cond;
    char s[20];

    while (1) {
        printf("\r\nEnter the pid: ");
        fgets(s, sizeof(s), stdin);
        pid = str2int(s);
        printf("\r\nEnter the data size: ");
        fgets(s, sizeof(s), stdin);
        data_size = str2int(s);
        printf("\r\nEnter the start value, or \'u\' for unknown: ");
        fgets(s, sizeof(s), stdin);
        if (s[0] == 'u') {
            start_cond = COND_UNDONDITIONAL;
            start_val = 0;
        } else {
            start_cond = COND_EQUALS;
            start_val = str2int(s);
        }

        scan = create_scan(pid, data_size);
        if (scan) break;
        printf("\r\nInvalid scan");
    }

    update_scan(scan, start_cond, start_val);
    printf("\r\n%d matches found\r\n", get_match_count(scan));

    return scan;
}

void ui_poke (HANDLE hProc, int data_size) {
    unsigned int addr;
    unsigned int val;
    char s[20];

    printf("Enter the address: ");
    fgets(s, sizeof(s), stdin);
    addr = str2int(s);

    printf("\r\nEnter the value: ");
    fgets(s, sizeof(s), stdin);
    val = str2int(s);
    printf("\r\n");

    poke(hProc, data_size, addr, val);
}

void ui_run_scan () {
    unsigned int val;
    char s[20];
    MEMBLOCK* scan;

    scan = ui_new_scan();

    while (1) {
        printf("\r\nEnter the next value or");
        printf("\r\n[i] increased");
        printf("\r\n[d] decreased");
        printf("\r\n[m] print matches");
        printf("\r\n[p] poke address");
        printf("\r\n[n] new scan");
        printf("\r\n[q] quit\r\n");

        fgets(s, sizeof(s), stdin);
        printf("\r\n");

        switch(s[0]) {
            case 'i':
                update_scan(scan, COND_INCREASED, 0);
                printf("%d, mathes found\r\n", get_match_count(scan));
                break;
            case 'd':
                update_scan(scan, COND_DECREASED, 0);
                printf("%d, mathes found\r\n", get_match_count(scan));
                break;
            case 'm':
                print_matches(scan);
                break;
            case 'p':
                ui_poke(scan->hProc, scan->data_size);
                break;
            case 'n':
                free_scan(scan);
                scan = ui_new_scan();
                break;
            case 'q':
                free_scan(scan);
                return;
            default:
                val = str2int(s);
                update_scan(scan, COND_EQUALS, val);
                printf("%d matches found\r\n", get_match_count(scan));
                break;
        }
    }
}