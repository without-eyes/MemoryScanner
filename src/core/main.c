#include <memscan/ui/UserInterface.h>

int main () {
    system("tasklist"); // Get process id
    ui_run_scan();
    return 0;
}