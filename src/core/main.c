#include <memscan/ui/UserInterface.h>

int main () {
    system("tasklist"); // Output a list of processes to allow user obtain process id
    ui_run_scan();
}