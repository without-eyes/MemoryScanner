run:
	gcc -c src/core/main.c -Iinclude
	gcc -c src/core/CoreFunctions.c -Iinclude
	gcc -c src/ui/UserInterface.c -Iinclude
	gcc -o memscan main.o CoreFunctions.o UserInterface.o
