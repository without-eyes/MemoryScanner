# Memory Scanner

This is a simple memory scanner for Windows platform written in C. The program allows you to scan the memory of a specified process,
search for specific values, and modify memory addresses. The executable file is already included in the directory, allowing you to directly run the
program without the need for compilation. 

## Features

- Scan the memory of a target process for specific values.
- Supports conditional searching based on equality, increase, or decrease.
- Poke values into memory addresses of the target process.

## Usage

1. **Run the Executable**: Simply execute the provided executable file `memscan.exe`.

2. **Enter Process ID and Data Size**: When prompted, enter the Process ID (PID) of the target process and the data size for scanning.

3. **Perform Scanning**:
   - Enter the next value to continue scanning.
   - Press `i` to search for increased values.
   - Press `d` to search for decreased values.
   - Press `m` to print the matches found.
   - Press `p` to poke a new value into a memory address.
   - Press `n` to start a new scan.
   - Press `q` to quit the program.

## Dependencies

- The executable file is self-contained and does not require any additional dependencies.

## Notes

- Make sure to run the program with appropriate permissions to access and modify memory of other processes.
- Incorrect usage or manipulation of memory addresses can lead to system instability or crashes. Use with caution.

## Author

The original author of this code is [gimmeamilk](https://www.youtube.com/@gimmeamilk).

I only add few comments to explain difficult lines of code, reorganized code into headers and source files.
