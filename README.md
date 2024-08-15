# File Sync Tool
A Tool that can sync two folders!

## How does it work
The tool reads al contents from folder a and b. If in folder b files are not the same as in folder a, the filde from folder a will be copied to folder b and overwrite the existing file.

## Synopsis

```
./filesynctool.py -h

  -h, --help            show this help message and exit
  -f FOLDER, --folder FOLDER
                        Path to the source directory to scan.
  -d DESTINATION, --destination DESTINATION
                        Path to the destination directory to copy files to.
  -o OUTPUT, --output OUTPUT
                        Output file to write the hashes.
  --hash-only           Create a hash file without copying files.

```