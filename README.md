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
  -c, --check           Check for files in the destination that would be overwritten.

```

## Important Note

- The tool copies files from the source directory to the destination directory, not the other way around.
- Use with caution. The tool may overwrite existing files in the destination directory.
- I take no responsibility for accidental deletion of files. Use at your own risk!


## Examples

**Create a Hash File Only:**

```bash
python filesynctool.py -f /path/to/source -o output.txt --hash-only
```
   
**Create a Hash File and Copy Files:**

```bash
python filesynctool.py -f /path/to/source -d /path/to/destination -o output.txt
```

**Copy Files Only (if hash file creation is not needed):**

```bash
python filesynctool.py -f /path/to/source -d /path/to/destination
```

**Check for Potential Overwrites and Additions:**

```bash
python filesynctool.py -f /path/to/source -d /path/to/destination --check
```

Feel free to modify the script and the README as needed for your specific use case.


### Key Points:

1. **Introduction and Description**: Clearly states what the tool does and how it works.
2. **Synopsis**: Provides the command-line options and their descriptions.
3. **Important Note**: Alerts users to the potential risks of using the tool.
4. **Examples**: Shows various ways to run the script with different options.

This `README.md` should be comprehensive enough to help users understand how to use your file synchronization tool effectively.
   