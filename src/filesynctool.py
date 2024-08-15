#!/usr/bin/env python3

import os
import hashlib
import argparse
import shutil


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of the file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_files_and_hashes(directory):
    """Get a list of file names and their corresponding SHA-256 hashes, including subfolder paths."""
    files_and_hashes = []
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            # Create a relative path including subfolders
            relative_path = os.path.relpath(os.path.join(root, file_name), directory)
            file_hash = calculate_sha256(os.path.join(root, file_name))
            files_and_hashes.append((relative_path, file_hash))
    return files_and_hashes


def write_hashes_to_file(files_and_hashes, output_file):
    """Write the file names and their hashes to a text file."""
    with open(output_file, "w") as f:
        for file_name, file_hash in files_and_hashes:
            f.write(f"{file_name}: {file_hash}\n")


def ensure_destination_exists(dest_file, dest_folder):
    """Ensure the destination folder exists, creating it if necessary."""
    dest_path = os.path.join(dest_folder, dest_file)
    dest_dir = os.path.dirname(dest_path)
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    return dest_path


def check_for_overwrites(source_directory, dest_directory):
    """Check if there are files in the destination directory that would be overwritten."""
    files_to_check = get_files_and_hashes(source_directory)
    overwrite_files = []
    
    for relative_path, src_hash in files_to_check:
        src_path = os.path.join(source_directory, relative_path)
        dest_path = os.path.join(dest_directory, relative_path)
        
        if os.path.exists(dest_path):
            dest_hash = calculate_sha256(dest_path)
            if dest_hash != src_hash:
                overwrite_files.append((relative_path, src_path, dest_path))
    
    if overwrite_files:
        print("The following files would be overwritten:")
        for rel_path, src, dest in overwrite_files:
            print(f"Source: {src}")
            print(f"Destination: {dest}")
            print(f"Relative Path: {rel_path}")
            print()
    else:
        print("No files would be overwritten.")


def copy_files_if_needed(source_directory, dest_directory):
    """Copy files from source to destination if they don't exist or have different hash values."""
    for root, dirs, files in os.walk(source_directory):
        for file_name in files:
            src_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(src_path, source_directory)
            dest_path = ensure_destination_exists(relative_path, dest_directory)
            
            if not os.path.exists(dest_path):
                # File does not exist in destination, so copy it
                shutil.copy2(src_path, dest_path)
                print(f"Copied: {src_path} to {dest_path}")
            else:
                # Compare file hashes
                src_hash = calculate_sha256(src_path)
                dest_hash = calculate_sha256(dest_path)
                if dest_hash != src_hash:
                    # Hashes differ, so copy the file
                    shutil.copy2(src_path, dest_path)
                    print(f"Updated: {src_path} to {dest_path}")


def main():
    parser = argparse.ArgumentParser(description='Compute SHA-256 hashes for files in a source directory, optionally copy them to a destination directory and check for potential overwrites.')
    parser.add_argument('-f', '--folder', type=str, required=True, help='Path to the source directory to scan.')
    parser.add_argument('-d', '--destination', type=str, help='Path to the destination directory to copy files to.')
    parser.add_argument('-o', '--output', type=str, help='Output file to write the hashes.')
    parser.add_argument('--hash-only', action='store_true', help='Create a hash file without copying files.')
    parser.add_argument('-c', '--check', action='store_true', help='Check for files in the destination that would be overwritten.')

    args = parser.parse_args()
    
    # Get the file names and their hash values
    files_and_hashes = get_files_and_hashes(args.folder)

    # Write the hash values to a file if specified
    if args.output:
        write_hashes_to_file(files_and_hashes, args.output)
        print(f"Hashes have been written to {args.output}")

    # Check for potential overwrites if --check is set
    if args.check:
        if args.destination:
            check_for_overwrites(args.folder, args.destination)
        else:
            print("Error: --check requires --destination to be specified.")
        return

    # Copy files to the destination directory if needed and destination is provided
    if args.destination:
        if args.hash_only:
            print("Hash file created. No files have been copied.")
        else:
            copy_files_if_needed(args.folder, args.destination)


if __name__ == "__main__":
    main()

