#!/usr/bin/env python3

import os
import hashlib
import argparse
import shutil
import sys
import fnmatch
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import threading
import datetime

def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of the file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def log_to_protocol(log_message):
    """Write a message to the protocol.txt file."""
    with open("protocol.txt", "a", encoding="utf-8") as log_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - {log_message}\n")

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
    """Write the file names and their hashes to a text file with UTF-8 encoding."""
    with open(output_file, "w", encoding="utf-8") as f:
        for file_name, file_hash in files_and_hashes:
            f.write(f"{file_name}: {file_hash}\n")
    log_to_protocol(f"Hashes have been written to {output_file}")

def ensure_destination_exists(dest_file, dest_folder):
    """Ensure the destination folder exists, creating it if necessary."""
    dest_path = os.path.join(dest_folder, dest_file)
    dest_dir = os.path.dirname(dest_path)
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        log_to_protocol(f"Created directory {dest_dir}")
    return dest_path

def check_for_overwrites(source_directory, dest_directory, progress_callback):
    """Check if there are files in the destination directory that would be overwritten or added."""
    files_to_check = get_files_and_hashes(source_directory)
    overwrite_files = []
    files_in_destination = {}

    # Read all files and their hashes from the destination directory
    for root, dirs, files in os.walk(dest_directory):
        for file_name in files:
            relative_path = os.path.relpath(os.path.join(root, file_name), dest_directory)
            dest_path = os.path.join(dest_directory, relative_path)
            if not should_exclude(file_name):
                dest_hash = calculate_sha256(dest_path)
                files_in_destination[relative_path] = dest_hash

    # Check for files that would be overwritten or need to be copied
    total_files = len(files_to_check)
    for i, (relative_path, src_hash) in enumerate(files_to_check):
        src_path = os.path.join(source_directory, relative_path)
        dest_path = os.path.join(dest_directory, relative_path)
        
        if relative_path in files_in_destination:
            dest_hash = files_in_destination[relative_path]
            if dest_hash != src_hash:
                overwrite_files.append((relative_path, src_path, dest_path))
        else:
            # File is in source but not in destination
            overwrite_files.append((relative_path, src_path, None))

        progress_callback(i + 1, total_files)

    if overwrite_files:
        log_to_protocol("Files that would be overwritten or added:")
        for rel_path, src, dest in overwrite_files:
            if dest:
                log_to_protocol(f"Source: {src}, Destination: {dest}")
            else:
                log_to_protocol(f"Source: {src}, Destination: Not present")
    else:
        log_to_protocol("No files would be overwritten or added.")

def should_exclude(file_name):
    """Determine if a file should be excluded based on its name."""
    exclusion_patterns = [
        ".nextcloudsync.log",
        ".sync_*"
    ]
    for pattern in exclusion_patterns:
        if fnmatch.fnmatch(file_name, pattern):
            return True
    return False

def copy_files_if_needed(source_directory, dest_directory, progress_callback):
    """Copy files from source to destination if they don't exist or have different hash values."""
    total_files = sum([len(files) for _, _, files in os.walk(source_directory)])
    file_count = 0

    for root, dirs, files in os.walk(source_directory):
        for file_name in files:
            if should_exclude(file_name):
                log_to_protocol(f"Excluded: {file_name}")
                continue  # Skip files that match exclusion patterns

            src_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(src_path, source_directory)
            dest_path = ensure_destination_exists(relative_path, dest_directory)
            
            if not os.path.exists(dest_path):
                # File does not exist in destination, so copy it
                shutil.copy2(src_path, dest_path)
                log_to_protocol(f"Copied: {src_path} to {dest_path}")
            else:
                # Compare file hashes
                src_hash = calculate_sha256(src_path)
                dest_hash = calculate_sha256(dest_path)
                if dest_hash != src_hash:
                    # Hashes differ, so copy the file
                    shutil.copy2(src_path, dest_path)
                    log_to_protocol(f"Updated: {src_path} to {dest_path}")

            file_count += 1
            progress_callback(file_count, total_files)

def run_operation(source_directory, dest_directory, output_file, hash_only, check, progress_callback):
    """Run the file operations based on provided parameters."""
    if output_file:
        files_and_hashes = get_files_and_hashes(source_directory)
        write_hashes_to_file(files_and_hashes, output_file)

    if check:
        if dest_directory:
            check_for_overwrites(source_directory, dest_directory, progress_callback)
        else:
            log_to_protocol("Error: --check requires --destination to be specified.")
        return

    if dest_directory:
        if hash_only:
            log_to_protocol("Hash file created. No files have been copied.")
        else:
            copy_files_if_needed(source_directory, dest_directory, progress_callback)

def gui():
    """Create a GUI for setting paths and options."""
    def select_source_directory():
        """Open a dialog to select the source directory."""
        path = filedialog.askdirectory()
        if path:
            source_entry.delete(0, tk.END)
            source_entry.insert(0, path)

    def select_destination_directory():
        """Open a dialog to select the destination directory."""
        path = filedialog.askdirectory()
        if path:
            dest_entry.delete(0, tk.END)
            dest_entry.insert(0, path)

    def select_output_file():
        """Open a dialog to select the output file."""
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                           filetypes=[("Text files", "*.txt")])
        if path:
            output_entry.delete(0, tk.END)
            output_entry.insert(0, path)

    def execute_operation():
        """Run the file operations based on user input."""
        source_directory = source_entry.get()
        dest_directory = dest_entry.get()
        output_file = output_entry.get()
        hash_only = hash_only_var.get()
        check = check_var.get()

        if not source_directory:
            messagebox.showerror("Error", "Source directory is required.")
            return
        if check and not dest_directory:
            messagebox.showerror("Error", "--check requires a destination directory.")
            return

        log_to_protocol("Starting operation...")
        log_to_protocol(f"Source directory: {source_directory}")
        if dest_directory:
            log_to_protocol(f"Destination directory: {dest_directory}")
        if output_file:
            log_to_protocol(f"Output file: {output_file}")
        log_to_protocol(f"Hash only: {hash_only}")
        log_to_protocol(f"Check for overwrites: {check}")

        # Run the operation in a separate thread
        threading.Thread(target=run_operation_threaded, args=(source_directory, dest_directory, output_file, hash_only, check)).start()

    def run_operation_threaded(source_directory, dest_directory, output_file, hash_only, check):
        """Wrapper to run the operation and handle the progress bar in a thread."""
        progress_bar.start()
        run_operation(source_directory, dest_directory, output_file, hash_only, check, update_progress)
        progress_bar.stop()
        log_to_protocol("Operation completed.")

    def update_progress(current, total):
        """Update the progress bar based on the current progress."""
        progress_bar['value'] = (current / total) * 100
        root.update_idletasks()

    # Create the main window
    root = tk.Tk()
    root.title("File Operation GUI")

    # Create and place widgets
    tk.Label(root, text="Source Directory:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
    source_entry = tk.Entry(root, width=50)
    source_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=select_source_directory).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(root, text="Destination Directory:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    dest_entry = tk.Entry(root, width=50)
    dest_entry.grid(row=1, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=select_destination_directory).grid(row=1, column=2, padx=10, pady=5)

    tk.Label(root, text="Output File:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
    output_entry = tk.Entry(root, width=50)
    output_entry.grid(row=2, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse", command=select_output_file).grid(row=2, column=2, padx=10, pady=5)

    hash_only_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Hash Only", variable=hash_only_var).grid(row=3, column=1, padx=10, pady=5, sticky="w")

    check_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Check for Overwrites", variable=check_var).grid(row=4, column=1, padx=10, pady=5, sticky="w")

    tk.Button(root, text="Run", command=execute_operation).grid(row=5, column=1, padx=10, pady=20)

    # Add a progress bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress_bar.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

    root.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Compute SHA-256 hashes for files, optionally copy them, check for overwrites, and show a GUI.')
    parser.add_argument('-f', '--folder', type=str, help='Path to the source directory to scan.')
    parser.add_argument('-d', '--destination', type=str, help='Path to the destination directory to copy files to.')
    parser.add_argument('-o', '--output', type=str, help='Output file to write the hashes.')
    parser.add_argument('--hash-only', action='store_true', help='Create a hash file without copying files.')
    parser.add_argument('-c', '--check', action='store_true', help='Check for files in the destination that would be overwritten.')
    parser.add_argument('--no-gui', action='store_true', help='Disable GUI and use the command line interface.')

    args = parser.parse_args()

    if args.no_gui:
        run_operation(args.folder, args.destination, args.output, args.hash_only, args.check, lambda x, y: None)
    else:
        gui()

if __name__ == "__main__":
    # Set console output encoding to UTF-8 (if applicable)
    if sys.stdout.encoding.lower() == 'cp437' or sys.stdout.encoding.lower() == 'charmap':
        print("Console output encoding may not support all Unicode characters. Consider using an environment with UTF-8 encoding.")
    main()
