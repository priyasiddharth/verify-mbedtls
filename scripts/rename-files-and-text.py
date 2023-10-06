#!/usr/bin/env python3

import os

def rename_and_replace(root_dir, old_text, new_text):
    for foldername, subfolders, filenames in os.walk(root_dir, topdown=False):
        # Rename filenames and replace text within files
        for filename in filenames:
            old_file_path = os.path.join(foldername, filename)

            # Rename filenames containing old_text
            if old_text in filename:
                new_filename = filename.replace(old_text, new_text)
                new_file_path = os.path.join(foldername, new_filename)
                os.rename(old_file_path, new_file_path)
                print(f"Renamed file: {old_file_path} -> {new_file_path}")

                # Adjust file path for text replacement
                old_file_path = new_file_path

            # Replace old_text with new_text within file content
            with open(old_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                file_contents = file.read()

            if old_text in file_contents:
                new_contents = file_contents.replace(old_text, new_text)
                with open(old_file_path, 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(new_contents)
                print(f"Replaced text within: {old_file_path}")

        # Rename directories containing old_text
        for subfolder in subfolders:
            if old_text in subfolder:
                old_folder_path = os.path.join(foldername, subfolder)
                new_folder_path = os.path.join(foldername, subfolder.replace(old_text, new_text))
                os.rename(old_folder_path, new_folder_path)
                print(f"Renamed directory: {old_folder_path} -> {new_folder_path}")

def main():
    root_directory = input("Enter the root directory to start the process: ")
    text_to_replace = input("Enter the text to replace in file and directory names, and within files: ")
    replacement_text = input("Enter the replacement text: ")

    rename_and_replace(root_directory, text_to_replace, replacement_text)

if __name__ == "__main__":
    main()
