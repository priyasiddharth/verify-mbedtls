#!/usr/bin/env python3

import os
import matplotlib.pyplot as plt

def count_code_lines(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()

    code_lines = [line for line in lines if not line.strip().startswith(("//", "/*", "*", "*/", "#")) and line.strip() != '']
    return len(code_lines)

def search_files(directory):
    code_files = {}
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            if "env" in filename and (filename.endswith(".c") or filename.endswith(".cc")):
                grandparent_directory = os.path.basename((os.path.dirname(foldername)))
                print(grandparent_directory)
                line_count = count_code_lines(os.path.join(foldername, filename))
                if grandparent_directory in code_files:
                    code_files[grandparent_directory] += line_count
                else:
                    code_files[grandparent_directory] = line_count
    return code_files

def plot_graph(code_files):
    grandparent_dirs = list(code_files.keys())
    line_counts = list(code_files.values())

    plt.figure(figsize=(10, 5))
    plt.bar(grandparent_dirs, line_counts, color='blue')
    plt.xlabel('Unit Proofs')
    plt.ylabel('Environment LOC')
    plt.title('Environment Lines of Code (LOC) per Unit Proof')
    plt.xticks([])
    plt.tight_layout()
    plt.savefig('lines_of_env_code_per_job.pdf')

def main():
    directory = input("Enter the directory to search: ")
    code_files = search_files(directory)

    if not code_files:
        print("No matching files found.")
        return

    total_lines = sum(code_files.values())
    avg_lines = total_lines / len(code_files)
    print(f"Average lines of code: {avg_lines:.2f}")

    plot_graph(code_files)

if __name__ == "__main__":
    main()
