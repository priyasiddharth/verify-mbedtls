#!/usr/bin/env python3

import os
import re
import subprocess
import csv
from collections import defaultdict

NUM_RUNS = 10

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def run_ctest():
    os.chdir("build-rel")
    timing_info = defaultdict(list)
    print(f"{bcolors.OKCYAN}Info: Running {NUM_RUNS} times.{bcolors.ENDC}")
    for _ in range(NUM_RUNS):
        result = subprocess.run(['ctest', '--schedule-random', '--output-log', 'ctest_log.txt'], universal_newlines=True)
        if result.returncode != 0:
            print(f"CTest failed with return code {result.returncode}")
            return None

        with open('ctest_log.txt', 'r') as file:
            for line in file:
                match = re.search(r'(?P<test_name>\w+)_harness_unsat_test.*Passed\s+([\d.]+)\s+sec', line)
                if match:
                    test_name = match.group('test_name')
                    time = float(match.group(2))
                    timing_info[test_name].append(time)

    avg_timing_info = {test: sum(times)/len(times) for test, times in timing_info.items()}
    os.chdir("..")
    return avg_timing_info

def count_code_lines(directory, file_patterns):
    code_lines = 0
    for foldername, _, filenames in os.walk(directory):
        for filename in filenames:
            if any(filename.endswith(pattern) for pattern in file_patterns):
                with open(os.path.join(foldername, filename), 'r', encoding='utf-8', errors='ignore') as file:
                    lines = file.readlines()
                non_comment_lines = [line for line in lines if not line.strip().startswith(("//", "/*", "*", "*/", "#")) and line.strip() != '']
                code_lines += len(non_comment_lines)
    return code_lines

def main():
    timing_info = run_ctest()
    if not timing_info:
        print("No timing information collected.")
        return
    data = []
    with open('test_data.csv', mode='w', newline='') as csv_file:
        fieldnames = ['test_name', 'average_ctest_running_time', 'unit_proof_LOC', 'env_LOC', 'total_LOC']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for test_name, avg_run_time in timing_info.items():
            unit_proof_loc = count_code_lines(f"seahorn/jobs/library/{test_name}/unit_proof", [".c"])
            env_loc = count_code_lines(f"seahorn/jobs/library/{test_name}/env", [".cc"])
            env_c_loc = count_code_lines(f"seahorn/jobs/library/{test_name}/env_c", [".c"])
            row = {
                'test_name': test_name,
                'average_ctest_running_time': avg_run_time,
                'unit_proof_LOC': unit_proof_loc,
                'env_LOC': env_loc + env_c_loc,
                'total_LOC': unit_proof_loc + env_loc + env_c_loc
            }
            writer.writerow(row)
            data.append(row)


if __name__ == "__main__":
    main()
