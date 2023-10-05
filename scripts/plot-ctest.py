#!/usr/bin/env python3

import os
import re
import subprocess
import matplotlib.pyplot as plt

def run_ctest():
    # Run CTest and capture the output
    # NOTE: change universal_newlines to text for python version 3.10. This works for python 3.6
    result = subprocess.run(['ctest', '--schedule-random', '--output-log', 'ctest_log.txt'], universal_newlines=True)
    if result.returncode != 0:
        print(f"CTest failed with return code {result.returncode}")
        return None

    # Parse the log file to extract timing information
    timing_info = []
    with open('ctest_log.txt', 'r') as file:
        for line in file:
            #match = re.search(r'(?P<test_name>\w+)\s+passed in (?P<time>\d+\.\d+)s', line)
            match = re.search(r'Passed\s+([\d.]+)\s+sec', line)
            if match:
                time = float(match.group(1))
                print('time:', time)
                timing_info.append(time)

    return timing_info

def main():
    overall_timing_info = []
    for _ in range(1):
        timing_info = run_ctest()
        if timing_info is not None:
            overall_timing_info.extend(timing_info)

    # Plot the timing information as a histogram
    plt.figure(figsize=(10, 5))
    plt.hist(overall_timing_info, bins=30, color='blue', edgecolor='black')
    plt.xlabel('Execution Time (s)')
    plt.ylabel('Number of Tests')
    plt.title('CTest Timing Histogram')
    plt.tight_layout()
    plt.savefig('ctest_timing_histogram.pdf')

if __name__ == "__main__":
    main()
