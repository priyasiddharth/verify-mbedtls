#!/usr/bin/env python3

import argparse
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

KEY_TO_TESTNAME = 'key_to_testname.csv'

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

def calculate_and_output_averages(data):
    total_env_lines =   sum(item['total_LOC'] for item in data)
    total_unit_proof_lines = sum(item['unit_proof_LOC'] for item in data)
    num_tests = len(data)

    avg_env_lines = total_env_lines / num_tests if num_tests != 0 else 0
    avg_unit_proof_lines = total_unit_proof_lines / num_tests if num_tests != 0 else 0

    print(f"Average lines of environment code: {avg_env_lines:.2f}")
    print(f"Average lines of unit proof code: {avg_unit_proof_lines:.2f}")


def plot_bargraph(data, use_keys=False):
    # Convert your data into a Pandas DataFrame
    df = pd.DataFrame(data)

     # Generate numeric keys if option is selected
    if use_keys:
        key_map = {name: i for i, name in enumerate(df['test_name'], 1)}
        df['test_name'] = df['test_name'].map(key_map)
        # Write the key to test name mapping to a CSV
        print(f'Writing key to testname data in {KEY_TO_TESTNAME}.')
        pd.DataFrame(list(key_map.items()), columns=['Key', 'Test Name']).to_csv(KEY_TO_TESTNAME, index=False)
    else:
        df['test_name'] = df['test_name'].str.replace('ssl_msg_', '')
    # Melt the DataFrame to have test names as individual rows
    df_melted = df.melt(id_vars=['test_name'], value_vars=['average_ctest_running_time', 'total_LOC'], var_name='Metric', value_name='Value')
    # Set Pandas to display all rows of the DataFrame
    pd.set_option('display.max_rows', None)

    # Set Pandas to display all columns of the DataFrame
    pd.set_option('display.max_columns', None)

    # Optional: Set the width of each column to avoid line wrapping
    pd.set_option('display.width', None)

    print(df_melted)

    # melted the grouped bar plot

    plt.figure(figsize=(20,12)) # 16:9
    ax = sns.barplot(x='test_name', y='Value', hue='Metric', data=df_melted, palette='deep')
    plt.xlabel('Test key', fontsize=24)
    plt.ylabel('Value', fontsize=24)
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles, ['Execution time (s)', 'Lines of Code for unit proof + environment'],  fontsize=24)
    #plt.xticks(rotation=45)
    plt.xticks(fontsize=22)  # Adjust rotation and fontsize as needed
    plt.yticks(fontsize=22)
    plt.tight_layout()
    plt.savefig('bar_graph_test_time_and_LOC.pdf')

def main():
    parser = argparse.ArgumentParser(description='Generate graphs from CSV data.')
    parser.add_argument('--use-keys', action='store_true', help='Use numeric keys instead of test names for the graph labels')
    args = parser.parse_args()   
    data = pd.read_csv('test_data.csv').to_dict(orient='records')  # Read CSV and convert it to list of dictionaries
    calculate_and_output_averages(data)
    plot_bargraph(data, args.use_keys)


if __name__ == "__main__":
    main()
