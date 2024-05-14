#!/usr/bin/env python3


import argparse
import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def load_dict_with_tuple_keys(filename):
    with open(filename, 'r') as f:
        converted_dict = json.load(f)
    original_dict = {tuple(eval(key)): value for key, value in converted_dict.items()}
    return original_dict

def sorting_key(item):
    knobname, knobval, job, times = item[0]  # Extract the key from the item
    return job  

def extract_data_pair(data, subkey, parameter):
    filtered = {job: v for (knobname, knobval, job, times), v in data.items() if knobval == subkey}
    x = 0
    y = 0
    for key in filtered.keys():
        if 'ownsem' in key:
            x = filtered[key][parameter]
        else:
            y = filtered[key][parameter]  
    return (x, y)

def extract_datalist(data, parameter):
    knob_range = {key[1] for key in data.keys()}
    data_pairs = [(extract_data_pair(data, knob, parameter)) for knob in knob_range]
    x = [item[0] for item in data_pairs]  # Extract first element of each tuple
    y = [item[1] for item in data_pairs]  # Extract second element of each tuple
    return (x, y)  # Return tuple

def scatter_plot(x, y, job_name):
    #df = pd.DataFrame({'ownsem': x, 'baseline': y})
    # Plot scatterplot with a unique marker style for each job
    marker_styles = ['o', '^', 's', 'd', 'x']  # You can extend this list for more job names
    plt.scatter(x, y, label=job_name, marker=marker_styles.pop(0))

def plot_lines(x, y):
    # Plot y=x line
    plt.plot(x, y, label='y = x', color='#FFB6C1') #pink

    # Plot y=3x line
    plt.plot(x, [3 * val for val in x], label='y = 3x', color='#98FB98') #green

def doPlot(data, parameter, job_names, out_filename):
  max_x_value = 0
  max_y_value = 0
  # Iterate over job names and plot each file separately
  for job_name, json_data in zip(job_names, data):
    x, y = extract_datalist(json_data, parameter)
    scatter_plot(x, y, job_name) 
    # Update maximum x and y values
    max_x_value = max(max_x_value, max(x))
    max_y_value = max(max_y_value, max(y))

  max_marker_size = plt.rcParams['lines.markersize']
  #Get the maximum value from both x and y and adjust plot
  max_value = max(max_x_value, max_y_value) + max_marker_size
  plt.xlim(0, max_value)
  plt.ylim(0, max_value)
  # Plot y=x and y=3x lines
  x_line = np.linspace(0, max_value, 100)
  plot_lines(x_line, x_line)
  # Add grid
  plt.grid(True)
  # Add labels
  plt.xlabel('Ownsem(s)')
  plt.ylabel('Baseline(s)')

  # Show legend
  plt.legend()
  plt.savefig(out_filename, format='pdf')
  plt.show()

def main():
    # Setup command line argument parsing
    parser = argparse.ArgumentParser(description='Run tests with different parameters, grep output, and store results.')
    parser.add_argument('--parameter', default='BMC.solve', help='Parameter')
    parser.add_argument('--input', nargs='+', help='List of filenames for the input JSON')
    parser.add_argument('--job_names', nargs='+', help='List of job names')
    parser.add_argument('--output', default='scatter_plot.pdf', help='filename of scatter plot')

    args = parser.parse_args()

    data = [load_dict_with_tuple_keys(filename) for filename in args.input]
    doPlot(data, args.parameter, args.job_names, args.output)

if __name__ == '__main__':
    main()


""" import argparse
import json
import pdb
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def load_dict_with_tuple_keys(filename):
  with open(filename, 'r') as f:
    converted_dict = json.load(f)
  original_dict = {tuple(eval(key)): value for key, value in converted_dict.items()}
  return original_dict

def sorting_key(item):
  knobname,knobval,job,times = item[0]  # Extract the key from the item
  return job  


def extract_data_pair(data,subkey, parameter):
  filtered = {job:v for (knobname,knobval,job,times),v in data.items() if knobval == subkey}
  x=0
  y=0
  for key in filtered.keys():
    if 'ownsem' in key:
      x = filtered[key][parameter]
    else:
      y = filtered[key][parameter]  
  return (x,y)

def extract_datalist(data,parameter):
  knob_range = {key[1] for key in data.keys()}
  data_pairs = [(extract_data_pair(data, knob, parameter)) for knob in knob_range]
  x = [item[0] for item in data_pairs]  # Extract first element of each tuple
  y = [item[1] for item in data_pairs]  # Extract second element of each tuple
  return (x,y)  # Return tuple

def scatter_plot(x,y):
  # Convert data to a DataFrame
  df = pd.DataFrame({'ownsem': x, 'shadow': y})

  # Plot scatterplot
  df.plot.scatter(x='ownsem', y='shadow', title='Scatter Plot')  
  # Save the plot
  plt.legend()
  plt.grid(True)
  # Calculate the maximum marker size
  max_marker_size = plt.rcParams['lines.markersize']
  # Set limits for both axes to be the same
  max_value = max(max(x), max(y)) + max_marker_size

  plt.xlim(0, max_value)
  plt.ylim(0, max_value)
  # Plot y=x line
  x_line = np.linspace(0, max_value, 100)
  y_line = x_line
  plt.plot(x_line, y_line, label='y = x')

  # Plot y=3x line
  y_3x_line = 3 * x_line
  plt.plot(x_line, y_3x_line, label='y = 3x')

  # Add legend
  plt.legend()

  plt.savefig('scatter_plot.png')  # Save the plot as 'scatter_plot.png'
  plt.show()

def doPlot(data, parameter):
  x,y = extract_datalist(data, parameter)
  scatter_plot(x, y)

def main():
  # Setup command line argument parsing
  parser = argparse.ArgumentParser(description='Run tests with different parameters, grep output, and store results.')
  parser.add_argument('--parameter', default='BMC.solve', help='Parameter')
  parser.add_argument('--input', default='results.json', help='Filename for the input JSON')
  args = parser.parse_args()

  data = load_dict_with_tuple_keys(args.input)
  doPlot(data, args.parameter)

if __name__ == '__main__':
  main()
 """