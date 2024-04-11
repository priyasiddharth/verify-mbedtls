#!/usr/bin/env python3

import argparse
import subprocess
import json
import os
import re
from pathlib import Path
import tempfile
import shutil

import pdb 

# Compile the grep pattern
grep_pattern = 'BRUNCH_STAT.*|Z3_STAT.*'

def save_dict_with_tuple_keys(filename, dict):
  # Convert tuple keys to a string representation
  converted_dict = {str(key): value for key, value in dict.items()}
  with open(filename, 'w') as f:
    json.dump(converted_dict, f, indent=2)

def parse_brunch_stat(lines):
  stats = {}
  for line in lines:
    # Remove the 'BRUNCH_STAT' or 'Z3_STAT' prefix and then split key,value
    if line.startswith('BRUNCH_STAT'):
      key_value = line.replace('BRUNCH_STAT ', '', 1).rsplit(' ', 1)
    else:
      key_value = line.replace('Z3_STAT ', '', 1).rsplit(':', 1)
    if len(key_value) == 2:
      key, value = key_value
      # Try to convert value to int, then float, or keep as string if it fails
      try:
        value = int(value)
      except ValueError:
        try:
            value = float(value)
        except ValueError:
            value = value.lower() == 'true'  # Convert "TRUE" string to boolean True
    else:
      # Handle case with no value
      key = key_value[0]
      value = None
    stats[key] = value
  return stats

def runSingleTestOnce(build_dir, test_name):
  """Run a test (once) and return output."""
  env_vars = {
    'VERIFY_FLAGS': '--command=bpf --log=bmc_z3stats',
  }
  new_env = os.environ.copy()
  new_env.update(env_vars)
  proc = subprocess.run(['ctest', '--timeout=2000', '--verbose', '-R', test_name], env=new_env, cwd=build_dir, capture_output=True, text=True, check=True)
  # Search for the pattern in the output
  return re.compile(grep_pattern).findall(proc.stdout)
  
def runTestsForParamNTimes(build_dir, seahorn_root, param_name, params, test_names, times, const_params):
  # Dictionary to store results
  results = {}
  constant_parameters = convert_params_from_list(const_params)
  for param in params:
    # Run cmake with the current parameter
    CMAKE_CONFIGURE = ['cmake',
                       '-DSEA_LINK=llvm-link-14',
                      '-DCMAKE_C_COMPILER=clang-14',
                      '-DCMAKE_CXX_COMPILER=clang++-14',
                      f'-DSEAHORN_ROOT={seahorn_root}',
                      '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                      f'-D{param_name}={param}'] + constant_parameters + ['../',
                      '-GNinja']
    print(CMAKE_CONFIGURE)
    subprocess.run(CMAKE_CONFIGURE, cwd = build_dir, check=True)
    print('Building...')
    # build 
    subprocess.run('ninja', cwd=build_dir, check=True)

    for test in test_names:
        for run_number in range(1, times + 1):
            # Run the test with ctest and capture the output
            matches = runSingleTestOnce(build_dir, test)
            # Store matches in the dictionary, including run number in the key
            if matches:
                results[(param_name, param, test, run_number)] = parse_brunch_stat(matches)
            else: 
                results[(param_name, param, test, run_number)] = 'error'
        print(f'{param_name}, {param}, {test}, {run_number}', results[(param_name, param, test, run_number)])
  return results


def create_tmp_subdir():
  # Step 1: Determine the current script directory
  base_directory = os.getcwd()
  print(f"Base directory: {base_directory}")

  # Step 2: Create a temporary directory in the base directory
  temp_dir_path = tempfile.mkdtemp(dir=base_directory)
  print(f"Temporary directory created at: {temp_dir_path}")
  return temp_dir_path

def convert_params_from_list(param_list):
  # Prefix each item in the list with "-D" and join them with spaces
  result = ['-D' + item for item in param_list]
  return result

class SplitArgsAction(argparse.Action):
  def __call__(self, parser, namespace, values, option_string=None):
      # Split the input string by commas and assign to the destination attribute
      setattr(namespace, self.dest, values.split(','))


def main():
  # Setup command line argument parsing
  parser = argparse.ArgumentParser(description='Run tests with different parameters, grep output, and store results.')
  parser.add_argument('--parameter', help='Parameter and values in the format "name=[value1,value2,...]"', required=True)
  parser.add_argument('--tests', nargs='+', help='List of tests', required=True)
  parser.add_argument('--seahorn_root', help='SeaHorn install directory', required=True)
  parser.add_argument('--runs', type=int, help='Number of times to run each test', required=True)
  parser.add_argument('--output', default='results.json', help='Filename for the output JSON')
  parser.add_argument('--const_parameters', action=SplitArgsAction, help='List of param=value to set as defaults.', required=True)
  args = parser.parse_args()

  # Extract parameter name and values
  param_match = re.match(r'(\w+)=\[(.*?)\]', args.parameter)
  if not param_match:
    raise ValueError("Parameter format is incorrect. Please use 'name=[value1,value2,...]'")
  param_name, param_values_str = param_match.groups()
  param_values = param_values_str.split(',')
  
  temp_dir_path = create_tmp_subdir()
  try:
    results = runTestsForParamNTimes(temp_dir_path,
                                    args.seahorn_root,
                                    param_name, 
                                    param_values,
                                    args.tests,
                                    args.runs,
                                    args.const_parameters)  
    # Output the results to a JSON file
    save_dict_with_tuple_keys(args.output, results)
    print(f"Results stored in {args.output}")  
  finally:
        # Step 4: Cleanup - delete the temporary directory and its contents
        shutil.rmtree(temp_dir_path)
        print("Temporary directory and its contents have been deleted")


if __name__ == '__main__':
  main()

  