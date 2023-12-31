#!/usr/bin/env python3
"""
This script parses the output generated by
llvm-opt --print-callgraph and saved to a file
to
query caller, callees information between functions
"""

import argparse
from typing import List, Dict, Optional

class CallGraph:
    def __init__(self):
        self.callers: Dict[str, List[str]] = {}
        self.callees: Dict[str, List[str]] = {}

    def add_call(self, caller: str, callee: str):
        if caller not in self.callees:
            self.callees[caller] = []
        self.callees[caller].append(callee)

        if callee not in self.callers:
            self.callers[callee] = []
        self.callers[callee].append(caller)

    def get_direct_callees(self, function: str) -> List[str]:
        return self.callees.get(function, [])

    def get_direct_callers(self, function: str) -> List[str]:
        return self.callers.get(function, [])

    def call_sequence(self, start: str, end: str) -> Optional[List[str]]:
        visited = set()
        return self._call_sequence_helper(start, end, visited)

    def _call_sequence_helper(self, current: str, end: str, visited: set) -> Optional[List[str]]:
        if current == end:
            return [current]

        visited.add(current)

        for callee in self.callees.get(current, []):
            if callee not in visited:
                next_seq = self._call_sequence_helper(callee, end, visited)
                if next_seq:
                    return [current] + next_seq

        return None

def parse_call_graph(file_path: str) -> CallGraph:
    with open(file_path, 'r') as f:
        data = f.read()
    graph = CallGraph()
    lines = data.split("\n")

    current_function = None
    for line in lines:
        if "Call graph node for function:" in line:
            current_function = line.split("'")[1]
        elif "calls function" in line:
            called_function = line.split("'")[1]
            graph.add_call(current_function, called_function)
    return graph


def main():
    parser = argparse.ArgumentParser(description="Analyze call graphs from llvm-opt output")

    parser.add_argument('--mode', required=True, choices=["callers", "callees", "path"],
                        help="Specify the operation mode: \
                        'callers' to get direct callers of a function, \
                        'callees' to get direct callees of a function, \
                        'path' to get call sequence between two functions.")

    parser.add_argument('--file', required=True, help="Path to the callgraph text file (mandatory).")

    parser.add_argument('--function', help="Specify the function name when using 'callers' or 'callees' mode.")
    parser.add_argument('--start', help="Specify the starting function for the 'path' mode.")
    parser.add_argument('--end', help="Specify the end function for the 'path' mode.")

    args = parser.parse_args()

    graph = parse_call_graph(args.file)

    if args.mode == "callers":
        if not args.function:
            parser.error("--function argument required for 'callers' mode.")
        print(f"Callers of the function {args.function}:")
        for func in graph.get_direct_callers(args.function):
            print(func)
    elif args.mode == "callees":
        if not args.function:
            parser.error("--function argument required for 'callees' mode.")
        print(f"Callees of the function {args.function}:")
        for func in graph.get_direct_callees(args.function):
            print(func)
    elif args.mode == "path":
        if not args.start or not args.end:
            parser.error("--start and --end arguments required for 'path' mode.")
        print(f"Call sequence between {args.start} and {args.end}:")
        for func in graph.call_sequence(args.start, args.end):
            print(func)


if __name__ == "__main__":
    main()
