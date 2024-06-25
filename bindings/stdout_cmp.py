#!/usr/bin/env python3
import argparse
import difflib
import re
import subprocess
import sys


def stdout_cmp(f1, f2):
    def lines_run(xs):
        out = subprocess.run(xs, stdout=subprocess.PIPE, check=True).stdout.decode()
        lines = out.splitlines(keepends=True)
        return out, [re.sub(r'([\t ])', '', ln) for ln in lines]

    out1, lns1 = lines_run(f1)
    out2, lns2 = lines_run(f2)
    dif = list(difflib.unified_diff(lns1, lns2))
    return len(dif) == 0, dif


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Comparing the standard output of two threads')
    parser.add_argument("-f1", nargs='+')
    parser.add_argument("-f2", nargs='+')
    argv = parser.parse_args(sys.argv[1:])
    res, dif = stdout_cmp(argv.f1, argv.f2)
    if not res:
        print('\n'.join(dif))
        exit(1)
    exit(0)
