#!/usr/bin/env python
# 
# Check all testcases against library methods
#
import sys
import libfwregex
from pprint import pprint
from glob import glob

VERBOSE = False

if len(sys.argv) == 2:
    if sys.argv[1] == '-v':
        VERBOSE = True

filenames = glob('test/*.log')

for filename in filenames:
    for line in open(filename):
        # Test get_timestamp()
        res = libfwregex.get_timestamp(line)
        if not res:
            print('get_timestamp: TEST FAILED for line:')
            print(line)
        else:
            print('get_timestamp: Test OK')
            if VERBOSE:
                pprint(res)
                print('')

        # Test get_builtconn()
        res = libfwregex.get_builtconn(line)
        if not res:
            print('get_builtconn: TEST FAILED for line:')
            print(line)
        else:
            print('get_builtconn: Test OK')
            if VERBOSE:
                pprint(res)
                print('')

