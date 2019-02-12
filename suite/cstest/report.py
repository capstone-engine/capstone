#!/usr/bin/python

import re
import sys
import getopt
from subprocess import Popen, PIPE
from pprint import pprint as ppr
import os


def Usage(s):
	print 'Usage: {} -t <cstest_path> [-f <file_name.cs>] [-d <directory>]'.format(s)
	sys.exit(-1)

def get_report_file(toolpath, filepath, getDetails):
	cmd = [toolpath, '-f', filepath]
	process = Popen(cmd, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()

#	stdout
	failed_tests = []
#	print '---> stdout\n', stdout
#	print '---> stderr\n', stderr
	matches = re.finditer(r'\[\s+RUN\s+\]\s+(.*)\n\[\s+FAILED\s+\]', stdout)
	for match in matches:
		failed_tests.append(match.group(1))
#	stderr
	counter = 0
	details = []
	for line in stderr.split('\n'):
		if '[  PASSED  ] 0 test(s).' in line:
			break
		elif 'LINE' in line:
			continue
		elif 'ERROR' in line and ' --- ' in line:
			try:
				details.append((failed_tests[counter], line.split(' --- ')[1]))
			except IndexError:
				details.append(('Unknown test', line.split(' --- ')[1]))
			counter += 1
		else:
			continue
	print '\n[-] There are/is {} failed test(s)'.format(len(details))
	if len(details) > 0 and getDetails:
		print '[-] Detailed report for {}:\n'.format(filepath)
		for f, d in details:
			print '\t[+] {}:\n\t\t{}\n'.format(f, d)
		print '\n'

def get_report_folder(toolpath, folderpath, details):
	for root, dirs, files in os.walk(folderpath):
		path = root.split(os.sep)
		for f in files:
			if f.split('.')[-1] == 'cs':
				print '[-] Target:', f,
				get_report_file(toolpath, os.sep.join(x for x in path) + os.sep + f, details) 

if __name__ == '__main__':
	Done = False
	details = False
	toolpath = ''
	try:
		opts, args = getopt.getopt(sys.argv[1:], "t:f:d:D")
		for opt, arg in opts:
			if opt == '-f':
				get_report_file(toolpath, arg, details)
				Done = True
			elif opt == '-d':
				get_report_folder(toolpath, arg, details)
				Done = True
			elif opt == '-t':
				toolpath = arg
			elif opt == '-D':
				details = True	
	except getopt.GetoptError:
		Usage(sys.argv[0])

	if Done is False:
		Usage(sys.argv[0])
