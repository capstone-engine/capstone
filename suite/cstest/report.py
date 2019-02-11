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

def get_report_file(toolpath, filepath):
	cmd = [toolpath, '-f', filepath]
	process = Popen(cmd, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()

#	stdout
	failed_tests = []
#	print stdout
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
		elif 'ERROR' in line:
			details.append((failed_tests[counter], line.split(' --- ')[1]))
			counter += 1
		else:
			continue
#	print stderr
	print '\n[-] There are/is {} failed test(s)'.format(len(details))
	if len(details) > 0:
		print '[-] Detailed report for {}:\n'.format(filepath)
		for f, d in details:
			print '\t[+] {}:\n\t\t{}\n'.format(f, d)
		print '\n'

def get_report_folder(toolpath, folderpath):
	cmd = [toolpath, '-d', folderpath]
	process = Popen(cmd, stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	
	print '\n[-] Folder {}'.format(folderpath)
	print '[-] General information\n'
	file_status = stdout.split('[+] TARGET: ')[1:]
	
	for fs in file_status:
		lines = fs.split('\n')
		fname = lines[0]
		failed_tests = []

		matches = re.finditer(r'\[\s+RUN\s+\] (.*)\n\[\s+FAILED\s+\]', '\n'.join(x for x in lines[1:]))
		for match in matches:
			failed_tests.append(match.group(1))

		if len(failed_tests) > 0:
			print '\tFile {}:\n'.format(os.path.basename(fname))
			for ft in failed_tests:
				print '\t\tError in {} --- Path: {}'.format(ft.lower(), fname)
			print '\n\n'
	
if __name__ == '__main__':
	Done = False
	toolpath = ''
	try:
		opts, args = getopt.getopt(sys.argv[1:], "t:f:d:")
		for opt, arg in opts:
			if opt == '-f':
				get_report_file(toolpath, arg)
				Done = True
			elif opt == '-d':
				get_report_folder(toolpath, arg)
				Done = True
			elif opt == '-t':
				toolpath = arg
	except getopt.GetoptError:
		Usage(sys.argv[0])

	if Done is False:
		Usage(sys.argv[0])
