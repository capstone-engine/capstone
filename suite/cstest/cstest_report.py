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

def get_report_file(toolpath, filepath, getDetails, cmt_out):
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
			parts = line.split(' --- ')
			try:
				details.append((parts[1], failed_tests[counter], parts[2]))
			except IndexError:
				details.append(('', 'Unknown test', line.split(' --- ')[1]))
			counter += 1
		else:
			continue
	print '\n[-] There are/is {} failed test(s)'.format(len(details))
	if len(details) > 0 and getDetails:
		print '[-] Detailed report for {}:\n'.format(filepath)
		for c, f, d in details:
			print '\t[+] {}: {}\n\t\t{}\n'.format(f, c, d)
		print '\n'
		return 0
	elif len(details) > 0:
		for c, f, d in details:
			if len(f) > 0 and cmt_out is True:
				tmp_cmd = ['sed', '-E', '-i.bak', 's/({})(.*)/\/\/ \\1\\2/g'.format(c), filepath]
				sed_proc = Popen(tmp_cmd, stdout=PIPE, stderr=PIPE)
				sed_proc.communicate()
				tmp_cmd2 = ['rm', '-f', filepath + '.bak']
				rm_proc = Popen(tmp_cmd2, stdout=PIPE, stderr=PIPE)
				rm_proc.communicate()

		return 0;
	return 1

def get_report_folder(toolpath, folderpath, details, cmt_out):
	result = 1
	for root, dirs, files in os.walk(folderpath):
		path = root.split(os.sep)
		for f in files:
			if f.split('.')[-1] == 'cs':
				print '[-] Target:', f,
				result *= get_report_file(toolpath, os.sep.join(x for x in path) + os.sep + f, details, cmt_out)
	
	sys.exit(result ^ 1)

if __name__ == '__main__':
	Done = False
	details = False
	toolpath = ''
	cmt_out = False
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ct:f:d:D")
		for opt, arg in opts:
			if opt == '-f':
				result = get_report_file(toolpath, arg, details, cmt_out)
				if result == 0:
					sys.exit(1)
				Done = True
			elif opt == '-d':
				get_report_folder(toolpath, arg, details, cmt_out)
				Done = True
			elif opt == '-t':
				toolpath = arg
			elif opt == '-D':
				details = True
			elif opt == '-c':
				cmt_out = True

	except getopt.GetoptError:
		Usage(sys.argv[0])

	if Done is False:
		Usage(sys.argv[0])
