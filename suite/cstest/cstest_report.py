#!/usr/bin/python

import re
import sys
import getopt
from subprocess import Popen, PIPE
from pprint import pprint as ppr
import os

_python3 = sys.version_info.major == 3


def Usage(s):
	print('Usage: {} -t <cstest_path> [-f <file_name.cs>] [-d <directory>]'.format(s))
	sys.exit(-1)

def decode_output(output):
	if _python3:
		return bytes.decode(output)
	return output

def print_tool_failure(filepath, returncode, stdout, stderr):
	print('\n[-] cstest failed for {} with exit code {}'.format(filepath, returncode))
	if stdout:
		print('[-] stdout:\n{}'.format(stdout))
	if stderr:
		print('[-] stderr:\n{}'.format(stderr))

def get_failed_tests(output):
	failed_tests = []
	summary_tests = []
	in_failed_summary = False
	for line in output.split('\n'):
		match = re.match(r'\[\s+FAILED\s+\]\s+(.*)', line)
		if match is None:
			continue
		name = match.group(1).strip()
		if re.match(r'\d+\s+test\(s\)', name):
			in_failed_summary = 'listed below' in name
			continue
		if in_failed_summary:
			summary_tests.append(name)
		else:
			failed_tests.append(name)

	return summary_tests if summary_tests else failed_tests

def normalize_line(line):
	return re.sub(r'\s+', '', line)

def get_test_name_from_file(filepath, code):
	try:
		with open(filepath, 'r') as f:
			lines = f.readlines()
	except OSError:
		return 'Unknown test'

	test_name = ''
	needle = normalize_line(code)
	for i, line in enumerate(lines):
		line = line.strip()
		if line.startswith('!# issue') or line.startswith('// !# issue'):
			test_name = line
		if needle and normalize_line(line).startswith(needle):
			return test_name if test_name else 'Line {}'.format(i + 1)

	return 'Unknown test'

def get_report_file(toolpath, filepath, getDetails, cmt_out):
	cmd = [toolpath, '-f', filepath]
	try:
		process = Popen(cmd, stdout=PIPE, stderr=PIPE)
	except OSError as e:
		print('\n[-] Failed to run {}: {}'.format(toolpath, e))
		return 0

	stdout, stderr = process.communicate()

#	stdout
	failed_tests = []
	stdout = decode_output(stdout)
	stderr = decode_output(stderr)

	if process.returncode != 0:
		print_tool_failure(filepath, process.returncode, stdout, stderr)
		return 0

	# print('---> stdout\n', stdout)
	# print('---> stderr\n', stderr)
	failed_tests = get_failed_tests(stdout + '\n' + stderr)
#	stderr
	counter = 0
	details = []
	for line in stderr.split('\n'):
		if '[  PASSED  ] 0 test(s).' in line:
			break
		elif 'LINE' in line:
			continue
		elif 'ERROR' in line and ' --- ' in line:
			parts = line.split(' --- ', 2)
			code = parts[1] if len(parts) > 1 else ''
			report = parts[2] if len(parts) > 2 else line
			if counter < len(failed_tests):
				test_name = failed_tests[counter]
			else:
				test_name = get_test_name_from_file(filepath, code)
			details.append((code, test_name, report))
			counter += 1
		else:
			continue
	print('\n[-] There are/is {} failed test(s)'.format(len(details)))
	if len(details) > 0 and getDetails:
		print('[-] Detailed report for {}:\n'.format(filepath))
		for c, f, d in details:
			print('\t[+] {}: {}\n\t\t{}\n'.format(f, c, d))
		print('\n')
		return 0
	elif len(details) > 0:
		for c, f, d in details:
			if len(f) > 0 and cmt_out is True:
				tmp_cmd = ['sed', '-E', '-i.bak', r's/({})(.*)/\/\/ \1\2/g'.format(c), filepath]
				sed_proc = Popen(tmp_cmd, stdout=PIPE, stderr=PIPE)
				sed_proc.communicate()
				tmp_cmd2 = ['rm', '-f', filepath + '.bak']
				rm_proc = Popen(tmp_cmd2, stdout=PIPE, stderr=PIPE)
				rm_proc.communicate()

		return 0
	return 1

def get_report_folder(toolpath, folderpath, details, cmt_out):
	result = 1
	for root, dirs, files in os.walk(folderpath):
		path = root.split(os.sep)
		for f in files:
			if f.split('.')[-1] == 'cs':
				print('[-] Target:', f,)
				result *= get_report_file(toolpath, os.sep.join(x for x in path) + os.sep + f, details, cmt_out)
	
	return result

def validate_tool(toolpath):
	if not toolpath:
		print('[-] Missing cstest path')
		return False
	if not os.path.isfile(toolpath):
		print('[-] cstest path does not exist: {}'.format(toolpath))
		return False
	if not os.access(toolpath, os.X_OK):
		print('[-] cstest path is not executable: {}'.format(toolpath))
		return False
	return True

if __name__ == '__main__':
	details = False
	toolpath = ''
	cmt_out = False
	files = []
	folders = []
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ct:f:d:D")
		for opt, arg in opts:
			if opt == '-f':
				files.append(arg)
			elif opt == '-d':
				folders.append(arg)
			elif opt == '-t':
				toolpath = arg
			elif opt == '-D':
				details = True
			elif opt == '-c':
				cmt_out = True

	except getopt.GetoptError:
		Usage(sys.argv[0])

	if not files and not folders:
		Usage(sys.argv[0])
	if not validate_tool(toolpath):
		sys.exit(1)

	result = 1
	for f in files:
		result *= get_report_file(toolpath, f, details, cmt_out)
	for d in folders:
		result *= get_report_folder(toolpath, d, details, cmt_out)

	sys.exit(result ^ 1)
