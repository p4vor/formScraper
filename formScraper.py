#!/usr/bin/env python 

'''
	takes a singl url or list of urls and payloads
	scraps urls and params from forms
	injects payloads into the params
	returns a JSON obj of a list of dictionaries, each dict contains the data of one form - the hostname, url, method, original_inputs(key-value pairs) and injected_inputs(inputes with payloads)
'''

__all__ = ['get_form_data', 'inject_payloads']

import requests
import argparse
import re
import urllib
from termcolor import colored
import json


def get_form_inputs(html_form):
	inputs = re.findall(r'(<input.*?>|<textarea.*?>|<select.*?>)', html_form)
	input_data = {}
	for input in inputs:
		if not re.search(r'type=\'?\"?submit', input):		# Skip input if type=submit
			input_name = re.findall(r'(?<=name=).*?(?=\s|\/>|>)', input)[0].strip("\"'")
			input_value_matches = re.findall(r'(?<=value=).*?(?=\s|\/>|>)', input)
			input_value = input_value_matches[0].strip("\"'") if len(input_value_matches) else ""
			input_data.update({input_name: input_value})

	return input_data


def get_form_method(form, inputs):
	methods = ['put', 'patch', 'delete']
	# Look for method in input values
	for key, val in inputs.items():
		# Remove the "method" input if exists
		if val.lower() in methods:
			inputs.pop(key)						
			return val.upper()

	# Look for method in form method attr
	method_matches = re.findall(r'(?<=method=).*?(?=\s|\/>|>)', form)
	return method_matches[0].strip("\"'").upper() if len(method_matches) else 'GET'


def convert_list_of_str_to_dict(list_var, separator):
	dict_var = {}
	if list_var:
		for item_str in list_var:
			name, value = item_str.split(separator)
			dict_var.update({name.strip(): value.strip()})

	return dict_var
	

def convert_headers_list_to_dict(headers_list):
	return convert_list_of_str_to_dict(headers_list, ':')


def convert_cookies_list_to_dict(cookies_list):
	return convert_list_of_str_to_dict(cookies_list, '=')


def inject(form_data, original_inputs, payloads, POST_data_str, curr_input_name=None):
	'''
		Injects all payloads into one form's inputs

		form_data:  the data of the target form
		original_inputs:  A dict of the original inputs of the target form
		payloads:  A list of payloads
		POST_data_str: 	Determines if the POST data is returned as a str
		curr_input_name:  The name of the input to be injected -
		 				  If present only this input will be injected with payloads
	'''
	for payload in payloads:
		if POST_data_str:			# if POST data should be a string
			POST_data_list = []
			for input_name, input_val in original_inputs:
				is_csrf_input = re.search(r'csrf', input_name)
				
				# Break if curr_input_name and input_name are 'csrf' input
				if is_csrf_input and curr_input_name == input_name:
					break

				if is_csrf_input or (curr_input_name and curr_input_name != input_name):
					POST_data_list.append(f"{input_name}={input_val}")
				else:
					POST_data_list.append(f"{input_name}={payload.strip()}")

			if POST_data_list:
				form_data['injected_inputs'].append("&".join(POST_data_list))
		else:						# if POST data should be a dict
			POST_data_dict = {}
			for input_name, input_val in original_inputs:
				is_csrf_input = re.search(r'csrf', input_name)

				# Break if curr_input_name and input_name are 'csrf' input
				if is_csrf_input and curr_input_name == input_name:
					POST_data_dict = {}
					break

				if is_csrf_input or (curr_input_name and curr_input_name != input_name):
					POST_data_dict.update({input_name: input_val})
				else:
					POST_data_dict.update({input_name: payload.strip()})

			if POST_data_dict:
				form_data['injected_inputs'].append(POST_data_dict)


def get_forms_data(url, json_data=False, headers=None, cookies=None):
	'''
		Scraps all forms from a page

		url:  Duh
		json_data:  Determines if the forms_data list is returned as json
		headers:  A dictionary or list of headers
		cookies:  A dictionary or list of cookies
	'''
	headers = headers if type(headers) == type({}) else convert_headers_list_to_dict(headers)
	cookies = cookies if type(cookies) == type({}) else convert_cookies_list_to_dict(cookies)
	r = requests.get(url, headers=headers, cookies=cookies)
	html_forms = re.findall(r'<form.*?<\/form>', r.text, flags=re.S)
	forms_data = []
	for form in html_forms:
		action = re.findall(r'(?<=action=).*?(?=\s|\/>|>)', form)[0].strip("\"'")
		parsed_url = urllib.parse.urlparse(url)
		scheme = urllib.parse.urlparse(url).scheme
		hostname = urllib.parse.urlparse(url).netloc
		inputs = get_form_inputs(form)
		forms_data.append({
			'hostname': hostname,
			'url': action if re.search(hostname, action) else urllib.parse.urljoin(scheme+'://'+hostname, action),
			'method': get_form_method(form, inputs),
			'original_inputs': inputs
		})

	if not json_data:
		return forms_data
	else:
		return json.dumps(forms_data)


def inject_payloads(url, payloads_param, json_data=False, headers=None, cookies=None, POST_data_str=False, one_input=False):
	'''
		Injects all payloads into all scraped forms' inputs

		url:  Duh
		payloads_param:  A list of payloads or a path of a file with payloads
		json_data:  Determines if the forms_data list is returned as json
		headers:  A dictionary or list of headers
		cookies:  A dictionary or list of cookies
		POST_data_str: 	Determines if the POST data is returned as a str
		one_input:  To inject each payload into one input at a time
	'''
	payloads = payloads_param if type(payloads_param) == type([]) else open(payloads_param, 'r').readlines()
	forms_data = get_forms_data(url, headers=headers, cookies=cookies)
	for form_data in forms_data:
		form_data.update({'injected_inputs': []})
		original_inputs = form_data['original_inputs'].items()
		if one_input:
			for input_name, input_val in original_inputs:
				inject(form_data, original_inputs, payloads, POST_data_str, curr_input_name=input_name)
		else:
			inject(form_data, original_inputs, payloads, POST_data_str)

	if not json_data:
		return forms_data
	else:
		return json.dumps(forms_data)



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="A script to scrap forms and inject payloads")
	parser.add_argument("-u", dest="url", help="Target url")
	parser.add_argument("-f", dest="urls_file", help="Path to a list of URLs")
	parser.add_argument("-p", dest="payloads_file", help="Path to a list of payloads. If not specified, discovered forms data will be returned")
	parser.add_argument("-H", dest="headers", help="Headers str. Could be used multiple times, e.g. \"User-Agent:test/app\"", action='append')
	parser.add_argument("-c", dest="cookies", help="Cookies str. Could be used multiple times, e.g. \"foo=bar\"", action='append')
	parser.add_argument("-j", "--json", help="Return the data in json format", action="store_true")
	parser.add_argument("--one-input", help="Inject one input at a time", action="store_true")
	options = parser.parse_args()

	# Check options -u and -f. One of them is required
	if not options.url and not options.urls_file:
		print(colored("[-] Missing option -u or -f. See help below.\n", "red"))
		parser.print_help()
		exit()

	if options.url and options.urls_file:
		print(colored("[-] U should specify only one of the options -u or -f. See help below.\n", "red"))
		parser.print_help()
		exit()

	if options.url:
		if options.payloads_file:
			forms_data = inject_payloads(options.url, options.payloads_file, json_data=options.json, headers=options.headers, cookies=options.cookies, one_input=options.one_input)
		else:
			forms_data = get_forms_data(options.url, json_data=options.json, headers=options.headers, cookies=options.cookies)
		
		print(forms_data)

	elif options.urls_file:
		forms_data_list = []
		if options.payloads_file:
			for url in open(options.urls_file, 'r').readlines():
				forms_data_list += inject_payloads(url.strip(), options.payloads_file, headers=options.headers, cookies=options.cookies, one_input=options.one_input)
		else:
			for url in open(options.urls_file, 'r').readlines():
				forms_data_list += get_forms_data(url.strip(), headers=options.headers, cookies=options.cookies)

		if not options.json:
			print(forms_data_list)
		else:
			print(json.dumps(forms_data_list))


'''
ex:  output from inject_payloads() function when "POST_data_str" is False
[
	{
		'hostname': 'localhost', 
		'url': 'http://google.com/users/1', 
		'method': 'DELETE', 
		'original_inputs': {'name': '', 'pet': '', 'bio': '', 'gender': '', 'csrf': 'aslkdjfklasjdf'
		}, 
		'injected_inputs': [
			{'name': '\'"xss>', 'pet': '\'"xss>', 'bio': '\'"xss>', 'gender': '\'"xss>', 'csrf': 'aslkdjfklasjdf'}, 
			{'name': 'xss"', 'pet': 'xss"', 'bio': 'xss"', 'gender': 'xss"', 'csrf': 'aslkdjfklasjdf'}, 
			{'name': 'alert', 'pet': 'alert', 'bio': 'alert', 'gender': 'alert', 'csrf': 'aslkdjfklasjdf'}
		]
	}, 
	{
		'hostname': 'localhost', 
		'url': 'http://localhost/comments', 
		'method': 'GET', 
		'original_inputs': {'_csrf': 'asdfasdfasdfasdfadsf', 'comment': '', 'author': ''}, 
		'injected_inputs': [
			{'_csrf': 'asdfasdfasdfasdfadsf', 'comment': '\'"xss>', 'author': '\'"xss>'}, 
			{'_csrf': 'asdfasdfasdfasdfadsf', 'comment': 'xss"', 'author': 'xss"'}, 
			{'_csrf': 'asdfasdfasdfasdfadsf', 'comment': 'alert', 'author': 'alert'}
		]
	}
]
'''


#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
#								NOTES
# should we get the value of the selected option if the input is "select"?