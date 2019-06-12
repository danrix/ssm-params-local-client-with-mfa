#!/usr/bin/env python3

import local_config as conf
import boto3
import datetime
import os
import colorama

# START: Preparation > Globals ............................................... #
default_region = conf.ssm['default_region']
colorama.init()

# END: Preparation > Globals ................................................. #

# START: Functions ........................................................... #
def mainLoop(credentials):
	# Preparation ............................................................ /
	action_requested = None	

	while True:
		# Check that the session is still valid .............................. >
		session_valid = checkSession(credentials['Expiration'])

		if session_valid == 500:
			printResults('')
			exit()

		# Verify user has requested an action ................................ >
		if not action_requested:
			# Present options to user, get desired action
			action_requested = getInput('main_menu')

			if action_requested == 500:
				action_requested = None
				printResults('generic_error')
				continue

		# Act on action request .............................................. >
		
		## Find Secret ##
		if 'f' in action_requested:
			# Input: Get secret's path
			s_input = getInput('find')

			if s_input == 500:
				printResults('generic_error')
				s_input = None
				continue
			else:
				# Normalize query path
				path_norm = normalizePath(s_input,credentials['list_path'])

				if path_norm == 501:
					printResults('invalid_empty')

					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

				if path_norm == 502:
					printResults('invalid_slash')
					
					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

				# Query for the secret given the path
				find_ret = findSecret(credentials,path_norm)

				if find_ret == 500:
					printResults('generic_error')
					continue
				elif find_ret == 404:
					printResults('cant_find')
					
					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

				else:
					# Print Results
					printResults('find',find_ret)
					
					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

		## Add Secret ##
		elif 'a' in action_requested:
			# Input: get secret path and value
			s_input = getInput('add')

			if s_input == 500:
				printResults('generic_error')
				s_input = None
				continue
			else:
				# Normalize new path
				n_path = normalizePath(s_input['path'],credentials['list_path'])

				if n_path == 501:
					printResults('invalid_empty')
					
					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

				elif n_path == 502:
					printResults('invalid_slash')
					
					# Check if the user wants to continue or exit
					action_requested = None if 'c' in getInput('retry') else exit()

				# Check for existing secret
				find_existing = findSecret(credentials,n_path)

				if find_existing == 500:
					printResults('generic_error')
					continue
				elif find_existing == 404:
					add_yes = True
				else:
					printResults('overwrite')
					s_confirm = getInput('yes_no')

					if 'y' in s_confirm:
						add_yes = True
					elif 'n' in s_confirm:
						add_yes = False

				if add_yes:
					# Try to add new secret
					s_input['path'] = n_path
					add_ret = addSecret(credentials,s_input)

					if add_ret == 500:
						printResults('generic_error')
						continue
					else:
						# Print Results
						printResults('add_success')
						
						# Check if the user wants to continue or exit
						action_requested = None if 'c' in getInput('retry') else exit()

		## List Hierarchy ##
		elif 'l' in action_requested:
			# if :
			# 	pass

			# Normalize query path
			path_norm = normalizePath(credentials['list_path'],credentials['list_path'])

			list_ret = getHierarchy(credentials,path_norm)
			if list_ret == 500:
				printResults('generic_error')
				continue
			else:
				# Print Results
				printResults('list',list_ret)
				
				# Check if the user wants to continue or exit
				action_requested = None if 'c' in getInput('retry') else exit()

		elif 'e' in action_requested:
			print(colorama.ansi.clear_screen(),end='')
			os.system('clear')
			exit()
		else:
			# Print Results
			printResults('wrong_choice')
			
			# Check if the user wants to continue or exit
			action_requested = None if 'c' in getInput('retry') else exit()


def getSecureCredentials():
	# Preparation ............................................................ /
	user_profile = conf.local['ssm_aws_profile']

	# 1. Start initial session using stored profile
	try:
		session = boto3.session.Session(profile_name=user_profile)
	except Exception as e:
		return 500
	else:
		# Prepare credentials for ssm client
		initial_creds = session.get_credentials()
		ssm_init_creds = {}
		ssm_init_creds['AccessKeyId'] = initial_creds.access_key
		ssm_init_creds['SecretAccessKey'] = initial_creds.secret_key

	# 2. Get user initials
	s_input = getInput('initials')

	# 3. Query ssm for user's params
	try:
		find_ret = findSecret(ssm_init_creds,str(conf.ssm['router_base_path']+s_input))
	except Exception as e:
		return 500
	else:
		if (find_ret == 404) or (find_ret == 500):
			return 500

	# 4. Extract user details from query return
	user = {}
	user['initials'] = s_input
	for param in find_ret['Parameters']:
		if 'aws_access_key_id' in param['Name']:
			user['AccessKeyId'] = param['Value']
			continue
		elif 'aws_secret_access_key' in param['Name']:
			user['SecretAccessKey'] = param['Value']
			continue
		elif 'list_path' in param['Name']:
			user['list_path'] = param['Value']
			continue

	# 5. Start user session
	try:
		session = boto3.session.Session(
			aws_access_key_id=user['AccessKeyId'], 
			aws_secret_access_key=user['SecretAccessKey'], 
			aws_session_token=None,  
			profile_name=None
			)
	except Exception as e:
		return 500
		
	## === ##

	# Initialize STS client
	try:
		client = session.client(
			service_name='sts',
			region_name=default_region
		)
	except Exception as e:
		return 500

	# Get MFA serial number
	try:
		mfa_par0 = conf.ssm['account_number']
		mfa_par1 = conf.local['mfa_suffix']+user['initials']
		mfa_serial = 'arn:aws:iam::{0}:mfa/{1}'.format(mfa_par0,mfa_par1)
	except Exception as e:
		return 500

	# Get secret code
	s_code = getInput('code')

	if s_code == 500:
		return 500

	# Get temporary session token
	try:
		response = client.get_session_token(
			DurationSeconds=900,
			SerialNumber=mfa_serial,
			TokenCode=s_code
		)
	except Exception as e:
		return 501

	# Return secure credentials .............................................. >
	return_object = {}
	return_object.update(response['Credentials'])
	return_object['list_path'] = user['list_path']
	return return_object

def normalizePath(s_in,base_path):
	# Lower case
	s_in = s_in.lower()

	# Split query string into path
	q_path = s_in.strip('/').split('/')

	# Split base path
	b_path = base_path.strip('/').split('/')

	# Remove parts of base path if they exist in query path
	for b_node in b_path:
		if b_node in q_path:
			q_path.remove(b_node)

	# Join the base and the query paths
	b_path.extend(q_path)
	f_path = "/".join(b_path)

	f_path = '/'+f_path

	return f_path

	# Return normalized query string ......................................... >
	return s_out

def getSsmClient(credentials):
	# Prepare client to SSM service .......................................... /
	try:
		client = boto3.client(
			'ssm',
			region_name=default_region,
			aws_access_key_id=credentials['AccessKeyId'],
			aws_secret_access_key=credentials['SecretAccessKey'],
			aws_session_token=credentials['SessionToken'] if 'SessionToken' in credentials else None
		)

	except Exception as e:
		return 500
	else:
		return client

def findSecret(credentials,s_in):
	# Prepare client to SSM service .......................................... /
	try:
		client = getSsmClient(credentials)
	except Exception as e:
		return 500

	# Find param(s) using query string ....................................... >
	# 1. Assume s_in is path only
	try:
		response = client.get_parameters_by_path(
			Path=s_in,
			Recursive=True,
			WithDecryption=True
		)
	except Exception as e:
		return 500
	else:
		if response['Parameters']:
			# Prepare a list to hold results if more than one run is needed
			whole_response = {}

			if 'list_path' in credentials:
				for x in range(len(response['Parameters'])):
					# Trim base path from parameter name for better results display
					response['Parameters'][x]['Name'] =  response['Parameters'][x]['Name'].replace(credentials['list_path'],'')
			# Add these corrected parameters to hold list
			whole_response['Parameters'] = response['Parameters']

			# Check if more than one run is needed
			if 'NextToken' in response:
				while 'NextToken' in response:
					# Try a next run
					try:
						response = client.get_parameters_by_path(
							Path=s_in,
							Recursive=True,
							WithDecryption=True,
							NextToken=response['NextToken']
						)
					except Exception as e:
						return 500
					else:
						# Correct parameters and add to hold list
						if response['Parameters']:
							if 'list_path' in credentials:
								for x in range(len(response['Parameters'])):
									# Trim base path from parameter name for better results display
									response['Parameters'][x]['Name'] =  response['Parameters'][x]['Name'].replace(credentials['list_path'],'')

							whole_response['Parameters'].extend(response['Parameters'])
					
			return_object = {}
			return_object['list'] = True
			# Return holding list
			return_object['Parameters'] = whole_response['Parameters']
			return return_object

	# 2. Assume secret name is included in path
	try:
		response = client.get_parameter(
			Name=s_in,
			WithDecryption=True
		)
	except Exception as e:
		return 404
	else:
		if response['Parameter']:
			if 'list_path' in credentials:
				# Strip the path from the result
				response['Parameter']['Name'] = response['Parameter']['Name'].replace(credentials['list_path'],'')

			return_object = {}
			return_object['list'] = False
			return_object['Parameter'] = response['Parameter']
			return return_object

def addSecret(credentials,s_in):
	# Prepare client to SSM service .......................................... /
	try:
		client = getSsmClient(credentials)
	except Exception as e:
		return 500

	# Add a secret
	try:
		response = client.put_parameter(
			Name=s_in['path'],
			Value=s_in['value'],
			Type='SecureString',
			Overwrite=True,
			Tier='Standard'
		)
	except Exception as e:
		return 500
	else:
		return 200

def getHierarchy(credentials,s_path):
	# Prepare client to SSM service .......................................... /
	try:
		client = getSsmClient(credentials)
	except Exception as e:
		return 500

	# Use Secure session to query Parameter Store
	try:
		response = client.get_parameters_by_path(
			Path=s_path,
			Recursive=True,
			WithDecryption=False
		)
	except Exception as e:
		return 500
	else:
		# return response

		if response['Parameters']:
			# Prepare a list to hold results if more than one run is needed
			whole_response = {}

			# Add these parameters to hold list
			whole_response['Parameters'] = response['Parameters']

			# # Check if more than one run is needed
			if 'NextToken' in response:
				while 'NextToken' in response:
					# Try a next run
					try:
						response = client.get_parameters_by_path(
							Path=s_path,
							Recursive=True,
							WithDecryption=False,
							NextToken=response['NextToken']
						)
					except Exception as e:
						return 500
					else:
						# Add parameters to hold list
						if response['Parameters']:
							whole_response['Parameters'].extend(response['Parameters'])
					
			return_object = {}
			# Return holding list
			return_object['Parameters'] = whole_response['Parameters']
			return return_object		

def checkSession(credentials_expiration):
	# Check that the secure session has not expired
	while True:
		# If it has, exit program
		if datetime.datetime.now(datetime.timezone.utc) > credentials_expiration:
			return 500
		else:
			return 200

# START: Functions | Input/Output .................... #	
def printResults(case,payload=None):
	print('')
	if case == 'generic_error':
		print('Something went wrong. Please try again')
	
	elif case == 'auth_error':
		print('Authentication failed. Please try again')
	
	elif case == 'find':
		print('------ Results ---------')
		print('')
		if payload['list']:
			for parameter in payload['Parameters']:
				line = str(parameter['Name']).replace('/secrets/', '')+' : \033[33;1m'+parameter['Value']+'\033[0m'
				print(line)
		else:
			line = str(payload['Parameter']['Name']).replace('/secrets/', '')+' : \033[33;1m'+payload['Parameter']['Value']+'\033[0m'
			print(line)
			line = '\nVersion: {0}'.format(payload['Parameter']['Version'])
			print(line)
			line = 'Last modified: {0}'.format(str(payload['Parameter']['LastModifiedDate']))
			print(line)

		print('')
		print('------------------------')

	elif case == 'overwrite':
		print('That secret already exists. Do you want to update it?')

	elif case == 'add_success':
		print('I recorded your new secret. To verify, press (C) to continue, and then (F) to see the secret\'s value.')

	elif case == 'list':
		print('------ Secrets Hierarchy')
		# print('')
		levels = {}

		for k in range(0,16):
			levels[k] = None

		# iterate over the list of secrets returned
		for secret in payload['Parameters']:
			# Split secret path in levels, remove redundant '/secrets/' level
			secret_path = str(secret['Name']).replace('/secrets/', '').split('/')
			
			level_counter = 0
			# iterate over every level in path
			for level in secret_path:
				# If this is a new level
				if levels[level_counter] != level:
					# Register this level name in the dict level slot
					levels[level_counter] = level
					# Clear all following level slots in dict
					for x in range(level_counter+1,20):
						levels[x] = ''
					# Print level name
					if level_counter == 0:
						print('\r\n- {0}'.format(level))
					else:
						spaces = level_counter*3
						print('{1}{0}'.format(level,' '*spaces))

				level_counter += 1

		print('')
		print('------------------------')

	elif case == 'wrong_choice':
		print('That is not a valid option.')

	elif case == 'cant_find':
		print('No results for that search.')

	elif case == 'invalid_empty':
		print('You cannot use an empty path. Use slashes to separate the path to your secret. e.g., \'amazon/username\' or \'amazon/password\' ')

	elif case == 'invalid_slash':
		print('You cannot use a slash as your path, but you can use slashes to separate the path to your secret. e.g., \'amazon/username\' or \'amazon/password\' ')

	else:
		print(case)


	return 200

def getInput(case):
	# Preparation ............................................................ /
	question_mark = '\033[32;1m ? \033[0m '
	start_input_blue = '\033[36;1m'
	print('')
	if case == 'initials':
		try:
			print(question_mark+'what are your initials? : '+start_input_blue, end='')
			s_input = input()
		except Exception as e:
			return_object = 500
		else:
			return_object = s_input

	if case == 'code':
		try:
			print(question_mark+'secret code? : '+start_input_blue, end='')
			s_input = input()
		except Exception as e:
			return_object = 500
		else:
			return_object = s_input

	if case == 'main_menu':
		try:
			print('------')
			print('')
			print('(F) Find a secret')
			print('(A) Add a secret')
			print('(L) List secrets hierarchy')
			print('(E) Exit')
			print('')
			print(question_mark+'what do you want to do? (enter letter) : '+start_input_blue, end='')
			action_wanted = input()
		except Exception as e:
			return_object = 500
		else:
			return_object = action_wanted.lower()

	if case == 'find':
		# Ask for input
		try:
			print(question_mark+'what secret(s) are you looking for? : '+start_input_blue, end='')
			s_input = input()
		except Exception as e:
			return_object = 500
		else:
			return_object = s_input

	if case == 'add':
		try:
			print('------ Add a New Secret ')
			print('')
			print('\033[35mInstructions:')
			print('Use slashes to separate the path to your new secret. e.g., \'amazon/username\' or \'amazon/password\' \033[0m')
			print('')
			print(question_mark+'1. What is your new secret\'s path? : '+start_input_blue,end='')
			new_path = input()
		except Exception as e:
			return_object = 500

		try:
			print('')
			print(question_mark+'2. What is the value of your new secret? : '+start_input_blue,end='')
			new_value = input()
		except Exception as e:
			return_object = 500

		return_object = {}
		return_object['path'] = new_path
		return_object['value'] = new_value

		# return return_object

	if case == 'retry':
		try:
			print(question_mark+'press (C) to Continue or (E) to Exit : '+start_input_blue,end='')
			s_input = input()
		except Exception as e:
			return_object = 500
		else:
			print(colorama.ansi.clear_screen(),end='')
			os.system('clear')
			return_object = s_input.lower()

	if case == 'yes_no':
		try:
			print(question_mark+'Yes, or no (Y/n) : '+start_input_blue,end='')
			s_input = input()
		except Exception as e:
			return_object = 500
		else:
			return_object = s_input.lower()

	print('\033[0m', end='')
	return return_object

# END: Functions ............................................................. #

# START: Main ................................................................ #
if __name__== "__main__":
	
	# Try to get secure session credentials .................................. >
	try:
		sec_credentials = getSecureCredentials()
	except Exception as e:
		exit()
	else:
		if (sec_credentials == 500) or (sec_credentials == 501):
			printResults('auth_error')
			print('')
			exit()

	mainLoop(sec_credentials)
