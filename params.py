#!/usr/bin/env python3

import local_config as conf
import boto3
import datetime
import time
import json
import os

# START: Preparation > Globals ............................................... #
default_region = conf.ssm['default_region']
securetoken_start = None

# END: Preparation > Globals ................................................. #

# START: Functions ........................................................... #
def mainLoop(credentials):
	# Preparation ............................................................ /
	action_requested = None	

	while True:

		# Verify user has requested an action ................................ >
		if not action_requested:
			# Present options to user, get desired action
			action_requested = getInput('main_menu')

			if action_requested == 500:
				action_requested = None
				postOutput('generic_error')
				continue

		# Act on action request .............................................. >
		
		## Find Secret ##
		if 'f' in action_requested:
			# Input: Get secret's path
			s_input = getInput('find')

			if s_input == 500:
				postOutput('generic_error')
				s_input = None
				continue
			else:
				# Normalize query path
				path_norm = normalizePath(s_input)
				# Query for the secret given the path
				find_ret = findSecret(credentials,path_norm)
			
				if find_ret == 500:
					postOutput('generic_error')
					continue
				else:
					# Print Results
					printResults('find',find_ret)
					# Check if the user wants to continue working
					s_input = getInput('retry')

					if 'c' in s_input:
						action_requested = None
						s_input = None
						continue
					else:
						exit()

		## Add Secret ##
		elif 'a' in action_requested:
			# Input: get secret path and value
			s_input = getInput('add')

			if s_input == 500:
				postOutput('generic_error')
				s_input = None
				continue
			else:
				# Normalize new path
				s_input['path'] = normalizePath(s_input['path'])
				# Check for existing secret
				find_existing = findSecret(credentials,s_input['path'])
				if find_existing == 500:
					postOutput('generic_error')
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
					add_ret = addSecret(credentials,s_input)

					if add_ret == 500:
						postOutput('generic_error')
						continue
					else:
						# Print Results
						printResults('add_success')
						# Check if the user wants to continue working
						s_input = getInput('retry')

						if 'c' in s_input:
							action_requested = None
							s_input = None
							continue
						else:
							exit()

		## List Hierarchy ##
		elif 'l' in action_requested:
			# if :
			# 	pass

			# Normalize query path
			path_norm = normalizePath("/")
			list_ret = getHierarchy(credentials,path_norm)

			if list_ret == 500:
				print('\r\nThat didn\'t work. Try again\r\n')
				continue
			else:
				# Print Results
				printResults('list',list_ret)
				# Check if the user wants to continue working
				s_input = getInput('retry')

				if 'c' in s_input:
					action_requested = None
					s_input = None
					continue
				else:
					exit()

def getSecureCredentials():
	# Preparation ............................................................ /
	user_profile = conf.local['ssm_aws_profile']

	# Start regular session using stored profile
	try:
		session = boto3.session.Session(profile_name=user_profile)
	except Exception as e:
		return 500

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
		mfa_par1 = conf.local['mfa_suffix']
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
	return response['Credentials']

def normalizePath(s_in):
	# Lower case
	s_in = s_in.lower()

	# If user HAS included basepath in query
	if conf.ssm['params_basepath'] in s_in:
		# Check if it has a root slash
		if s_in[:1] != '/':
			s_in = '/'+s_in

		# Prepare return string
		s_out = s_in

	# If user has NOT included basepath in query
	else:
		if s_in[:1] == '/':
			s_in = s_in[1:]

		# Prepare return string
		s_out = '/{0}/{1}'.format(conf.ssm['params_basepath'],s_in)

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
		    aws_session_token=credentials['SessionToken'],
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
			return_object = {}
			return_object['list'] = True
			return_object['Parameters'] = response['Parameters']
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
		return response

	
def printResults(case,payload=None):
	print('')
	if case == 'generic_error':
		print('Something went wrong. Please try again')
	
	elif case == 'auth_error':
		print('I can\'t authenticate you. Please try again')
	
	elif case == 'find':
		print('------ Results ---------')
		print('')
		if payload['list']:
			for parameter in payload['Parameters']:
				line = str(parameter['Name']).replace('/secrets/', '')+' : '+parameter['Value']
				print(line)
		else:
			line = str(payload['Parameter']['Name']).replace('/secrets/', '')+' : '+payload['Parameter']['Value']
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


	else:
		print(case)


	return 200

def getInput(case):
	print('')
	if case == 'code':
		try:
			s_input = input('secret code? : ')
		except Exception as e:
			return 500
		else:
			return s_input

	if case == 'main_menu':
		try:
			print('------')
			print('')
			print('(F) Find a secret')
			print('(A) Add a secret')
			print('(L) List secrets hierarchy')
			print('(E) Exit')
			print('')
			action_wanted = input('what do you want to do? (enter letter) : ')
		except Exception as e:
			return 500
		else:
			return action_wanted.lower()

	if case == 'find':
		# Ask for input
		try:
			s_input = input('what secret(s) are you looking for? : ')
		except Exception as e:
			return 500
		else:
			return s_input

	if case == 'add':
		try:
			print('------ Add a New Secret ')
			print('')
			print('Instructions:')
			print('Use slashes to separate the path to your new secret. e.g., \'amazon/username\' or \'amazon/password\' ')
			print('')
			new_path = input('1. What is your new secret\'s path? : ')
		except Exception as e:
			return 500

		try:
			print('')
			new_value = input('2. What is the value of your new secret? : ')
		except Exception as e:
			return 500

		return_object = {}
		return_object['path'] = new_path
		return_object['value'] = new_value

		return return_object

	if case == 'retry':
		try:
			s_input = input('press (C) to Continue or (E) to Exit : ')
		except Exception as e:
			return 500
		else:
			return s_input.lower()

	if case == 'yes_no':
		try:
			s_input = input('(y) yes, or (n) no : ')
		except Exception as e:
			return 500
		else:
			return s_input.lower()

# END: Functions ............................................................. #

# START: Main ................................................................ #
if __name__== "__main__":
	
	# Try to get secure session credentials .................................. >
	try:
		sec_credentials = getSecureCredentials()
	except Exception as e:
		exit()
	else:
		if sec_credentials == 500:
			printResults('auth_error')
			exit()

	mainLoop(sec_credentials)




	# securetoken_start = str(sec_credentials['Expiration'])
	# print(securetoken_start)
	# print(json.dumps(sec_credentials,indent=4, sort_keys=True, default=str))

	# while True:
	# 	if datetime.datetime.now(datetime.timezone.utc) > sec_credentials['Expiration']:
	# 		print('expired')
	# 		exit()
	# 	else:
	# 		print('not expired: ',datetime.datetime.now(datetime.timezone.utc))
	# 		time.sleep(30)
