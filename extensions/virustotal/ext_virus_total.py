# -*- coding: utf-8 -*-
import time
import json
import urllib
import urllib2
import os
from datetime import datetime
from vito_config import *


# Scan folder searching queue files from syscheck in syscheck folder
def get_queue_files(): 
	
	list_files = []

	# Check and filter results, all queue files are called: "(agent_name) 192.0.0.0->syscheck"
	for file in os.listdir(syscheck_folder):
		endings = ["-_syscheck", "->syscheck"]
		if file[-10:] in endings or file == "syscheck":
			file = syscheck_folder+file
			list_files.append(file)
		
	return list_files

# Scan queue file, line by line 
def scan_queue_file(file_path, last_entry, countZ):	
	
	file = open( os.path.abspath( file_path ), 'r').readlines()
	
	if is_public_key:
		frecuency_key = 15

	count = 0
	update = False

	if countZ == 0:
		vt_sleep = False
	else:
		vt_sleep = True

	hostname = file_path.split('/')[-1][:-10]
	if len(hostname) < 1:
		hostname = "OSSEC Server"

	last_temp = last_entry[1]

	for line in reversed(file):

		try:
			line = line.split(':',5)
			md5sum = line[4]
			date_and_name = line[5].split('!')[1]
			# print "info this line:", md5sum, date_and_name
			# example output: "1427747294 /home/user/myFiles/3.file"

		except:
			#Wrong syscheck database format
			puke_local_error(hostname, 0, 0, 591)
			vt_sleep = False
			break

		#data already checked, some previous problems analazing this db
		if len(last_temp) > 0:
			if last_temp == date_and_name:
				last_temp = ""
			continue

		#checked already, leaving this agent syscheck file
		if last_entry[0] == date_and_name:
			# print "EXIT FOR THIS FILE----------------------@\n"
			break

		#Obtaining info
		file_time = datetime.fromtimestamp(  int(date_and_name.split(' ')[0])  ).strftime('%Y-%m-%d %H:%M:%S')
		file_name = date_and_name.split(' ',1)[1].strip()
		

		#Wrong md5sum, useless to send to vt
		if len(md5sum) != 32:
			#TODO create some log
			puke_local_error(hostname, file_name, file_time, 590)
			vt_sleep = False
			continue

		if vt_sleep is True :
			time.sleep(frecuency_key)

		if count == 0:
			new_last_entry = date_and_name
			update = True
		count += 1
		vt_sleep = True
		
		results_vt = retrieve_results_md5(md5sum, personal_API_Key)

		resp_code = results_vt.get("response_code")

		if resp_code == -1:
			#Something went wrong ... aborting scan
			puke_error_log(696)
			update = False
			break
			
		else:

			if resp_code == 0:
				#non data in vt
				puke_noD_log(hostname, file_name, file_time)

			elif resp_code == 1:
				#data in vtapi
				puke_log(hostname, file_name, file_time, results_vt)

		update_temp_db(hostname, date_and_name)

	# Syscheck DB done, cleaning temp data 
	# update_temp_db(hostname, "")
	if update is True:
		update_db(hostname, new_last_entry)

#create a log from vt results
def puke_log(hostname, file_name, file_time, log_json):

	plus = log_json.get("positives", -1)

	#necessary vars to read from log_json
	true = True
	false = False

	#File is being scanned in VT servers | /home/user/myFiles/6.file | Created date: 2015-03-30 22:28:14 | Permalink: https...
	if plus < 0:
		message = ( "File is being scanned in VT servers | " + file_name + 
			" | Created date: " + file_time + " | Permalink: " + log_json.get("permalink") )

	#Safe file, scan date:  2010-05-15 03:38:44 |/home/user/myFiles/6.file |Created date: 2015-03-30 22:28:14| Permalink: https... ]
	elif plus == 0:
		#Safe file
		message = ( "Code 100: Safe file, scan date: " + log_json.get("scan_date") + 
			" | " + file_name + 
			" | Created date: " + file_time + 
			" | Permalink: " + log_json.get("permalink") )

	#Suspicious file identified. Ratio detected: 32/45 (% message), 2010-05-15|/h/u/file |Created date: 2015-03-30| Results: Avira: TrojanV, Panda: TrojanZ ... | Permalink: https...
	else:
		pts = log_json.get("positives")
		tot = log_json.get("total")
		percent = '%.2f'%((pts/float(tot))*100)
		percent_msg = get_percent(percent)

		scans_msg = ""
		for i in log_json.get("scans"):
			if log_json.get("scans").get(i).get("result") is not None:
				# i 									= Antivirus Name
				# log_json.get("scans").get(i).get("result") 	= Malware/Virus name
				scans_msg += i + ": " + log_json.get("scans").get(i).get("result") + ", "
		scans_msg = scans_msg[:-2]

		message = ( percent_msg[1] + percent_msg[0] + " identified. Ratio detected: " + str(pts) +"/"+ str(tot) +
			" (" + str(percent) + "%" +
			"), scan date: " + log_json.get("scan_date") + 
			" | " + file_name + 
			" | Created date: " + file_time + 
			" | Results: " + scans_msg +
			" | Permalink: " + log_json.get("permalink") )

	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]  [Host " + hostname + "]\n"  )
	
# Translate the percent of dangerousness to human text message
# Switch case % for level of dangerousness
def get_percent(prcnt):

    prcnt = int(float(prcnt))
    if prcnt in range(0,10):
        return ": Malwarelicious file", "Alert 110"
    elif prcnt in range(10,30):
        return ": Dangerous file", "Alert 130"
    elif prcnt in range(30,60):
        return ": Very Dangerous file", "Alert 160"
    elif prcnt in range(60,100):
        return ": Really Dangerous file", "Alert 200"
    else:
        return ": Error with percent!!", "Alert 099"

#create a global error log, not internet connection or wrong VT API key
# [Time 2016.02.03 20:44:04] [Sender virustotal-devel]  [Message ERROR 696: Not connection with VirusTotal DB, please check your internet connection or VirusTotal API Key]
def puke_error_log(code, add_info = ""):

	message = ""


	if code == 001:
		message = "Code 001: virustotal-devel for wazuh has started"
	elif code == 002:
		message = "Code 002: New Syscheck DB found for agent: " + add_info
	elif code == 003:
		message = "Code 003: All Syscheck DBs scanned, next scan in " + str(add_info) + " seconds."
	elif code == 696:
		message = "ERROR 696: Not connection with VirusTotal DB, please check your internet connection or VirusTotal API Key"
	elif code == 697:
		message = "ERROR 697: Wrong API Key, please check your VirusTotal API Key"
	elif code == 698:
		message = "ERROR 698: Broken DB for virustotal-devel for wazuh, new DB created"
	elif code == 699:
		message = "ERROR 699: No DB for virustotal-devel for wazuh, new DB created"


	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]\n" )

#create a local error log
# [Time 2016.02.03 20:44:04] [Sender virustotal-devel]  [Message Error in local data]  [Host Hostname]
def puke_local_error(hostname, file_name, file_time, code = 0):

	message = "ERROR 000: Syscheck DB Error"
	if code == 590:
		message = "ERROR 590: Wrong MD5 hash for " + file_name + " | Created date: " + file_time 
	elif code == 591:
		message = "ERROR 591: Not valid DB Syscheck format for agent: " + hostname  
			 
	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]  [Host " + hostname + "]\n"  )

#create a no-data in VT log
# [Time 2016.02.03 20:44:04] [Sender virustotal-devel]  [Message No Data in VirusTotal, please upload this file manually]  [Host Hostname]
def puke_noD_log(hostname, file_name, file_time):
	message = ("Code 098: No Data in VirusTotal, please upload this file manually"
		" | " + file_name + 
		" | Created date: " + file_time	)

	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]  [Host " + hostname + "]\n"  )

#write a log in our log file "./log_vt
def write_anylog(log_string):
	
	with open(log_file, 'ab') as data_file:
		data_file.write(log_string)

#conver from epoch time to a human readable time
def epoch_converter(some_sting):
	#datetime.datetime.fromtimestamp(  int(info_list[3].split(' ')[0])  ).strftime('%Y-%m-%d %H:%M:%S')
	return datetime.fromtimestamp(  some_sting  ).strftime('%Y-%m-%d %H:%M:%S')

#get actual time in our format
def time_now():

	return datetime.now().strftime('%Y.%m.%d %H:%M:%S')

# Retrieve report VirusTotal
def retrieve_results_md5(MD5, myPersonalKey):

	# print "Scanning file in VT"
	try:
		
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource": MD5,"apikey": myPersonalKey}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json_data = json.loads(response.read())

		# print "File scanned", json_data
		return json_data

	except:
		# Not possible connection with VirusTotal Database
		# return False
		return {u'response_code': -1, u'more_info': u'error connection with VirusTotal DB, please check your internet connection or VirusTotal API Key'}

#extract previous last entry for this agent in our json db
# if there is not any data for this agent, is going to create in our db
def extract_last_entry(agent_path):
	agent = agent_path.split('/')[-1][:-10]
	if len(agent) < 1:
		agent = "OSSEC Server"

	error = False

	if not os.path.isfile(db_file):
		with open(db_file, 'w+'):
			puke_error_log(699)
			error = True
			

	with open(db_file, 'r') as data_file:  

		try:
			tree_data = json.load(data_file)
		except:
			#DB is broken: Creating new emptly DB
			tree_data = {u"agents": {} }
			if error is False: puke_error_log(698)

		agent_record = tree_data["agents"].get( agent )

		#If no data in DB for this agent: Creating from scratch
		if agent_record == None:
			tree_data["agents"][ agent ] = {}
			tree_data["agents"][ agent ]["last_entry"] = "None"
			tree_data["agents"][ agent ]["FTS"] = time_now()
			tree_data["agents"][ agent ]["Temp"] = ""
			last_entry_found = temp = ""
			puke_error_log(002, agent)
		
		else:
			last_entry_found = agent_record.get( "last_entry" )
			temp = agent_record.get( "Temp" )

		tree_data["agents"][ agent ]["LTS"] = time_now()


	with open(db_file, 'w') as f:
		f.write(json.dumps(tree_data, indent=4))

	return (last_entry_found, temp)

#Get our Local configuration ####OBSOLOTE###
def extract_vt_config():
	with open('local_data.json', 'r') as data_file:  
		tree_data = json.load(data_file)
		api_key = tree_data["local_conf_vt"]["API_Key"]
		if tree_data["local_conf_vt"]["public_KEY"] == "True":
			frec = 15
		else:
			frec = tree_data["local_conf_vt"]["frecuency"]
		return str(api_key), int(frec)

#Update last entry checked in queue file for an agent 
def update_db(agent, new_last_entry):

	with open(db_file, 'r') as f:
		tree_data = json.load(f)

	with open(db_file, 'w+') as f:
		tree_data["agents"][ agent ]["last_entry"] = new_last_entry
		tree_data["agents"][ agent ]["LTS"] = time_now()
		tree_data["agents"][ agent ]["Temp"] = ""
		f.write(json.dumps(tree_data, indent=4))
		f.close()

#Update temp data:
def update_temp_db(agent, temp_data):

	with open(db_file, 'r') as f:
		tree_data = json.load(f)

	with open(db_file, 'w+') as f:
		tree_data["agents"][ agent ]["Temp"] = temp_data
		tree_data["agents"][ agent ]["LTS"] = time_now()
		f.write(json.dumps(tree_data, indent=4))
		f.close()

# This function create a service/Daemon that will execute a det. task
def summon_daemon():

  	try:
		# Store the Fork PID
		pid = os.fork()

		
		if pid > 0:
			print 'PID: %d' % pid
			os._exit(0)

	except OSError, error:
		print 'Unable to fork. Error: %d (%s)' % (error.errno, error.strerror)
		os._exit(1)
	main_vt()

############################################################################
############################################################################
############################################################################
############################################################################
#
# MAIN PROGRAM HERE:
#
############################################################################
############################################################################
############################################################################
############################################################################

def main_vt():
	puke_error_log(001)
	while True:
		print "\nRound starts here:"
		countZ = 0

		if len(personal_API_Key) == 64:
			for queue_file in get_queue_files():
				print "SCANING FILE: ", queue_file
				# print "LAST ENTRY FOUND: ", extract_last_entry(queue_file)
				scan_queue_file(queue_file, extract_last_entry(queue_file), countZ)
				print "-----------File scanned successfully-------------\n"
				countZ += 1
		else:
			puke_error_log(697)

		print "Round finished, waiting for next scan round in " + str(sleep_time) + " seconds."
		print "#############################################################"
		puke_error_log(003, sleep_time)
		time.sleep(sleep_time)

if __name__ == "__main__":
	summon_daemon()
