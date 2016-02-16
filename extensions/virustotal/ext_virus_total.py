import time
# import simplejson as json
import json
import urllib
import urllib2
import os
from datetime import datetime
from vito_config import *


# Scan folder searching queue files from syscheck in syscheck folder
def get_queue_files(): 
	
	list_files = []

	# Check and filter results, all queue files are called: "(agent_name) 192.0.0.0-_syscheck"
	for file in os.listdir(syscheck_folder):
		if file[-10:] == "-_syscheck":
			file = syscheck_folder+file
			list_files.append(file)

	return list_files

# Scan queue file, line by line 
def scan_queue_file(file_path, last_entry, countZ):
	#examples, final version should be parametres: file_path, last_entry	

	file = open(file_path, 'r').readlines()

	# #get (vt API key, vt restrintions)
	# vt_config = extract_vt_config()
	
	if is_public_key:
		frecuency_key = 15

	count = 0
	update = False
	for line in reversed(file):
		line = line.split(':',5)		
		md5sum = line[4]
		date_and_name = line[5].split('!')[1]
		# print "info this line:", md5sum, date_and_name
		# example output: "1427747294 /home/user/myFiles/3.file"

		#checked already, leaving this agent syscheck file
		if last_entry == date_and_name:
			# print "EXIT FOR THIS FILE----------------------@\n"
			break

		if (countZ == 0 and count ==0) is False :
			time.sleep(frecuency_key)

		if count == 0:
			new_last_entry = date_and_name
			update = True
		count += 1
		
		results_vt = retrieve_results_md5(md5sum, personal_API_Key)

		resp_code = results_vt.get("response_code")

		if resp_code == -1:
			#Something went wrong ... aborting scan
			puke_error_log(696)
			update = False
			break
			
		else:
			#Obtaining info
			file_time = datetime.fromtimestamp(  int(date_and_name.split(' ')[0])  ).strftime('%Y-%m-%d %H:%M:%S')
			file_name = file = date_and_name.split(' ')[1].strip()
			hostname = file_path.split('/')[-1][:-10]
			
			if resp_code == 0:
				#non data in vt
				puke_noD_log(hostname, file_name, file_time)

			elif resp_code == 1:
				#data in vt
				puke_log(hostname, file_name, file_time, results_vt)

	
	#if true: update_db(file_path, new_last_entry)
	if update is True:
		update_db(file_path, new_last_entry)

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
		message = ( "Safe file, scan date: " + log_json.get("scan_date") + 
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

		message = ( "Suspicious file identified. Ratio detected: " + str(pts) +"/"+ str(tot) +
			" (" + str(percent) + "%" + percent_msg +
			"), scan date: " + log_json.get("scan_date") + 
			" | " + file_name + 
			" | Created date: " + file_time + 
			" | Results: " + scans_msg +
			" | Permalink: " + log_json.get("permalink") )

	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]  [Host " + hostname + "]\n"  )

	
# Translate the percent of dangerousness to human text message
# Switch case % for level of dangerousness
def get_percent(prcnt):

    if prcnt>=0 and prcnt<11:
        return "0­10% Malicious file"
    elif prcnt>10 and prcnt<31:
        return ("11­30% Dangeruos file")
    elif prcnt>30 and prcnt<61:
        return ("31­60% Your system is in danger")
    elif prcnt>60 and prcnt<101:
        return ("61­100% you are fucked")
    else:
        return ("Error with percent!!")
	
	
#create a error log, not internet connection or wrong VT API key
# [Time 2016.02.03 20:44:04] [Sender virustotal-devel]  [Message ERROR 696: Not connection with VirusTotal DB, please check your internet connection or VirusTotal API Key]
def puke_error_log(code):

	if code == 696:
		message = "ERROR 696: Not connection with VirusTotal DB, please check your internet connection or VirusTotal API Key"
	elif code == 697:
		message = "ERROR 697: Wrong API Key, please check your VirusTotal API Key"

	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]\n" )

#create a no-data in VT log
# [Time 2016.02.03 20:44:04] [Sender virustotal-devel]  [Message No Data in VirusTotal, please upload this file manually]  [Host Hostname]
def puke_noD_log(hostname, file_name, file_time):
	message = ("No Data in VirusTotal, please upload this file manually"
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

		# print "File scanned"
		return json_data

	except:
		# Not possible connection with VirusTotal Database
		# return False
		return {u'response_code': -1, u'more_info': u'error connection with VirusTotal DB, please check your internet connection or VirusTotal API Key'}

#extract previous last entry for this agent in our json db
# if there is not any data for this agent, is going to create in our db
def extract_last_entry(agent_path):
	agent = agent_path.split('/')[-1]

	with open(db_file, 'r') as data_file:  

		try:
			tree_data = json.load(data_file)
		except:
			#DB is broken: Creating new emptly DB
			tree_data = {u"agents": {} }

		agent_record = tree_data["agents"].get( agent )

		#If no data in DB for this agent: Creating from scratch
		if agent_record == None:
			tree_data["agents"][ agent ] = {}
			tree_data["agents"][ agent ]["last_entry"] = "None"
			tree_data["agents"][ agent ]["FTS"] = time_now()
			last_entry_found = None
		
		else:
			last_entry_found = agent_record.get( "last_entry" )

		tree_data["agents"][ agent ]["LTS"] = time_now()


	with open(db_file, 'w') as f:
		f.write(json.dumps(tree_data, indent=4))

	return last_entry_found

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
def update_db(agent_path, new_last_entry):
	agent = agent_path.split('/')[-1]

	with open(db_file, 'r') as f:
		tree_data = json.load(f)

	with open(db_file, 'w+') as f:
		tree_data["agents"][ agent ]["last_entry"] = new_last_entry
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
	while True:
		# print "\nRound starts here:\n"
		countZ = 0

		if len(personal_API_Key) == 64:
			for queue_file in get_queue_files():
				# print "\nSCANING FILE: ", queue_file
				# print "\nLAST ENTRY FOUND: ", extract_last_entry(queue_file)
				scan_queue_file(queue_file, extract_last_entry(queue_file), countZ)
				# print "-----------END SCAN FILE-------------\n\n\n\n"
				countZ += 1
		else:
			puke_error_log(697)

		time.sleep(sleep_time)

if __name__ == "__main__":
	summon_daemon()