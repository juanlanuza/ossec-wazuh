# -*- coding: utf-8 -*-

import time
import json
import urllib
import urllib2
import os
from datetime import datetime
from vito_config import *
import sqlite3
import threading


sleep_flag = False

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

# Create Virustotal-Ossec DB if does not exist.
def create_DB():

	# Open VirustTotal DB
	conn = sqlite3.connect(VirusTotal_DB)
	cur = conn.cursor()

	# Do some setup: Create tables if do not exist in DB
	cur.executescript('''

	CREATE TABLE IF NOT EXISTS Hostname (
	    id     INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	    name   TEXT UNIQUE,
	    FTS	   TEXT,
	    LTS    TEXT,
	    LEntry TEXT,
	    Temp   TEXT
	);

	CREATE TABLE IF NOT EXISTS Queue (
	    host_id     INTEGER,
	    name_file  	TEXT,
	    timestamp	INTEGER,
	    md5			TEXT,
	    PRIMARY KEY (host_id, timestamp, md5)
	)

	''')

	global_commit(conn)

# Scan queue file, line by line, and add to internal DB
def scan_queue_file(file_path):	
	
	file = open( os.path.abspath( file_path ), 'r').readlines()

	update_DB = False

	count_lines = 0
	info_update = ""

	# Open VirustTotal DB
	conn = sqlite3.connect(VirusTotal_DB)
	conn.text_factory = str
	cur = conn.cursor()


	# Get hostname's name
	hostname = file_path.split('/')[-1][:-10]
	if len(hostname) < 1:
		hostname = "OSSEC Server"

	
	# Search and select data about hostname in DB
	cur.execute('SELECT id, LEntry FROM Hostname WHERE name = ? ', (hostname, ))
	
	try:
		host_id = cur.fetchone()[0]
	except:
		host_id = None

	# Add new entry in DB, if hostname seem for first time.
	if host_id is None:
		cur.execute('''INSERT OR IGNORE INTO Hostname (name, FTS) VALUES ( ?, ? )''', ( hostname, time_now()) )

		update_DB = True

		cur.execute('SELECT id, LEntry FROM Hostname WHERE name = ? ', (hostname, )) 
		host_id, last_entry = cur.fetchone()

	else:
		cur.execute('SELECT LEntry FROM Hostname WHERE id = ? ', (host_id, ))
		last_entry = cur.fetchone()[0]

	if last_entry is None:
		last_entry = ""

	# Update Last time seem in DB
	conn.execute('''UPDATE Hostname SET LTS = ? WHERE id = ?''', (time_now(), host_id)	)

	for line in reversed(file):

		count_lines += 1

		try:
			line = line.split(':',5)
			md5sum = line[4]
			date_and_name = line[5].split('!')[1]

			if date_and_name.strip() == last_entry.strip():
				# print "Data already register in DB, leaving Syscheck File.....@\n"
				break
			
			if count_lines == 1:
				info_update = date_and_name
				update_DB = True


			file_time = date_and_name.split(' ')[0]
			file_name = date_and_name.split(' ',1)[1].strip()

		except:
			#Wrong syscheck database format
			puke_local_error(hostname, 0, 0, 591)
			update_DB = False
			break

		cur.execute('''INSERT OR IGNORE INTO Queue
			(host_id, name_file, timestamp, md5) VALUES ( ?, ?, ?, ?)''', 
			( host_id, file_name, file_time, md5sum ) )

	if update_DB is True:
		conn.execute('''UPDATE Hostname SET LEntry = ? WHERE id = ?''', (info_update, host_id)	)
	
	global_commit(conn)

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
		
		message = ( "Event 100: Safe file, scan date: " + log_json.get("scan_date") + 
			" | " + unicode(file_name, "utf-8") + 
			" | Created date: " + file_time + " | Permalink: " + log_json.get("permalink") )


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
		message = "Event 001: virustotal-devel for wazuh has started"
	elif code == 002:
		message = "Event 002: New Syscheck DB found for agent: " + add_info
	elif code == 003:
		message = "Event 003: All Syscheck DBs scanned, next scan in " + str(add_info) + " seconds."
	elif code == 004:
		message = "Event 004: New Service/Daemon process started, PID: " + str(add_info)
	elif code == 005:
		message = "Event 005: " + add_info
	elif code == 696:
		message = "ERROR 696: Not connection with VirusTotal DB, please check your internet connection or VirusTotal API Key"
	elif code == 697:
		message = "ERROR 697: Wrong API Key, please check your VirusTotal API Key"
	elif code == 698:
		message = "ERROR 698: Broken DB for virustotal-devel for wazuh, new DB created"
	elif code == 699:
		message = "ERROR 699: No DB for virustotal-devel for wazuh, new DB created"
	elif code == 700:
		message = "ERROR 700: No Syscheck DBs found"


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
	message = ("Event 098: No Data in VirusTotal, please upload this file manually"
		" | " + file_name + 
		" | Created date: " + file_time	)

	write_anylog( "[Time "+ time_now() + "] [Sender virustotal-devel]  [Message " + message + "]  [Host " + hostname + "]\n"  )

#write a log in our log file "./log_vt
def write_anylog(log_string):

	# log_string = log_string.encode("utf-8")
	
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

# Function to commit DB and avoid possible threading problems
def global_commit(connection):

	global sleep_flag

	try:
		while sleep_flag is True:
			pass
		connection.commit()
		sleep_flag = True
		time.sleep(0.1)
		sleep_flag = False

	except:
		time.sleep(0.5)
		global_commit(connection)

#This thread will scan Syscheck folder and files, registering all data in a local DB. 
def syscheck_scanner():
	create_DB()
	while True:

		queue_fileS = get_queue_files()

		# No Syschek files.
		if len(queue_fileS) < 1:
			puke_error_log(700)

		# Scanning Syscheck files.
		for queue_file in queue_fileS:
			scan_queue_file(queue_file)
			# print "-----------File scanned successfully-------------\n"

		# print "Round finished, waiting for next scan round in " + str(sleep_time) + " seconds."
		puke_error_log(003, sleep_time)
		time.sleep(sleep_time)

# Function create to scan the local virusTotal DB (sql)
def db_scanning():

	if is_public_key:
		frecuency_key = 15

	vt_sleep = False

	while True:

		if vt_sleep is True :
			time.sleep(frecuency_key)

		# Check Virus Total API Key
		if len(personal_API_Key) == 64:

			# Open VirustTotal DB
			conn = sqlite3.connect(VirusTotal_DB)
			conn.text_factory = str
			cur = conn.cursor()

			# Search the oldest register in DB
			cur.execute('SELECT min(timestamp), md5, name_file, Hostname.name FROM Queue JOIN Hostname ON Queue.host_id = Hostname.id;' )
			timestamp, md5sum, name_file, hostname = cur.fetchone()

			# print "Scanning:", name_file, "from:", hostname, timestamp

			if md5sum is None:
				if name_file is None:
					time.sleep(sleep_time)
				continue


			# Converting timestamp to readable format
			file_time = datetime.fromtimestamp(  timestamp ).strftime('%Y-%m-%d %H:%M:%S')

			# If Wrong md5sum, useless to send to vt
			if len(md5sum) != 32:
				puke_local_error(hostname, name_file, file_time, 590)
				vt_sleep = False
				cur.execute('''DELETE FROM Queue WHERE md5 = ? AND timestamp = ? AND 
					name_file=?''', ( md5sum, timestamp, name_file))
				global_commit(conn)
				print "wrong md5 deleting entry:", name_file, "from:", hostname
				continue

			# Connecting with VirusTotal Site
			results_vt = retrieve_results_md5(md5sum, personal_API_Key)
			vt_sleep = True

			# Parsing results from VirusTotal
			resp_code = results_vt.get("response_code")

			if resp_code == -1:
				# Something wrong, Not connection with VirusTotal DB or Invalid VirusTotal API Key ... aborting scan
				puke_error_log(696)
				print "resp_code -1"
				
				global_commit(conn)

				time.sleep(sleep_time)
				continue
				
			else:

				if resp_code == 0:
					#non data in vt
					puke_noD_log(hostname, name_file, file_time)

				elif resp_code == 1:
					#data in vtapi
					puke_log(hostname, name_file, file_time, results_vt)

				cur.execute('''DELETE FROM Queue WHERE md5 = ? AND timestamp = ? AND 
					name_file=?''', ( md5sum, timestamp, name_file))	

				global_commit(conn)

		else:
			# Wrong API Key
			puke_error_log(697)
			break

# This function create a service/Daemon that will execute a both tasks in multithreading
def summon_daemon():

  	try:
		# Store the Fork PID
		pid = os.fork()
		
		if pid > 0:
			# print 'PID: %d' % pid
			puke_error_log(004, pid)
			os._exit(0)

	except OSError, error:
		# print 'Unable to fork. Error: %d (%s)' % (error.errno, error.strerror)
		os._exit(1)
		puke_error_log(005, 'Unable to fork. Error: %d (%s)' % (error.errno, error.strerror) )
	puke_error_log(001)

	# Create new threads
	thread1 = virusTotal_thread(1, "scan_syscheck")
	thread2 = virusTotal_thread(2, "send_to_vt")

	# Start new Threads
	thread1.start()
	time.sleep(5)
	thread2.start()

# VirusTotal-Wazuh Threads
class virusTotal_thread (threading.Thread):
    def __init__(self, threadID, name):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
    def run(self):
        # print "Starting " + self.name
        if self.name == "scan_syscheck":
        	syscheck_scanner()
        if self.name == "send_to_vt":
        	db_scanning()
        

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



if __name__ == "__main__":
	summon_daemon()