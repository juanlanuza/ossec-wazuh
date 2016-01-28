import xml.etree.ElementTree as ET
import time
import simplejson as json
import urllib
import urllib2
import datetime

#Get your own Public Key in www.virustotal.com
VT_PublicKey = "826817e7386257a1a2a516a00ac0b11ab230c2a841da7892d17ac678ebdb880b"

#Limit for public key 1 request/ 15 seconds
wait_time = 15

#Folder to find Syscheck queue files in OSSEC, by default:
# dir = "/var/ossec/queue/syscheck/"
#for trying:
dir = "./syscheck/"

# Scan folder searching queue files from syscheck in syscheck folder
def get_queue_files():
 	
 	with open('local_data.json', 'r') as data_file: 
 		tree_data = json.load(data_file)
 		dir = tree_data["local_conf_vt"]["syscheck_folder"]

	import os
	list_files = []

	# Check and filter results, all queue files are called: "(agent_name) 192.0.0.0-_syscheck"
	for file in os.listdir(dir):
		if file[-10:] == "-_syscheck":
			file = dir+file
			list_files.append(file)

	return list_files

# Scan queue file, line by line 
def scan_file(file_path, last_entry):
	#examples, final version should be parametres: file_path, last_entry	

	file = open(file_path, 'r').readlines()

	#get (vt API key, vt restrintions)
	vt_config = extract_vt_config()

	count = 0
	for line in reversed(file):
		line = line.split(':')		#TODO: NEED OPTIMIZATION FOR WINDOWS AGENTS
		md5sum = line[4]
		date_and_name = line[5].split('!')[1]
		print "info this line:", md5sum, date_and_name
		# example output: "1427747294 /home/user/myFiles/3.file"

		#checked already, leaving this agent syscheck file
		if last_entry == date_and_name:
			print "EXIT FOR THIS FILE----------------------@\n"
			break

		if count == 0:
			new_last_entry = date_and_name
			update_db(file_path, new_last_entry)
		#TODO: first process data from first file do not need to sleep, need to fix it
		time.sleep(vt_config[1]) 
		
		count += 1

		#send md5 to vt and parser results
		# print retrieve_results_md5(md5sum, myPublicKey)
		data_vt = parser_json_result( retrieve_results_md5(md5sum, vt_config[0]) )
		
		print data_vt

		#if there is any positive result
		if data_vt is False:
			print "Non data in VT or Connection Error"
		elif data_vt[0] == 0:
			print "Good File"
		elif data_vt[0] > 0:
			print "------->I AM A VIRUS<--------"

			#Create LOG : extract name agent, ip, file name and date
			new_log = file_path.split('/')[-1], data_vt[0], data_vt[1], date_and_name
			write_log(new_log)
			

# Write the log in our file "./log_vt" 
def write_log(info_list):
	
	timestamp = datetime.datetime.fromtimestamp(  int(info_list[3].split(' ')[0])  ).strftime('%Y-%m-%d %H:%M:%S')
	file = info_list[3].split(' ')[1].strip()
	timenow = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

	#[Time ][Host ] [Sender virustotal-devel][Log: Suspicious file identified. Ratio detected: 4/42|  /file.txt |Created date: 2013...  ]
	log_string = "[Timestamp " + timenow +"] [Sender virustotal-devel] [Host " + info_list[0][:-10] + "] [Log: Suspicious file identified. Ratio detected: " + str(info_list[1]) + '/' + str(info_list[2]) +"|" + file + "|Created date: " + timestamp + "]\n" 
	# print log_string
	with open('log_vt', 'ab') as data_file:
		data_file.write(log_string)

# Retrieve report VirusTotal
def retrieve_results_md5(MD5, myPublicKey):

	try:
		
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource": MD5,"apikey": myPublicKey}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json_data = json.loads(response.read())

		# print json_data.get("positives"), json_data.get("scan_date")

		return json_data
	except:
		# Not possible connection with VirusTotal Database
		return False
		return {u'response_code': -1, u'more_info': u'error connection with VirusTotal DB'}
		# return json.loads("'response_code': -1, 'more_info': 'error connection with VirusTotal DB'"

# Extract info from VT report : positive, total
def parser_json_result(vt_answer):
	#if there is any result, response code from vt is 1, otherwise there is not results
	if vt_answer is False:
		return False
	elif vt_answer.get("response_code") == 1:
		return (vt_answer.get("positives"), vt_answer.get("total"))
	else:
		return False


#extract previous last entry for this agent in our json db
# if there is not any data for this agent, is going to create in our db
# TODO if db does not exist : create new emplty db
def extract_last_entry(agent_path):
	agent = agent_path.split('/')[-1]
	with open('local_data.json', 'r') as data_file:  
		updated = False  
		tree_data = json.load(data_file)
		last_entry_found = tree_data["agents"].get( agent )
		if last_entry_found == None:
			tree_data["agents"][ agent ] = "None"
			updated = True

	if updated is True:
		with open('local_data.json', 'w') as f:
			f.write(json.dumps(tree_data, indent=4))

	return last_entry_found

#Get our Local configuration
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

	with open('local_data.json', 'r') as f:
		tree_data = json.load(f)

	with open('local_data.json', 'w+') as f:
		tree_data["agents"][ agent ] = new_last_entry
		f.write(json.dumps(tree_data, indent=4))
		f.close()


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

for queue_file in get_queue_files():
	print "\nSCANING FILE: ", queue_file
	print "\nLAST ENTRY FOUND: ", extract_last_entry(queue_file)
	scan_file(queue_file, extract_last_entry(queue_file))
	print "-----------END SCAN FILE-------------\n\n\n\n"

# print extract_vt_config()