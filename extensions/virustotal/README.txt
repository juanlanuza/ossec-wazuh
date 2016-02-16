README: 

###

	VirusTotal devel for OSSEC
	
###

Configuration: vito_config.py

	- First you need to update your API KEY in (line 7)
		personal_API_Key 
		
	- Update your Queue Syscheck folder: (for now we are trying in a fake folder with some queue files) (line 18)
		syscheck_folder
		
	- Please check the file vito_config.py for more options
		
		
Execute VirusTotal devel for OSSEC:
	
	$python ext_virus_total.py
	
-The new way to execute the app

	-insert ext_virus_total from /virus_total/etc/default en /etc/default

	-insert ext_virus_total.sh from /virus_total/etc/int.d en /etc/init.d

	-The variable with the path for the file ext_virus_total.py must be filled in file ext_virus_total inside /etc/default
	-VT_HOME=/home/user/Desktop/virustotal

	
All events/logs can be checked in:
	See some examples in:
		log_vt


Logtest by OSSEC:

	See some examples in:
		LOGTEST_RESULTS.TXT
		

See schematic process in and Malware sample MD5 list:
	
		logarithmo.txt
