README: 

###

	VirusTotal devel for OSSEC
	
###

Configuration: vito_config.py

	- First you need to update your API KEY in (line 7)
		personal_API_Key 
		
	- Update your Queue Syscheck folder (in absolute path)
		syscheck_folder
		
	- Please check the file vito_config.py for more options
		
		
Execute VirusTotal devel for OSSEC:
	
	$python ext_virus_total.py
	
-The new way to execute the app

	-from /virustotal/etc/default  copy the ext_virus_total file to /etc/default

	-In /etc/default/ext_virus_total change the variable (VT_HOME) that contains the path for the filr ext_virus_total.py 
	-VT_HOME= path where you have downloaded the virustotal pacage (e.g VT_HOME=/home/user/Desktop/virustotal)

	-from /virustotal/etc/int.d copy the ext_virus_total.sh file to /etc/init.d

	
All events/logs can be checked in:
	See some examples in:
		log_vt


Logtest by OSSEC:

	See some examples in:
		LOGTEST_RESULTS.TXT
		

See schematic process in and Malware sample MD5 list:
	
		logarithmo.txt
