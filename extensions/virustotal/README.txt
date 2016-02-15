README:

###

	VirusTotal devel for OSSEC

###

Configuration: local_data.json

	- First you need to update your API KEY in
		"local_conf_vt" / "API_Key"

	- Update your Queue Syscheck folder: (for now we are trying in a fake folder with some queue files)
		"local_conf_vt" / "syscheck_folder"



Execute VirusTotal devel for OSSEC:

	$python main.py


All events/logs can be checked in:

	log_vt


Logtest by OSSEC:

	See some examples in:
		LOGTEST_RESULTS.TXT


See schematic process in and Malware sample MD5 list:

		logarithmo.txt


#######################################
#######################################

The new way to execute the app

insert ext_virus_total from /virus_total/etc/default en /etc/default

insert ext_virus_total.sh from /virus_total/etc/int.d en /etc/init.d

The variable with the path for the file ext_virus_total.py must be filled in file ext_virus_total inside /etc/default
VT_HOME=/home/user/Desktop/virustotal
