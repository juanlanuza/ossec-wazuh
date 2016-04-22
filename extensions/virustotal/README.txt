README: 

Introduction

	VirusTotal devel for OSSEC is a Python module that integrates OSSEC with Virustotal, the main goal is to consult all Hashes obtained by Syscheck against the Virustotal DB, a free service that analyzes files from malwares.

	Check if any new or changed file was infected with Malware or Virus in order to avoid unexpected system downtime, technical difficulties, or other interruptions!

Requisites

	You need to get an API key to use the VirusTotal Public API 2.0. To do so, just sign-up on the service, go to your profile and click on API Key.

	*** Virustotal Public Key is limited to at most 4 requests per minute.

	You also need to have installed manager’s Wazuh HIDS.

	And finally you need at least up Python 2.7 in order to execute VirusTotal devel for OSSEC.

Install

	You need to copy files from github in some folder in your machine.
	virustotal-ossec.py: Main file program
	vito_config.py: Configuration file

	You need to copy rules/decoders into the right Ossec folder
	virustotal_rules.xml into /var/ossec/rules/
	virustotal_decoders.xml into /var/ossec/etc/wazuh_decoders/

	Update your ossec.conf file in /var/ossec/etc/ossec.conf
	For your new rules: 

	<include>virustotal_rules.xml</include>

	Add log_file (see Configuration step) as localfile to monitor, for ex:

	  <localfile>
		<log_format>syslog</log_format>
		<location>/home/user/Desktop/virustotal/virustotal_log.txt</location>
	  </localfile>


Configuration

	You will need to configure some parameters into configuration file vito_config.py:

		- First you need to update your API KEY: personal_API_Key 
		- Update your Queue Syscheck folder: syscheck_folder

	Then, if you wish, you can configure others parameters:
		log_file: File for VirusTotal-Devel for Wazuh logs (Absolute or relative path)
		db_file: Agents DB for VirusTotal-Devel for Wazuh (Absolute or relative path)
		sleep_time: Time (in seconds) between scans in syscheck folder
			
		
Running

	To run VirusTotal devel for OSSEC you just need to execute the file virustotal-ossec.py with Python.

		$ python virustotal-ossec.py
		
Alerts

	By default you will have a certain range of rules and decoders that you can download on ... and we encourage you to develop your own rules and decoders and configure the existing ones according to your needs!

		<rule id="113425" level="3">
			<if_sid>113400</if_sid>
			<id>590</id>
			<description>Wrong MD5 hash for a file, VT-Devel can not process it.</description>
		</rule>


