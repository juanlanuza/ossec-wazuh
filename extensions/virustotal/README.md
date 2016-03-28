##README: 

###

	VirusTotal devel for OSSEC
	
###

##Introduction

	VirusTotal devel for OSSEC integrates OSSEC with Virus Total, the main goal is to consult all hash obtained
	by OSSEC against the Virus Total DB through its public API

	Check if any changed file was infected with Virus or is clean in order to avoid in order to avoid unexpected
	system downtime, technical difficulties, or other interruptions!


##Instalation

	VirusTotal devel for OSSEC requires you to have previously installed OSSEC as your manager and have root
	permitions on your System. You can download and install it following these instruction.

	It is also needed to have intaled Python 2.7+, and at least join to VirusTotal Community, in this case you
	will have a limited check aginst VirusTotal DB of 15 minuts to avoid this you will need to have a VirusTotal
	Premium account

	Python packages

	The API uses Python to perform some tasks. Install in your system:

    	Python 2.7+

	Copy the API folder to OSSEC folder:

##Configuration

	You can configure some parameters using the file vito_config.py:

		- First you need to update your API KEY in (line 7)
			personal_API_Key 
		
		- Update your Queue Syscheck folder: (for now we are trying in a fake folder with some 
		queue files) (line 18)
			syscheck_folder


    Paths:

        -insert ext_virus_total from /virus_total/etc/default in /etc/default

		-insert ext_virus_total.sh from /virus_total/etc/int.d in /etc/init.d

	Logs

    	logs: All events/logs can be checked in log_vt

	By default you will have a certain range of rules and decoders that you can download on ... and 
	we encourage you to develop your own rules and decoders and configure the existing ones according
	to your needs!
		ex:
		<rule id="113425" level="3">
    			<if_sid>113400</if_sid>
    			<id>590</id>
    			<description>Wrong MD5 hash for a file, VT-Devel can not process it.</description>
  		</rule>
	

##Executation

	Execute VirusTotal devel for OSSEC:

		-insert ext_virus_total from /virus_total/etc/default in /etc/default

		-insert ext_virus_total.sh from /virus_total/etc/int.d in /etc/init.d

		-The variable with the path for the file ext_virus_total.py must be filled in file 
		ext_virus_total inside /etc/default
		
		-VT_HOME=/home/user/Desktop/virustotal


##Referene
	To be complete..
	
##Request
	To be complete..
