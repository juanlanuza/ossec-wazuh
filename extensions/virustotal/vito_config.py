#####
##		Local config for VirusTotal-Devel for Wazuh
#####


## Get your key in virustotal.com
personal_API_Key = ""



## Public keys are free --> limitations: a scan every 15 seconds
## For private keys change to False and the frequency
is_public_key = True
frecuency_key = 15


## Syscheck folder to watch (Absolute path)
## By default in OSSEC is "/var/ossec/queue/syscheck/"
syscheck_folder = "/var/ossec/queue/syscheck/"

## File for VirusTotal-Devel for Wazuh logs (Absolute or relative path)
log_file = "zlog_micro.txt"

## Agents DB for VirusTotal-Devel for Wazuh (Absolute or relative path)
VirusTotal_DB = "zVTotal.sqlite"

## Time (in seconds) between scans in syscheck folder make by VirusTotal-Devel for Wazuh
sleep_time = 600


#####
## 		Personalize your log
#####

#
# Coming soon!
#