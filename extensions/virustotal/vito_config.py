#####
##		Local config for VirusTotal-Devel for Wazuh
#####


## Get your key in virustotal.com
personal_API_Key = "###"


## Public keys are free --> limitations: a scan every 15 seconds
## For private keys change to False and the frequency
is_public_key = True
frecuency_key = 15


## Syscheck folder to watch (Absolute path)
## By default in OSSEC is "/var/ossec/queue/syscheck/"
syscheck_folder = "/var/ossec/queue/syscheck/"

## File for VirusTotal-Devel for Wazuh logs (Absolute or relative path)
log_file = "log_vt"

## Agents DB for VirusTotal-Devel for Wazuh (Absolute or relative path)
db_file = "local_data.json"

## Time (in secons) between scans in syscheck folder make by VirusTotal-Devel for Wazuh
sleep_time = 60


#####
## 		Personalize your log
#####


## Analisys results, antivirus and virus detected names
is_result = True

## Link to virustotal website with full info about specific file
is_permalink = True

