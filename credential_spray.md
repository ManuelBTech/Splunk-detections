# Credential Spray Detection (Splunk)
## Description
Detects possible credential spraying behavior by identifying a single source IP generating failed 
authentication attempts against several unique user accounts. 

## DATA Source
Windows Security Event Logs (Event Code 4625 - Failed Logon)

## SPL Query
index="botsv3" sourcetype="wineventlog:security" (EventCode=4625)
stats dc(Account_Name) as unique_accounts count as failures by src_ip
where unique_accounts >= 5 AND failures >= 10
sort - failures
table src_ip unique_accounts failures
