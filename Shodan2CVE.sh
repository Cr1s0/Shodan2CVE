#!/bin/bash
# 
#title           :Shodan2CVE.sh
#description     :This script will gather public vulnerabilities from IPs or domains, show stats and print CVE information. 
#data source	 :OSINT
#author		 :Cr1s0 - https://github.com/Cr1s0
#date            :2021-11-16
#version         :1.3
#notes           :Before execution, start "shodan" with a subscription plan API_KEY
#		 :Install 'jq'
#==============================================================================

#Global variables
provider_product=""
stats_for_domain=""

function credits () {
	tput bold; tput setaf 3
	printf "
	****************************************************************************************************\n"
	tput setaf 2
	printf "
	.d8888b.   888                    888                    .d8888b.   .d8888b.  888     888 8888888888 
	d88P  Y88b 888                    888                   d88P  Y88b d88P  Y88b 888     888 888        
	Y88b.      888                    888                          888 888    888 888     888 888        
	  Y888b.   88888b.   .d88b.   .d88888  8888b.  88888b.       .d88P 888        Y88b   d88P 8888888    
	     Y88b. 888  88b d88  88b d88  888      88b 888  88b  .od888P   888         Y88b d88P  888        
	       888 888  888 888  888 888  888 .d888888 888  888 d88P       888    888   Y88o88P   888        
	Y88b  d88P 888  888 Y88..88P Y88b 888 888  888 888  888 888        Y88b  d88P    Y888P    888        
	  Y8888P   888  888   Y88P     Y88888  Y888888 888  888 888888888    Y8888P       Y8P     8888888888" 
	tput setaf 3
	printf "\n
	*******************************        Author: Cr1s0 - v1.3         ********************************\n\n"
	tput sgr0
}

function cleaning () { #Delete unnecessary files.
	rm $HOME/Desktop/Shodan2CVE/CVE/temp*.* &>/dev/null
	rm $HOME/Desktop/Shodan2CVE/CVE/CVE*.txt &>/dev/null
	rm $HOME/Desktop/Shodan2CVE/CVE-* &>/dev/null
	rm $HOME/Desktop/Shodan2CVE/tempfile.txt &>/dev/null
	rm $HOME/Desktop/Shodan2CVE/results.json.gz &>/dev/null
}

function save_CVEs_from_active () { #Use of Shodan to save each CVE in a temporary file.
	echo "Saving IP - Domain - CVE - CVSS - Provider - Product. Please check $HOME/Desktop/Shodan2CVE/CVE/$1.txt"
	shodan host $1 | grep -Po 'CVE-\K\S+' >| $HOME/Desktop/Shodan2CVE/CVE/temp.txt

	#Append "CVE-" to each line
	awk '{print "CVE-" $0;}' $HOME/Desktop/Shodan2CVE/CVE/temp.txt >| $HOME/Desktop/Shodan2CVE/CVE/CVEs_$1.txt
	gather_domain_CVSS_product_from_CVE $1 $HOME/Desktop/Shodan2CVE/CVE/CVEs_$1.txt
}

function gather_domain_CVSS_product_from_CVE () {
	#Retrieve NIST response with 'wget' to save CVSS-risk pairs. Data treatment based in our needs.
	if [ -f "$HOME/Desktop/Shodan2CVE/CVE/CVEs_$1.txt" ]; then
		rm $HOME/Desktop/Shodan2CVE/CVE/$1.txt &>/dev/null
	fi	

	shodan download results ip:$1 &>/dev/null
	domain=$(shodan parse --fields domains results.json.gz | tail -1) &>/dev/null
	
	while IFS= read line || [ -n "$line" ];
	do
		gather_product_from_CVE $line
		
		wget https://nvd.nist.gov/vuln/detail/$line &>/dev/null
		
		#Variables for CVSSv2 and CVSSv3 need to be different because sometimes, depending on CVE source, they have more than one value.
		#For example, CVE-2021-32802.

		crit_cvss_nok=$(cat $line | grep -P '(?<=class="label label).*(?=</a>)' | cut -d '>' -f2 | cut -d '<' -f1 | sed 's/ /;/g' | tr '\n' '-')
		matches_nok=$(echo $crit_cvss_nok | tr -cd ';' | wc -c)
		crit_cvss_ok=$(cat $line | grep -P '(?<=class="label label).*(?=</a>)' | cut -d '>' -f2 | cut -d '<' -f1 | sed 's/ /;/g' | tr '\n' ';')
		matches_ok=$(echo $crit_cvss_ok | tr -cd ';' | wc -c)

		if [[ $matches_nok -eq 1 ]]; then
			#matches_nok=1 means that CVSSv3 is missing, so "N/A;N/A;" is appended to the variable. Otherwise, no action is needed.
			na="N/A;N/A;"
			crit_cvss=${na}${crit_cvss_ok}
			
		elif [[ $matches_nok -eq 2 ]]; then
			#matches_nok=2 means that there is a unique CVSSv3, CVSSv2 and risk pairs, so the values are saved directly.
			crit_cvss=$crit_cvss_ok
		else
			#matches_nok>2 means that there are more than one CVSSv3 sources, so just the first CVSSv3-risk pair is saved.
			crit_cvss=$(echo $crit_cvss_nok | cut -d '-' -f1)';'$(echo $crit_cvss_nok | rev | cut -d '-' -f2 | rev ); crit_cvss+=';'
		fi 

		#Merge all information to a final file.
		crit_cvss_final=$(echo -n "$1;"; echo -n "$domain;"; echo -n "$line;"; echo -n "$crit_cvss")
		final=$crit_cvss_final$provider_product
		echo $final >> $HOME/Desktop/Shodan2CVE/CVE/$1.txt

	done < "$2"
	insertColumns $HOME/Desktop/Shodan2CVE/CVE/$1.txt
	
	#If the active does not have published CVEs, we create an empty file. Otherwise, statistics() will loop infinitely.
	if [ ! -f "$HOME/Desktop/Shodan2CVE/CVE/$1.txt" ]; then
		touch $HOME/Desktop/Shodan2CVE/CVE/$1.txt
	fi
}

function gather_product_from_CVE () {

	API_URL='https://cve.circl.lu/api'
	IFS=: read -r _ _ _ vendor product _ < <(
	  # Perform API request
	  curl -s "$API_URL/cve/$1" |

	  # Parse JSON data returned by the API to get only what we need.
	  jq -r '.vulnerable_product[0]'
	)
	provider_product=${vendor^}';'${product^}
}

function insertColumns () { #Append headers merged file.
	sed -i '1i IP;Domain;CVE_ID;CVSS_v3;Risk_v3;CVSS_v2;Risk_v2;Provider;Product' $1 &>/dev/null
}

function requirements () {
	mkdir $HOME/Desktop/Shodan2CVE/CVE &>/dev/null
}	

function shodan2CVE () {
	requirements
	save_CVEs_from_active $1
	cleaning
}

function merge_files () {
	#If specified or default file exists, it is previously deleted.
	if [ -f "$HOME/Desktop/Shodan2CVE/CVE/$1.csv" ]; then
		rm $HOME/Desktop/Shodan2CVE/$1.csv &>/dev/null
	fi
	
	first=

	for file in $HOME/Desktop/Shodan2CVE/CVE/*.txt
	do
		exec 5<"$file" #Open file.
		read LINE <&5 #Read first line.
		[ -z "$first" ] && echo "$LINE" #Print it only from first file.
		first="no"

		cat <&5 #Print the rest directly to standard output.
		exec 5<&- #Close file.
		#Redirect stdout for this section into final_file.csv.
	done > $HOME/Desktop/Shodan2CVE/$1.csv
	
	if [[ $(head -n 1 $HOME/Desktop/Shodan2CVE/$1.csv) == '' ]]; then #Ensure that the first line of merged file is the header. 
			header="IP;Domain;CVE_ID;CVSS_v3;Risk_v3;CVSS_v2;Risk_v2;Provider;Product" 
			sed -i "1s/.*/$header/" $HOME/Desktop/Shodan2CVE/$1.csv &>/dev/null
	fi	
}

function statistics () {
	#Read each {ip}.txt file. If it does not exist, analyse it before generating statistics.
	#If no IP is specified, generate statistics for each {ip}.txt file.
	
	if [[ ! "$1" =~ [A-Za-z:space:] ]]; then #If it's an IP then get stats
		if [ ! -f "$HOME/Desktop/Shodan2CVE/CVE/$1.txt" ]; then #If the IP has not been previously analysed.
			echo -e "\t[*] $1 has not been analysed. Please wait."
			shodan2CVE $1
			statistics $1
		else
			for file in $HOME/Desktop/Shodan2CVE/CVE/$1.txt #'$1' corresponds to each IP
			do
				#Stats CVSSv3.
				ncrit3=$(cat CVE/$1.txt | cut -d ';' -f5 | grep -c "CRITICAL")
				nhigh3=$(cat CVE/$1.txt | cut -d ';' -f5 | grep -c "HIGH")
				nmedium3=$(cat CVE/$1.txt | cut -d ';' -f5 | grep -c "MEDIUM")
				nlow3=$(cat CVE/$1.txt | cut -d ';' -f5 | grep -c "LOW")
				nna3=$(cat CVE/$1.txt | cut -d ';' -f5 | grep -c "N/A")
				#Stats CVSSv2.
				ncrit2=$(cat CVE/$1.txt | cut -d ';' -f7 | grep -c "CRITICAL")
				nhigh2=$(cat CVE/$1.txt | cut -d ';' -f7 | grep -c "HIGH")
				nmedium2=$(cat CVE/$1.txt | cut -d ';' -f7 | grep -c "MEDIUM")
				nlow2=$(cat CVE/$1.txt | cut -d ';' -f7 | grep -c "LOW")
				nna2=$(cat CVE/$1.txt | cut -d ';' -f7 | grep -c "N/A")
				
				let total_cve=ncrit3+nhigh3+nmedium3+nlow3+nna3
				#Print results
				echo -e "--- Statistics for $1 (Total: $total_cve)"
				printStats $ncrit3 $ncrit2 $nhigh3 $nhigh2 $nmedium3 $nmedium2 $nlow3 $nlow2 $nna3 $nna2
			done
		fi
	else #If the second argument is a domain, show stats for each IP.
		echo -e "--- Getting stats for $1"
		check_if_ip_or_domain $1 #As index, the next "for" will use the value of the global variable "stats_for_domain".	
		for ip in $(echo $stats_for_domain | sed "s/,/ /g") #For each comma-separated IP, print statistics results.
		do
			if [[ ! "$ip" =~ [A-Za-z:space:] ]]; then #If no letters or spaces, "$ip" is an IP so stats are printed.
				#Stats CVSSv3.
				ncrit3=$(cat CVE/$ip.txt | cut -d ';' -f5 | grep -c "CRITICAL")
				nhigh3=$(cat CVE/$ip.txt | cut -d ';' -f5 | grep -c "HIGH")
				nmedium3=$(cat CVE/$ip.txt | cut -d ';' -f5 | grep -c "MEDIUM")
				nlow3=$(cat CVE/$ip.txt | cut -d ';' -f5 | grep -c "LOW")
				nna3=$(cat CVE/$ip.txt | cut -d ';' -f5 | grep -c "N/A")
				#Stats CVSSv2.
				ncrit2=$(cat CVE/$ip.txt | cut -d ';' -f7 | grep -c "CRITICAL")
				nhigh2=$(cat CVE/$ip.txt | cut -d ';' -f7 | grep -c "HIGH")
				nmedium2=$(cat CVE/$ip.txt | cut -d ';' -f7 | grep -c "MEDIUM")
				nlow2=$(cat CVE/$ip.txt | cut -d ';' -f7 | grep -c "LOW")
				nna2=$(cat CVE/$ip.txt | cut -d ';' -f7 | grep -c "N/A")
				
				let total_cve=ncrit3+nhigh3+nmedium3+nlow3+nna3
				#Print results
				echo -e "--- Statistics for $ip (Total: $total_cve)"
				printStats $ncrit3 $ncrit2 $nhigh3 $nhigh2 $nmedium3 $nmedium2 $nlow3 $nlow2 $nna3 $nna2
			fi
		done
	fi
}

function printStats () {
	printf "\tCVSSv3 %-20s\t CVSSv2\n" 
	printf "\tCritical= %-20s\t Critical= %-20s\n" "$1" "$2"
	printf "\tHigh= %-20s\t High= %-20s\n" "$3" "$4"
	printf "\tMedium= %-20s\t Medium= %-20s\n" "$5" "$6"
	printf "\tLow= %-20s\t Low= %-20s\n" "$7" "$8"
	printf "\tN/A= %-20s\t N/A= %-20s\n" "$9" "${10}"
	na=0
	low=0
	medium=0
	high=0
	critical=0
	printf '\n\tCVSS v3: ' 
	tput setaf 7 ;\
	while [ $na -lt $9 ] #N/A = White
	do
		printf '█%.0s'
		let na++
	done	
	tput setaf 2 ;\
	while [ $low -lt $7 ] #Low = Green
	do
		printf '█%.0s'
		let low++
	done	
	tput setaf 3 ;\
	while [ $medium -lt $5 ] #Medium = Yellow
	do
		printf '█%.0s'
		let medium++
	done	
	tput setaf 1 ;\
	while [ $high -lt $3 ] #High = Red
	do
		printf '█%.0s'
		let high++
	done	
	tput setaf 5 ;\
	while [ $critical -lt $1 ] #Critical = Magenta
	do
		printf '█%.0s'
		let critical++
	done
	tput setaf 7
	printf ' '$9'-'$7'-'$5'-'$3'-'$1'\n'
	na=0 
	low=0
	medium=0
	high=0
	critical=0
	tput setaf 7 ;\
	printf '\n\tCVSS v2: ' 
	tput setaf 7 ;\
	while [ $na -lt ${10} ] #N/A = White
	do
		printf '█%.0s'
		let na++
	done	
	tput setaf 2 ;\
	while [ $low -lt $8 ] #Low = Green
	do
		printf '█%.0s'
		let low++
	done	
	tput setaf 3 ;\
	while [ $medium -lt $6 ] #Medium = Yellow
	do
		printf '█%.0s'
		let medium++
	done	
	tput setaf 1 ;\
	while [ $high -lt $4 ] #High = Red
	do
		printf '█%.0s'
		let high++
	done	
	tput setaf 5 ;\
	while [ $critical -lt $2 ] #Critical = Magenta
	do
		printf '█%.0s'
		let critical++
	done	
	tput setaf 7
	printf ' '${10}'-'$8'-'$6'-'$4'-'$2'\n\n'
}

function check_if_ip_or_domain () { #The object of this function is to execute Shodan2CVE() with the IP of "www.domain.tld" and "domain.tld".
	if [[ "$1" =~ [A-Za-z:space:] ]]; then #If "$1" is a domain, the variable is treated as needed.
		
		if [[ "$1" =~ ^www.* ]]; then #Case 'www.domain.tld' => Remove "www." and save.
			domain=$(echo $1 | sed 's/www.//g')
			echo -e "\n\t[*] Gathering information related to $domain"

		elif [[ "$1" =~ ^https?://.* ]]; then #Case starts with "http?://", with or without "www."
			domain=$(echo $1 | sed 's/https\?:\/\///') #Remove "http?://" and check if domain starts or not with "www."

			if [[ "$domain" =~ ^www.* ]]; then #Case "www." => Delete "www." and save.
				domain=$(echo $domain | sed 's/www.//') 
				echo -e "\n\t[*] Gathering information related to $domain"
							
			else #Case "domain" => Do nothing.
				echo -e "\n\t[*] Gathering information related to $domain"
			fi
		
		else
			#Case "domain.tld" => Do nothing.
			domain="$1"
			echo -e "\n\t[*] Gathering information related to $domain"
		fi
		
		#Because "dig" may return diferent values when a domain is specified with and without "www", it's executed for both cases.
		ip_with_www=$(echo $(dig +short "www.$domain") | sed 's/ /,/g')
		ip_without_www=$(echo $(dig +short "$domain") | sed 's/ /,/g')
		
		#Join all IPs in a single variable and delete duplicated ones. If there is still any domain, ignore it.
		ip_list=$(echo $ip_with_www,$ip_without_www | tr ',' '\n' | grep -v '^$' | sort | uniq -i | tr '\n' ','); ip_list=$(echo "${ip_list%?}")
		stats_for_domain=$ip_list #This variable will be used only when user wants to print stats by specifying a domain
		
		for ip in $(echo $ip_list | sed "s/,/ /g") #For each comma-separated IP, and if it's an IP, then call shodan2CVE. Otherwise, ignore it. 
		do
			if [[ ! "$ip" =~ [A-Za-z] ]]; then
				sleep 1.5 #Add 1.5 seconds delay because shodan has a massive API call control.
				shodan2CVE $ip
			fi
		done			
	else	#If there are no letters (its an IP), used directly.
		echo -e "\n\t[*] Gathering information related to $1"
		shodan2CVE $1
	fi
}

function print_CVE_data () {
	gather_product_from_CVE $1
	wget https://nvd.nist.gov/vuln/detail/$1 &>/dev/null
	
	#Variables for CVSSv2 and CVSSv3 need to be different because sometimes, depending on CVE source, they have more than one value.
	#For example, CVE-2021-32802.

	crit_cvss_nok=$(cat $1 | grep -P '(?<=class="label label).*(?=</a>)' | cut -d '>' -f2 | cut -d '<' -f1 | sed 's/ /;/g' | tr '\n' '-')
	matches_nok=$(echo $crit_cvss_nok | tr -cd ';' | wc -c)
	crit_cvss_ok=$(cat $1 | grep -P '(?<=class="label label).*(?=</a>)' | cut -d '>' -f2 | cut -d '<' -f1 | sed 's/ /;/g' | tr '\n' ';')
	matches_ok=$(echo $crit_cvss_ok | tr -cd ';' | wc -c)

	if [[ $matches_nok -eq 1 ]]; then
		#matches_nok=1 means that CVSSv3 is missing, so "N/A;N/A;" is appended to the variable. 
		na="N/A;N/A;"
		crit_cvss=${na}${crit_cvss_ok}
		
	elif [[ $matches_nok -eq 2 ]]; then
		#matches_nok=2 means that there is a unique CVSSv3, CVSSv2 and risk pairs, so the values are saved directly.
		crit_cvss=$crit_cvss_ok
	else
		#matches_nok>2 means that there are more than one CVSSv3 sources, so just the first CVSSv3-risk pair is saved.
		crit_cvss=$(echo $crit_cvss_nok | cut -d '-' -f1)';'$(echo $crit_cvss_nok | rev | cut -d '-' -f2 | rev ); crit_cvss+=';'
	fi 

	printf "\tVersion 3 \tCVSS= %-20s\n" "$(echo $crit_cvss | cut  -d';' -f1)"
	printf "\t\t\tRisk= %-20s\n" "$(echo $crit_cvss | cut -d ';' -f2)"
	printf "\tVersion 2 \tCVSS= %-20s\n" "$(echo $crit_cvss | cut  -d';' -f3)"
	printf "\t\t\tRisk= %-20s\n" "$(echo $crit_cvss | cut -d ';' -f4)"	
	printf "\tProvider= %-20s\n\tProduct= %-20s\n" "$(echo $provider_product | cut -d ';' -f1)" "$(echo $provider_product | cut -d ';' -f2)"
	rm $1 &>/dev/null
}

function showHelp () {
	printf "
For a correct execution, save $0 in '$HOME/Desktop/Shodan2CVE' and run Shodan with a subscription API_KEY.
Usage: ./Shodan2CVE.sh [OPTION] [ARGUMENT]

Options:
	-h, --help			Show this message and exit.
	-i, --ip [ip,ip]		Gather information from one or more given comma-separated IPs.
	-d, --domain [domain,domain]	Gather information from one or more given comma-separated domains.
	-f, --file [file]		Gather information from the IPs or domains listed in a specified '.txt' file. Note: One IP or domain per line.
	-m, --merge [file]		Merge all results in a single CSV file, whose name can be set as default, if not passed as argument, or custom.
	-s, --stats [ip,domain]		Show stats from one or more given comma-separated IPs or domains, or read from '.txt' file (same as '-sf' option).
	-sf, --stats-file [file]	Show stats from the IPs or domains contained in the '.txt' file passed as argument.
	-c, --cve [CVE-YYYY-XXXXX]	Print information from one or more given comma-separated CVE ID.
	-r, --release			Show release notes and exit.
	
Examples: 	
	./Shodan2CVE.sh -i 8.8.8.8,8.8.4.4
	./Shodan2CVE.sh --domain twitch.tv,https://youtube.es
	./Shodan2CVE.sh -f list.txt
	./Shodan2CVE.sh -m => As a result the file 'final_file.csv' will be created.
	./Shodan2CVE.sh list => Filename will be 'list.csv'.
	./Shodan2CVE.sh --stats => Print statistics from all previously analysed IPs.
	./Shodan2CVE.sh -s 8.8.8.8,8.8.4.4,https://google.com => Print statistics for these IPs/domains.
	./Shodan2CVE.sh --cve CVE-2021-29935,CVE-2019-1694
"
}

function showRelease () {
	printf "Release notes:
	
v1.0  	What's new?
	|- First version.
	|- Supported information gathering from an individual IP, passed as argument.
	|- Merge CVE results in a single CSV file, with a default or custom name.

v1.1	What's new?
	|- Added argument management to gather information from several comma-separated IPs or from text file.
	|- Show statistics for one or more specified IPs.

	Bugfixes
	|- Manage cases like CVE-2021-32802, when more than one CVSS scoring source is returned.

v1.2	What's new?
	|- Domain treatment, passed either from command line or from a file.
	|- If no specified target, statistics for each previously analysed IP. In addition, automatic anaysis if the IP has not been analysed.

	Bugfixes
	|- 'dig' is used to obtain the IP from a given domain but, because it may return more than one IP, its response is treated in the way that,
	   if there is any duplicated IP, it's just scanned once.
	   
v1.3    What's new?
	|- Supported domain statistics. When an user requests for a domain statistics, shows its IPs.
	|- Show coloured statistics, based on IPs or domains contained in a text file.
	|- Print comma-separated CVE information.
	
	Bugfixes
	|- Solve cases when the first line of the merged file is blank.
"
}

#########################################################################
########################### PROGRAM EXECUTION ###########################
#########################################################################

# Main Function

	param=$1
	credits
	case $param in

		--ip | --domain | -i | -d)  
			if [[ "$(echo $2 | rev)" =~ ^txt.* ]]; then
				echo "Please specify one or more comma-separated IPs or domains. For files use '-f' option."
			else		
				for i in $(echo $2 | sed "s/,/ /g")
				do
					check_if_ip_or_domain $i
				done
			fi
			;;

                --file | -f)
                	cp $2 tempfile.txt #A temporary file is used because otherwise a new line is appended to the input file for some reason.
			new_line=" "; echo $new_line >> tempfile.txt #Blank line is added, otherwise the last registry is not read.
			num_lines=$(sed -n '$=' $2) 
			echo -e "Reading target IPs or domains from file. Number of entries: $num_lines"
			while IFS= read -r line 
			do
				check_if_ip_or_domain $line
			done < "tempfile.txt"
			;;

		--merge | -m)	#Merge all files in a single one.
			if [[ $# -eq 1 ]]; then #If no destination file is specified, a default name is used.
				merge_files final_file
				echo "final_file.csv generated properly and saved in $HOME/Desktop/Shodan2CVE."
			elif [[ $# -eq 2 ]]; then #Otherwise, specified name is used.
				merge_files $2
				echo "$2.csv generated properly and saved in $HOME/Desktop/Shodan2CVE."
			else
				showHelp
			fi
			;;
			
		--stats | -s) 
			if [[ $# -eq 2 ]]; then #If there are 3 arguments it means that we have script_name + argument + IPs/domains.

				if [[ "$(echo $2 | rev)" =~ ^txt.* ]]; then 
		                	cp $2 tempfile.txt #A temporary file is used, otherwise a new line is appended to the input file
					new_line=" "; echo $new_line >> tempfile.txt #Blank line is added because otherwise the last registry is not read.
               				num_lines=$(sed -n '$=' $2)
					echo -e "Reading target IPs or domains from file. Number of entries: $num_lines"
					while IFS= read -r line 
					do
						statistics $line
					done < "tempfile.txt"
				else
					for i in $(echo $2 | sed "s/,/ /g")
					do
						statistics $i
					done
				fi
			elif [[ $# -eq 1 ]]; then #If just script_name + argument, generate stats for all previously analysed IPs.
				search_dir="$HOME/Desktop/Shodan2CVE/CVE"
				for file in "$search_dir"/* #List all files within "search_dir" directory.
				do
					check=$(echo "$file" | sed 's#.*/##') #Save file by file without full path.
					statistics ${check%.*} #Call statistics() without extension, so just the IP is sent.
				done
			else
				showHelp
			fi
			;;

		--stats-file | -sf) #Show stats for IPs saved in a file. This option is no needed anymore, '-s' accepts files.
			cp $2 tempfile.txt #A temporary file is used because otherwise a new line is appended to the input file for some reason.
			new_line=" "; echo $new_line >> tempfile.txt #Blank line is added because otherwise the last registry is not read.
			num_lines=$(sed -n '$=' $2)
			echo -e "Reading target IPs or domains from file. Number of entries: $num_lines"
			while IFS= read -r line #Each $line has an IP so statistics function is called for each one.
			do
				statistics $line
			done < "tempfile.txt"
			rm "tempfile.txt" &>/dev/null
			;;		

		--cve | -c) #Show CVE information, comma-separated or from file.
			echo -e "Showing CVE information.\n"
			for i in $(echo $2 | sed "s/,/ /g")
			do
				echo $i
				print_CVE_data $i
				echo ""
			done
			;;

		--release | -r) #Show release notes
			showRelease
			;;
					
		--help | -h | *) #If none or wrong argument, or want to show help.
			showHelp
			;;
        esac