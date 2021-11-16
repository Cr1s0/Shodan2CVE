# Shodan2CVE

The object of this script is to gather public vulnerabilities from IPs or domains, based on Shodan.

Although you can find some screenshots with examples, the available options are:

## Requirements
- Save this bash script in '$HOME/Desktop/Shodan2CVE'.
- Run Shodan with a subscription API_KEY.
- Make sure you have "shodan" and "jq" packages installed in your system.

## Init
In order to have all the functionalities, the first task is to init Shodan with a subscription plan API_KEY.

To do so, run "$ shodan init API_KEY" as shown below.

![Imgur Image](https://imgur.com/yW7JAm5.png)
  
## Usage:
 
```
./Shodan2CVE.sh [OPTION] [ARGUMENT]

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
```

## Examples

### Analyse specific comma-separated IPs or domains. 

![Imgur Image](https://imgur.com/zlciX3f.png)

### Analyse IPs or domains from a given file: 

Analyse the registries contained in "list.txt"

![Imgur Image](https://imgur.com/ph1r24k.png)

### Print coloured statistics for given IPs or domains, specified from command line or file. 

If the IP has not been analysed, it will before printing stats.

![Imgur Image](https://imgur.com/VDC5GtQ.png)

Print statistics for all IPs.

![Imgur Image](https://imgur.com/NjmirtB.png)
	
### Merge all the results in a single file: 

![Imgur Image](https://imgur.com/V0qnFqv.png)

### Print CVE information: 

![Imgur Image](https://imgur.com/OLxdQKq.png)
