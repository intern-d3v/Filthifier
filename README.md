# Filthifier

A python tool to generate a virtual machine with random vulnerabilities based off of user preference.

## Terms and Definitions
	Vulnerability - a security flaw which serves as a weakness to an operating system, typically in the form of a misconfiguration.

	Service - a application or process which runs in the background to provide or execute essential tasks when called. Examples: apache2, sshd, telnetd

	Category - a generalized description which describes a group of vulnerabilities. All vulnerabilities have a category. The categories are the following:
		- userAudit: vulnerabilities consisting of unauthorized users, admins, or user configurations
		- unauthorizedSoftware: software and programs that pose a security weakness or have malicious potential
		- loginPolicy: all vulnerabilities relating to login and authentication security
		- securityAudit: general security misconfiguration and exploitables
		- services: vulnerabilities in required services which are improperly configured
		- kernelAudit: kernel security vulnerabilities
		
## Configuring
The Filthifier relies on three primary configurations:
- prefs.json
- vulnerabilities/
- config.json

### prefs.json 
  prefs.json is the primary file to be edited by the user. Every user must customize the prefs.json to their liking. This is the only file which is necessary to be edited.
  It contains three major configuration options:
  - os
    - controls which operating system the challenge image will be initialized with
  - difficulty
    - select from easy, medium, or hard to govern the difficulty of the training image produced
  - services
    - list to define which services should be required on the challenge image (ex: [ssh,apache2])
  - vulnerabilities
    - set to a list of individual vulnerabilities (ex: ["ssh_root_login"]) to only implement the desired vulnerabilities. Alternatively, the "random" flag can be used to generate a full image based off the information in config.json

### vulnerabilities/
  vulnerabilities/ contains a subdirectory for each vunlerability to be sourced for image creation. The name of each subdirectory should reflect a general description of the vulnerability. For example, the directory heirarchy for a vulnerability concerning remote root login over ssh is as follows:
```
	vulnerabilities/
	└── ssh_root_login/	
	    ├── check_success.sh
	    ├── dependencies.tar.gz
	    ├── info.json
	    └── init.sh
```
  Each file is necessary for a vulnerability to be generated. The vulnerability will not be loaded if all files are not present.
  ### info.json
  The info.json file contains multiple fields as properties of a vulnerability.
  	- name
	  - the name given to the parent directory of info.json
	- description
	  - a concise description of the vulnerability
	- type
	  - the category which describes the vulnerability
	- difficulty
	  - the difficulty (easy, medium, hard) of the vulnerability
	- stig_id
	  - the stig_id of the vulnerability (if applicable to the stig index)
  ### check_success.sh
  check_success.sh contains a bash boolean which executes to verify that the vulnerability has been removed. It returns 0 on execution if the vulnerability is removed.
  ### init.sh
  init.sh inserts the vulnerability onto the virtual machine. It contains a bash script to write the misconfiguration to the machine. init.sh should unpack and utilize dependencies.tar.gz if necessary.
  ### dependencies.tar.gz
  dependencies.tar.gz is an archive of files, scripts, or media necessary to initialize the vulnerability.

### config.json
config.json should be edited by advanced users only. TO BE IMPLEMENTED.
## Execution
To execute the filthifier, run ```$ python filthifier.py``` This outputs the following files to the build/ directory:
  - initfile.bash
    - file to initialize the virtual machine with vulnerabilities
  - scoreconfig.json
    - json file containing description of vulnerability as key with command as element
  - scenario.txt
    - file containing user logins, required services, and company policy
  - dependencies.tar.gz
    - archive containing dependencies for the initfile script
  
