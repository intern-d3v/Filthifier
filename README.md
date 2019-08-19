# VulnSet

A python tool to generate a virtual machine with random vulnerabilities based off of user preference.

## Configuring
VulnSet relies on three primary files for configuration:
- prefs.json
- vulns.json
- config.json
### prefs.json 
  prefs.json is the primary file to be edited.
  It contains three major configuration options:
  - os
    - controls which operating system the challenge image will be initialized with
  - difficulty
    - select from easy, medium, and hard to govern the difficulty of the training image produced
  - services
    - list to define which services should be required on the challenge image (ex: [ssh,apache2])
### vulns.json
  vulns.json contains all of the vulnerabilities sorted by category and difficulty.
  A vulnerability is defined by a description, a scoring command, and a provisioning command.
  
  For example:
  
  
  
    [
  
     "ssh remote root login disabled",
     
     "grep PermitRootLogin /etc/ssh/sshd_config | grep -i no",
     
     "sed -i '\/PermitRootLogin\/cPermitRootLogin yes' \/etc\/ssh\/sshd_config"
    
    ]
 
 
   
  Here, the first element of the array is the description. The second is the command to be executed to verify if the vulnerability has been removed. The third is executed upon virtual machine provisioning to plant the vulnerability on the machine.
  
  As mentioned, vulnerabilities fall into one of the several below categories listed beside their qualifications.
  - userAudit: user and administrator privileges
  - loginPolicy: policy pertaining to account login at a system level
  - securityAudit: general security audits to harden the environment
  - updates: configuring automatic, secure upgrades of the operating system and its software
  - unauthorizedSoftware: any software that is considered extraneous to the scenario. Generally hacking tools, video games, or additional media.
  - kernelAudit: kernel security configuration

Additionally, each required service that the user specifies in "prefs.json" needs its own category. Premade categories of ssh, apache2, mysql, and vsftpd already exist.

Within each category are subdifficulties. Vulnerabilities fall into a subdifficulty to ensure that the difficulty level of the image is measured and fair.

Advanced users who wish to add potential vulnerabilities to the database must edit vulns.json to effect changes
  
### config.json
  config.json should only be edited by advanced users.
  It contains weight distributions of different vulnerability categories across difficulties.
  config.json provides the unique configuration for each difficulty that can be set in prefs.json. If the difficulty chosen in prefs.json is not within config.json, it will not register and the program will exit.
  
  Each difficulty has several properties unique to its difficulty level. Below are the properties with their descriptions.
  - minUsers: minimum amount of users to be created.
  - maxUsers: maximum amount of users to be created.
  - minbound: minimum amount of vulnerabilities to be provisioned onto the image.
  - maxbound: maximum amount of vulnerabilities to be provisioned onto the image.
  - categoryWeights: dictionary of all possible vulnerability categories with percentage vulnerabilities which should fall under that category
  - difficultyWeight: dictionary of subdifficulties and what percentage of vulnerabilities should be that subdifficulty.
  
 ## Advanced Usage and Configuration
 





=====


{
	"config": {
		"services": {
					"package_name":["service_name","cmd_check_service_running", "install service command"],


		},
		"userAudit": {
					"easy": [
							["Guest account is disabled","grep allow-guest /etc/lightdm/users.conf| grep false","echo 'allow-guest=true' >> /etc/lightdm/users.conf","#"],
							["Unauthorized admin {randomUser} removed", "getent group |grep sudo | grep {randomUser}", "usermod -g sudo {randomUser}","#"],
							["Unauthorized admin {randomUser} removed", "getent group |grep sudo | grep {randomUser}", "usermod -g sudo {randomUser}","#"],
							["Unauthorized admin {randomUser} removed", "getent group |grep sudo | grep {randomUser}", "usermod -g sudo {randomUser}","#"],
							["Unauthorized admin {randomUser} removed", "getent group |grep sudo | grep {randomUser}", "usermod -g sudo {randomUser}","#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Unauthorized user {randomUsername} removed", "getent passwd | grep {randomUsername}","adduser --quiet --disabled-password --shell /bin/bash --home /home/{randomUsername} --gecos \"User\" {randomUsername};echo {randomUsername}:p4ssw0rd1| chpasswd", "#"],
							["Insecure password for {anyUser} changed","grep \"tHJ3/K\" /etc/shadow ","echo '{anyUser}:sa3tHJ3/KuYvI' | chpasswd -e","#"],
							["Insecure password for {anyUser} changed","grep \"tHJ3/K\" /etc/shadow ","echo '{anyUser}:sa3tHJ3/KuYvI' | chpasswd -e","#"]
							

							
					],
					"medium": [
							
				],
					"hard": [



							["Hidden user removed","grep 'x:0:' \/etc\/passwd | wc -l | grep -w 1", "name=$(./src/misc/evilNameGen);sed -i '10i$name:x:0:0:,,,:/:/bin/bash' /etc/passwd ","#" ],
							["Duplicate UIDs have been corrected","! awk -F: '{print $3}' /etc/passwd | sort |uniq -d","./src/initScripts/dupeVuln {mainUser}","#"]

		]
		},
		"loginPolicy": {
					"easy": [
							["Correct maximum password age set","grep PASS_MAX_DAYS \/etc\/login.defs | grep -Po \"([3-8][0-9]|90)\"","#"],
							["Correct minimum password age set","grep PASS_MIN_DAYS \/etc\/login.defs | grep -Po \"([7-9]|10)\"","#"],
							["Correct password warn age set","grep PASS_WARN_AGE /etc/login.defs | grep \"(([5-9])\"","#"]
					],
					"medium": [
							["Passwords are remembered","grep pam_unix.so /etc/pam.d/common-password |grep remember=| grep -Po \"([3-5])\" ","#"],
							["Minimun length is required for passwords","grep pam_unix.so /etc/pam.d/common-password | grep minlen= |grep -Po \"([7-9]|10)\" ","#"],
							["Password complexity enforced","grep pam_cracklib.so \/etc\/pam.d\/common-password | sed 's\/ \/\/g' |grep -E 'ucredit\\=\\-1.*lcredit\\=\\-1.*dcredit\\=\\-1.*ocredit\\=\\-1'","#"],
							["Failed login restrictions set","grep \"auth required pam_tally2.so\" /etc/pam.d/common-auth | grep deny= | grep -Po \"([3-6])\" ","#"],
							["Account unlock time set","grep \"auth required pam_tally2.so\" /etc/pam.d/common-auth | grep unlock_time= | grep -Po \"(1[0-9]{3}|2000)\"","#"]
					],
					"hard":	[
							["Secure hashing algorithm utilized", "grep -Ei \"obsucre sha512|obsucre sha256\" /etc/pam.d/common-password ","sed -i 's\/obscure sha512\/obscure md5\/g' \/etc\/pam.d\/common-password","#"],
							["Authentication required for single-user mode","grep -i password /boot/grub/grub.cfg| grep sha512","#","#"],
							["Direct login to root account has been disabled","grep root /etc/shadow | grep -E ':!:|:L:'", "echo -e \"bruh\\nbruh\" | passwd root","#"],
							["Pam-apparmor is configured","\\[ \"$(apparmor_status | grep 'are loaded'| cut -d \" \" -f1)\"  == \"$(apparmor_status | grep 'profiles are in enforce mode' | cut -d \" \" -f1)\" && $( dpkg -l | grep libpam-apparmor | cut -d\" \" -f1 |grep ii) \\] ","#","#"]
						
	
					]
		},
		"securityAudit": {
					"easy": [
							["Unauthorized media files have removed","test -e /home/{mainUser}/Music/.hidden","mkdir /home/{mainUser}/Music/.hidden; cp ./src/mediaFiles/* /home/{mainUser}/Music/.hidden","#"],
							["UFW (Uncomplicated Firewall) has been enabled","ufw status | grep \"active \"","ufw disable","#"],
							["Netcat backdoor disabled","netstat -tulpn grep \"/nc\"","./src/initScripts/netcatVuln","initScripts/netcatVuln","#"],
							["System checks for updates daily","grep Update /etc/apt/apt.conf.d/10periodic | grep 1"," sed -i 's/1/0/g' /etc/apt/apt.conf.d/10periodic","#"]
							],
					"medium": [
							["Firefox blocks dangerous downloads","grep \"user_pref(\"browser.safebrowsing.downloads.enabled\", false);\" /home/{mainUser}/.mozilla/firefox/*.defaults/pref.js","#"],
							["Insecue sudo configuration fixed ", "! grep NOPASSWD /etc/sudoers","apt -y install sudo; sed -i '\/%sudo\/c\\%sudo ALL=(ALL) NOPASSWD: ALL' \/etc\/sudoers'","#"],
							["Unauthorized banner removed","grep h4cked /etc/issue.net","./src/initScripts/bannerVuln","initScripts/bannerVuln"],
							["Perl backdoor disabled","! netstat -tulpn | grep \"/sh \"", "./src/initScripts/perlVuln", "initScripts/perlVuln"],
							["DNS spoof protection has been enabled","grep nospoof /etc/hosts.conf | grep on","#","#"],
							["Protection enabled against memory based denial of service attack","grep hard /etc/security/limits.conf| grep core | grep *","#","#"],
							["Telnet client uninstalled","! dpkg -l | grep telnet | cut -d\" \" -f1 |grep ii","apt -y install telnet","#"],
							["Trivial File Transfer Protocol server is no longer installed","! dpkg -l | grep tftp-hpa | cut -d\" \" -f1 |grep ii","apt -y install tftp-hpa,","#"],
							["The rsh-server package is no longer installed","! dpkg -l | grep rsh-server| cut -d\" \" -f1 |grep ii","apt -y install rsh-server","#"]

							
					],
					"hard":	[
							["Malicious sudoers.d file removed", "! grep NOPASSWD /etc/sudoers.d/.README","./src/initScripts/sudoVuln","initScripts/sudoVuln"],
							["Secure are permissions set for shadow "," ls -all \/etc\/shadow | grep \"\\-rw\\-r\\-\\-\\-\\-\\- 1 root\"","chmod 666 /etc/shadow; useradd r00t; chown r00t:r00t /etc/shadow","#"],
							["The PATH variable is secured","! grep \"/sbin:/bin:/usr/sbin::/usr/bin\" /root/.bashrc","echo \"/sbin:/bin:/usr/sbin::/usr/bin\" >> /root/.bashrc","#"],
							["Malicious domain redirection removed","grep -E \"irs.gov|linkedin.com|facebook.com|usa.net\" \/etc\/hosts","./src/initScrips/domainVuln","/initScripts/domianVuln"],
							["Secure permissions are enabled for /etc/profile","ls -all \/etc\/profile | grep \"\\-rwx\\-\\-\\-\\-\\-\\-\"| grep root", "chmod 666 /etc/profile; chown games:games /etc/profile","#"],
							["Secure permissions are enabled for /etc/sysctl.conf","ls -all \/etc\/sysctl.conf | grep \"\\-rwx\\-\\-\\-\\-\\-\\-\" |grep root", "chmod 666 /etc/sysctl.conf; chown games:games /etc/profile","#"],
							["Stricter defaults are enabled for shared memory","grep tmpfs /etc/fstab | grep -E 'ro.*noexec.*nosuid.*nodev'","#"],
							["Logging directory is owned by root","ls -l  /var/| grep log | grep root","chown -R games:games /var/log","#"],
							["The Fingerd package is uninstalled","! dpkg -l | grep fingerd | cut -d\" \" -f1 |grep ii","apt -y install fingerd","#"],
							["A sticky bit is set on the /tmp directory","stat -c '%a' /tmp | grep 1777","chmod -R 777 /tmp","#"],
							["System log files have the appropriate owner and permissions"," ls -la /var/log/syslog | cut -d' ' -f3 | grep syslog && stat -c '%a' /var/log/syslog | grep 640","chwon root:root /var/log/syslog; chmod 666 /var/log/syslog","#"]
							



					]
		},
		"updates": {
					"easy": [
							["Bash is upgraded","! bash --version |4.3.11(1)-release","#"],
							["Firefox is upgraded","! firefox --version | grep 65.0.1","#"],
							["LibreOffice is upgraded ","! libreoffice --version | grep 4.2.8.2","#"]
					],
					"medium": [
							["The Kernel has been upgraded","! uname -r | grep 4.4.0-142-generic",">/etc/apt/sources.list","#"],
							["Firefox is upgraded","! firefox --version | grep 65.0.1","#"],
							["LibreOffice is upgraded ","! libreoffice --version | grep 4.2.8.2","#"]


					],
					"hard":	[
					]
		},
		"unauthorizedSoftware": {
			"easy":[
				
							["Keylogger logkeys has been removed","! dpkg -l | grep logkeys | cut -d\" \" -f1 |grep ii","apt -y install logkeys","#"],
							["Gaming software oolite removed","! test -e /home/{mainUser}/Music/oolite.exe","cp ./src/software/oolite.exe /home/{mainUser}/Music/oolite.exe","software/oolite.exe"],
                          				["Password cracking software John The Ripper removed","! dpkg -l | grep  john | cut -d\" \" -f1 |grep ii","apt -y install john","#"],
                       					["Port scanning software nmap removed","! dpkg -l | grep nmap | cut -d\" \" -f1 | grep ii","apt -y install nmap","#"],
							["Generic hacking tool netcat removed","! dpkg -l | grep netcat-traditional | cut -d\" \" -f1 | grep ii","apt -y install netcat-traditional","#"]
		],
			"medium":[
                         				["Password cracking software ophcrack removed","! dpkg -l | grep ophcrack| cut -d\" \" -f1 |grep ii","apt -y install ophcrack","#"],
                 			           	["Wireless hacking tool aircrackremoved","! dpkg -l | grep aircrack-ng | cut -d\" \" -f1 |grep ii","apt -y  install aircrack-ng","#"],
                           			 	["Web application password cracker wfuzz removed","! dpkg -l | grep wfuzz | cut -d\" \" -f1 |grep ii","apt -y  install wfuzz","#"],
                         			   	["Gaming server Freeciv removed","! dpkg -l | grep freeciv-server | cut -d\" \" -f1 |grep ii","apt -y install freeciv-server","#"],
					        	["Network vulnerabilty scanner nikto removed","test -e /etc/.nikto/nikto","mkdir /etc/.nikto; cp ./src/software/nikto.exe /etc/.nikto","software/nikto.exe"],
							["Password cracking tool hydra removed","test -e /opt/.thc-hydra-master.zip","cp ./src/software/thc-hydra-master.zip /opt","software/thc-hydra-master.zip"]

				],
		      "hard": [
							["Network hacking tool yersiana removed","! whereis yersinia","apt -y install yersinia; num=$(($(perl -lne 'print $. if \/Package: yersinia\/'  \/var\/lib\/dpkg\/status | head -n1) + 1))   ; sed -i \"${num}d\" \/var\/lib\/dpkg\/status ;sed -i \"${num}i\\Status:\\ deinstall\\ ok\\ config\\-files\"  \/var\/lib\/dpkg\/status","#"],
							["Password cracking tool hashcat removed","! whereis hashcat","apt -y install hashcat; num=$(($(perl -lne 'print $. if \/Package: hashcat\/'  \/var\/lib\/dpkg\/status | head -n1) + 1))   ; sed -i \"${num}d\" \/var\/lib\/dpkg\/status ;sed -i \"${num}i\\Status:\\ deinstall\\ ok\\ config\\-files\"  \/var\/lib\/dpkg\/status","#"]

					]
		},

		"kernelAudit": {
                                        "easy": [
                                        ],
                                        "medium": [
                                                        ["Kernel ignores ICMP broadcasts","sysctl -a |grep net.ipv4.icmp_echo_ignore_broadcasts | grep 1","./src/initScripts/sysctlVuln net.ipv4.icmp_echo_ignore_broadcasts 0","#"],
                                                        ["TCP SYN protection enabled","sysctl -a |grep syncookies | grep 1","./src/initScripts/sysctlVuln net.ipv4.tcp_syncookies 0","#"]
                                        ],
                                        "hard": [
                                                        ["ASLR randomizaion enabled","sysctl -a | grep kernel.randomize_va_space| grep 2","./src/initScripts/sysctlVuln kernel.randomize_va_space 1","#"],
                                                        ["Martian packets are logged","sysctl -a | grep net.ipv4.conf.default.log_martians | grep 1","./src/initScripts/sysctlVuln net.ipv4.conf.default.log_martian 0","#"],
                                                        ["ICMP broadcasts are ignored","sysctl -a |grep net.ipv4.icmp_echo_ignore_broadcasts | grep 1","./src/initScripts/sysctlVuln net.ipv4.icmp_echo_ignore_broadcast 0","#"],
                                                        ["ICMP redirects are not accepted","sysctl -a|grep net.ipv4.conf.all.accept_redirects | grep 0","./src/initScripts/sysctlVuln net.ipv4.conf.all.accept_redirects 1","#"],
                                                        ["Netfilter denies source routed packets","sysctl -a |grep net.ipv4.conf.all.accept_source_route | grep 0","./src/initScripts/sysctlVuln net.ipv4.conf.all.accept_source_route 1","#"],
                                                        ["Reverse path filtering enabled","sysctl -a |grep net.ipv4.conf.all.rp_filter /| grep 1","./src/initScripts/sysctlVuln net.ipv4.conf.all.rp_filter 0","#"],
                                                        ["Packets are not forwarded","sysctl -a | grep 'net.ipv4.ip_forward ' | grep 0","./src/initScripts/sysctlVuln net.ipv4.ip_forward 1",#"],
                                                        ["Promiscuous networking mode disabled","! netstat -i |grep eth0 |grep P","cp ./src/misc/promisc.service /etc/systemd/system; chmod 664 /etc/systemd/system/promisc.service; systemctl enable promisc","#"]
                                        ]
                },

		"ssh": {
			"easy": [
							["SSH Root login disabled","grep PermitRootLogin /etc/ssh/sshd_config | grep -i no","sed -i '\/PermitRootLogin\/cPermitRootLogin yes' \/etc\/ssh\/sshd_config","#"]
			],
			"medium": [

							["X11 forwarding disabled ","grep X11Forwarding  /etc/ssh/sshd_config | grep -i no","sed -i '\/X11Forwarding\/cX11Forwarding  yes' \/etc\/ssh\/sshd_config","#"],
							["Empty passwords prohibted for SSH","grep PermitEmptyPasswords  /etc/ssh/sshd_config | grep -i no","sed -i '\/PermitEmptyPasswords\/cPermitEmptyPasswords  yes' \/etc\/ssh\/sshd_config","#"],
							["SSH runs on port 22","grep Port  /etc/ssh/sshd_config | grep \" 22\"", "sed -i '\/Port\/cPort  898' \/etc\/ssh\/sshd_config","#"],
							["Strict mode is enabled for ssh","grep StrictModes /etc/ssh/sshd_config | grep -i yes | grep -v \\#","sed -i 's/StrictModes/StrictModes No/g' /etc/ssh/sshd_config","#"]


			],
			"hard": [
							["Protocol 2 enabled for SSH", "grep Protocol /etc/ssh/sshd_config | grep 2"," if [ \"$(grep Protocol \/etc\/ssh\/sshd_config)\" ]; then sed -i '\/Protocol\/cProtocol 1' \/etc\/ssh\/sshd_config ; else echo \"Protocol 1\" >> \/etc\/ssh\/sshd_config; fi","#"],
							["SSH is hardened against privelege escalation","grep UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v \"#\" | grep  sandbox","sed -i '/UsePrivilegeSeparation/cUsePrivilegeSeparation no' /etc/ssh/sshd_config","#"],
							[".shost file removed","test -e /home/{mainUser}","touch /home/{mainUser}/.shosts; chmod 777 /home/{mainUser}/.shosts","#"],
							["SSH public host key files have been given secure permissions","! stat -c '%a' /etc/ssh/*.pub | grep -v 644","chmod 770 /etc/ssh/*.pub","#"],
							["Private keys for SSH secured","stat -c '%a' /home/$mainUser/.ssh/id_rsa | grep 606","ssh-keygen -b 2048 -t rsa -f /home/{mainUser}/.ssh/id_rsa -q -N \"\";chmod 707 /home/{mainUser}/.ssh/id_rsa","mainUser"],
							["SSH does not allow authentication using known hosts","grep IgnoreUserKnownHosts /etc/ssh/sshd_config | grep -i yes | grep -v \\#","sed -i 's/IgnoreUserKnownHosts/IgnoreUserKnownHosts no/g' /etc/ssh/sshd_config","#"]

			]
			},
		"apache2": {
			"easy": [
							["Directory listing disabled for webserver","! grep Indexes /etc/apache2/apache2.conf | grep -","sed -i '\/Indexes\/d' \/etc\/apache2\/apache2.conf; sed -r -i -e 's|^([[:space:]]*)<\/Directory>|\\1\\tOptions Indexes\\n\\1<\/Directory>|g' \/etc\/apache2\/apache2.conf","#"],
							["Symbolic links are not followed by webserver","! grep FollowSymLinks /etc/apache2/apache2.conf | grep -","sed -i '\/-FollowSymLinks\/d' \/etc\/apache2\/apache2.conf; sed -r -i -e 's|^([[:space:]]*)<\/Directory>|\\1\\tOptions Indexes\\n\\1<\/Directory>|g' \/etc\/apache2\/apache2.conf","#"]

					],
			"medium": [
							["Secure permissions enacted on webserver root directory","ls -ld /var/www | grep drwxr-xr-x","chmod -R 666 /var/www","#"],
							["Protection enacted against webserver fingerprinting","grep ServerSingature /etc/apache2/apache2.conf |grep -i Off && grep ServerTokens /etc/apache2/apache2.conf |grep -i Prod","sed -i '/Server/d' /etc/apache2/apache2.conf; printf \"ServerSingature On\nServerTokens OS\" >> /etc/apache2/apache2.conf","#"],
							["Webserver Override function disabled","! grep AllowOverride /etc/apache2/apache2.conf | grep All","sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf","#"]
					],
			"hard":	[
							["Unauthorized website disabled", "! netstat -tulpn |grep apache2| grep 800" ,"echo -e \"<VirtualHost *:800>\nDocumentRoot /\n</VirtualHost>\" >> /etc/apache2/sites-enabled/000-default.conf; echo Listen 800 >> /etc/apache2/ports.conf", "#"]

					]
					
					
	},
	
	"mysql": {
			"easy": [
							["Mysql remote access is disabled","grep bind-address /etc/mysql/my.cnf | grep 127.0.0.1","sed -i '/bind-address/d' /etc/mysql/my.cnf; echo bind-address=0.0.0.0 >> /etc/mysql/my.cnf","#"]
					],
			"medium": [
							["Unauthorized Mysql user removed","grep ROOT /var/lib/mysql/mysql/user.MYI","mysql -u root -ppassword -e \"CREATE USER 'ROOT'@'localhost' IDENTIFIED BY 'password';\"","#"]
			],
			
			"hard": [
							["Mysql cannot load local files","grep local-infile /etc/mysql/my.cnf | grep 0","sed -i '/local-infile/d' /etc/mysql/my.cnf; echo local-infile=1 >> /etc/mysql/my.cnf","#"],
							["Malicious Mysql database dropped"," ! test -e /var/lib/mysql/TEST", "mysql -u root -ppassword -e \"CREATE DATABASE TEST; exit;mysql -u root -ppassword TEST < ./src/misc/evilData.sql\"","#"]

			
			]



	}
}
  
}
