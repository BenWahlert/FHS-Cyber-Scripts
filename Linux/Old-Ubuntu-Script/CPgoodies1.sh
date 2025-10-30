#!/bin/sh

if [[ $EUID -ne 0 ]]
then
  echo "This script must be run as root"
  exit
fi
echo "Script is being run as root."


mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
Echo "Backups folder created on the Desktop."

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

echo "/etc/group and /etc/passwd files backed up."
mkdir /home/logs
chmod 777 /home/logs
echo "Log folder in /home/logs folder"
echo "---------Updating Using Apt-Get----------------"
{
    
	apt update --no-allow-insecure-repositories
	apt update && apt upgrade -y
	apt full-upgrade -y
	apt install -f -y
	apt autoremove -y
	apt autoclean -y
	apt check
	find /etc/apt -type f -name '*.list' -exec sed -i 's/^#\(deb.*-backports.*\)/\1/; s/^#\(deb.*-updates.*\)/\1/; s/^#\(deb.*-proposed.*\)/\1/; s/^#\(deb.*-security.*\)/\1/' {} +
}



echo "--------- Deleting Dangerous Files ----------------"
{
    
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
	sudo apt-get --purge remove cups -y
	sudo apt-get --purge remove nmap -y
	sudo apt-get --purge remove zenmap -y
	sudo apt-get --purge remove wireshark -y
	sudo apt-get --purge remove hashcat -y
	sudo apt-get --purge remove netcat -y
	sudo apt-get --purge remove netcat-openbsd -y
	sudo apt-get --purge remove ncat
	sudo apt-get --purge remove pnetcat
	sudo apt-get --purge remove socat
	sudo apt-get --purge remove sock
	sudo apt-get --purge remove scoket
	sudo apt-get --purge remove sbd
	sudo apt-get --purge remove john -y
	sudo apt-get --purge remove john-data -y
	sudo apt-get --purge remove hydra -y
	sudo apt-get --purge remove hydra-gtk -y
	sudo apt-get --purge remove aircrack-ng -y
	sudo apt-get --purge remove fcrackzip
	sudo apt-get --purge remove lcrack
	sudo apt-get --purge remove ophcrack
	sudo apt-get --purge remove ophcrack-cli
	sudo apt-get --purge remove pdfcrack
	sudo apt-get --purge remove pyrit
	sudo apt-get --purge remove rarcrack
	sudo apt-get --purge remove sipcrack
	sudo apt-get --purge remove irpas
	sudo apt-get --purge remove logkeys
	sudo apt-get --purge remove zeitgeist
	sudo apt-get --purge remove nfs-kernel-server
	sudo apt-get --purge remove nfs-common
	sudo apt-get --purge remove portmap
	sudo apt-get --purge remove rpcbind
	sudo apt-get --purge remove autofs
	sudo apt-get --purge remove nginx
	sudo apt-get --purge remove nginx-common
	sudo apt-get --purge remove inetd
	sudo apt-get --purge remove openbsd-inetd
	sudo apt-get --purge remove xinetd
	sudo apt-get --purge remove inetutils*
	sudo apt-get --purge remove vnc4server
	sudo apt-get --purge remove vncsnapshot
	sudo apt-get --purge remove vtgrab
	sudo apt-get --purge remove snmp
	sudo apt-get --purge remove pure-ftpd
	sudo apt-get --purge remove vsftpd
	sudo apt-get --purge remove burpsuite -y
	sudo apt-get --purge remove cewl -y
	sudo apt-get --purge remove cdpsnarf -y
	sudo apt-get --purge remove bed -y
	sudo apt-get --purge remove 0trace -y
	sudo apt-get --purge remove ace-voip -y
	sudo apt-get --purge remove armitage -y
	sudo apt-get --purge remove beeef-xss -y
	sudo apt-get --purge remove bdfproxy -y
	sudo apt-get --purge remove blindelephant -y
	sudo apt-get --purge remove bluelog -y
	sudo apt-get --purge remove blueranger -y
	sudo apt-get --purge remove bluesnarfer -y
	sudo apt-get --purge remove 0trace -y
	sudo apt-get --purge remove ace-voip -y
	sudo apt-get --purge remove amap -y
	sudo apt-get --purge remove apache-users -y
	sudo apt-get --purge remove armitage -y
	sudo apt-get --purge remove asleap -y
	sudo apt-get --purge remove automater -y
	sudo apt-get --purge remove bdfproxy -y
	sudo apt-get --purge remove bed -y
	sudo apt-get --purge remove beef-xss -y
	sudo apt-get --purge remove blindelephant -y
	sudo apt-get --purge remove bluelog -y
	sudo apt-get --purge remove blueranger -y
	sudo apt-get --purge remove bluesnarfer -y
	sudo apt-get --purge remove bulk-extractor -y
	sudo apt-get --purge remove bully -y
	sudo apt-get --purge remove burpsuite -y
	sudo apt-get --purge remove cdpsnarf -y
	sudo apt-get --purge remove cherrytree -y
	sudo apt-get --purge remove cisco-auditing-tool -y
	sudo apt-get --purge remove cisco-global-exploiter -y
	sudo apt-get --purge remove cisco-ocs -y
	sudo apt-get --purge remove cisco-torch -y
	sudo apt-get --purge remove clusterd -y
	sudo apt-get --purge remove cmospwd -y
	sudo apt-get --purge remove commix -y
	sudo apt-get --purge remove copy-router-config -y
	sudo apt-get --purge remove creddump -y
	sudo apt-get --purge remove cryptcat -y
	sudo apt-get --purge remove cryptsetup -y
	sudo apt-get --purge remove cryptsetup-bin -y
	sudo apt-get --purge remove cryptsetup-initramfs -y
	sudo apt-get --purge remove cryptsetup-run -y
	sudo apt-get --purge remove cymothoa -y
	sudo apt-get --purge remove davtest -y
	sudo apt-get --purge remove dbd -y
	sudo apt-get --purge remove ddrescue -y
	sudo apt-get --purge remove deblaze -y
	sudo apt-get --purge remove desktop-base -y
	sudo apt-get --purge remove dex2jar -y
	sudo apt-get --purge remove dirbuster -y
	sudo apt-get --purge remove dmitry -y
	sudo apt-get --purge remove dnmap -y
	sudo apt-get --purge remove dnschef -y
	sudo apt-get --purge remove dotdotpwn -y
	sudo apt-get --purge remove dpkg -y
	sudo apt-get --purge remove dpkg-dev -y
	sudo apt-get --purge remove dradis -y
	sudo apt-get --purge remove dumpzilla -y
	sudo apt-get --purge remove eapmd5pass -y
	sudo apt-get --purge remove edb-debugger -y
	sudo apt-get --purge remove edb-debugger-plugins:amd64 -y
	sudo apt-get --purge remove enum4linux -y
	sudo apt-get --purge remove enumiax -y
	sudo apt-get --purge remove exe2hexbat -y
	sudo apt-get --purge remove exploitdb -y
	sudo apt-get --purge remove faraday -y
	sudo apt-get --purge remove fern-wifi-cracker -y
	sudo apt-get --purge remove fierce -y
	sudo apt-get --purge remove fiked -y
	sudo apt-get --purge remove fimap -y
	sudo apt-get --purge remove findmyhash -y
	sudo apt-get --purge remove fragroute -y
	sudo apt-get --purge remove fragrouter -y
	sudo apt-get --purge remove framework2 -y
	sudo apt-get --purge remove ftester -y
	sudo apt-get --purge remove giskismet -y
	sudo apt-get --purge remove gnome-shell-extension-proxyswitcher -y
	sudo apt-get --purge remove gnome-shell-extensions -y
	sudo apt-get --purge remove gnome-theme-kali -y
	sudo apt-get --purge remove gpp-decrypt -y
	sudo apt-get --purge remove grabber -y
	sudo apt-get --purge remove hamster-sidejack -y
	sudo apt-get --purge remove hash-identifier -y
	sudo apt-get --purge remove hashcat-utils -y
	sudo apt-get --purge remove hexinject -y
	sudo apt-get --purge remove hotpatch -y
	sudo apt-get --purge remove hyperion -y
	sudo apt-get --purge remove iaxflood -y
	sudo apt-get --purge remove init -y
	sudo apt-get --purge remove init-system-helpers -y
	sudo apt-get --purge remove intersect -y
	sudo apt-get --purge remove intrace -y
	sudo apt-get --purge remove inviteflood -y
	sudo apt-get --purge remove jad -y
	sudo apt-get --purge remove javasnoop -y
	sudo apt-get --purge remove jboss-autopwn -y
	sudo apt-get --purge remove john -y
	sudo apt-get --purge remove john-data -y
	sudo apt-get --purge remove johnny -y
	sudo apt-get --purge remove joomscan -y
	sudo apt-get --purge remove jsql-injection -y
	sudo apt-get --purge remove kali-archive-keyring -y
	sudo apt-get --purge remove kali-debtags -y
	sudo apt-get --purge remove kali-defaults -y
	sudo apt-get --purge remove kali-desktop-base -y
	sudo apt-get --purge remove kali-desktop-common -y
	sudo apt-get --purge remove kali-desktop-core -y
	sudo apt-get --purge remove kali-desktop-live -y
	sudo apt-get --purge remove kali-grant-root -y
	sudo apt-get --purge remove kali-linux -y
	sudo apt-get --purge remove kali-menu -y
	sudo apt-get --purge remove kali-root-login -y
	sudo apt-get --purge remove kali-themes -y
	sudo apt-get --purge remove kali-themes-common -y
	sudo apt-get --purge remove killerbee -y
	sudo apt-get --purge remove king-phisher -y
	sudo apt-get --purge remove kismet -y
	sudo apt-get --purge remove kismet-capture-common -y
	sudo apt-get --purge remove kismet-capture-linux-bluetooth -y
	sudo apt-get --purge remove kismet-capture-linux-wifi -y
	sudo apt-get --purge remove kismet-capture-nrf-51822 -y
	sudo apt-get --purge remove kismet-capture-nrf-mousejack -y
	sudo apt-get --purge remove kismet-capture-nxp-kw41z -y
	sudo apt-get --purge remove kismet-capture-ti-cc-2531 -y
	sudo apt-get --purge remove kismet-capture-ti-cc-2540 -y
	sudo apt-get --purge remove kismet-core -y
	sudo apt-get --purge remove kismet-logtools -y
	sudo apt-get --purge remove laudanum -y
	sudo apt-get --purge remove lbd -y
	sudo apt-get --purge remove libcryptsetup12:amd64 -y
	sudo apt-get --purge remove libdpkg-perl -y
	sudo apt-get --purge remove libfindrtp -y
	sudo apt-get --purge remove netdiscover -y
	sudo apt-get --purge remove p0f -y
	sudo apt-get --purge remove recon-ng -y
	sudo apt-get --purge remove unix-privesc-check -y
	sudo apt-get --purge remove maltego -y
	sudo apt-get --purge remove maltego-teeth -y
	sudo apt-get --purge remove metasploit-framework -y
	sudo apt-get --purge remove mfterm -y
	sudo apt-get --purge remove mimikatz -y
	sudo apt-get --purge remove miranda -y
	sudo apt-get --purge remove msfpc -y
	sudo apt-get --purge remove multimac -y
	sudo apt-get --purge remove nautilus-extension-gnome-terminal -y
	sudo apt-get --purge remove ncat-w32 -y
	sudo apt-get --purge remove ndiff -y
	sudo apt-get --purge remove nfspy -y
	sudo apt-get --purge remove nikto -y
	sudo apt-get --purge remove nipper-ng -y
	sudo apt-get --purge remove nishang -y
	sudo apt-get --purge remove nmap -y
	sudo apt-get --purge remove nmap-common -y
	sudo apt-get --purge remove ohrwurm -y
	sudo apt-get --purge remove ollydbg -y
	sudo apt-get --purge remove oscanner -y
	sudo apt-get --purge remove pack -y
	sudo apt-get --purge remove padbuster -y
	sudo apt-get --purge remove paros -y
	sudo apt-get --purge remove pdf-parser -y
	sudo apt-get --purge remove pdfid -y
	sudo apt-get --purge remove pdgmail -y
	sudo apt-get --purge remove perl-cisco-copyconfig -y
	sudo apt-get --purge remove pipal -y
	sudo apt-get --purge remove plecost -y
	sudo apt-get --purge remove powerfuzzer -y
	sudo apt-get --purge remove powersploit -y
	sudo apt-get --purge remove protos-sip -y
	sudo apt-get --purge remove pwnat -y
	sudo apt-get --purge remove ike-scan -y
	sudo apt-get --purge remove python-faraday -y
	sudo apt-get --purge remove python-filedepot -y
	sudo apt-get --purge remove python-flask-classful -y
	sudo apt-get --purge remove python-flask-login -y
	sudo apt-get --purge remove python-flask-mail -y
	sudo apt-get --purge remove python-flask-restless -y
	sudo apt-get --purge remove python-flask-session -y
	sudo apt-get --purge remove python-ipaddress -y
	sudo apt-get --purge remove python-ldap3 -y
	sudo apt-get --purge remove python-ldapdomaindump -y
	sudo apt-get --purge remove python-marshmallow -y
	sudo apt-get --purge remove python-marshmallow-sqlalchemy -y
	sudo apt-get --purge remove python-nplusone -y
	sudo apt-get --purge remove python-peepdf -y
	sudo apt-get --purge remove python-pylibemu -y
	sudo apt-get --purge remove python-pyv8 -y
	sudo apt-get --purge remove python-rfidiot -y
	sudo apt-get --purge remove python-speaklater -y
	sudo apt-get --purge remove python-sqlalchemy-schemadisplay -y
	sudo apt-get --purge remove python-webencodings -y
	sudo apt-get --purge remove python3-advancedhttpserver -y
	sudo apt-get --purge remove python3-email-validator -y
	sudo apt-get --purge remove python3-faraday-plugins -y
	sudo apt-get --purge remove python3-filedepot -y
	sudo apt-get --purge remove python3-filteralchemy -y
	sudo apt-get --purge remove python3-flask-classful -y
	sudo apt-get --purge remove python3-flask-kvsession -y
	sudo apt-get --purge remove python3-flask-mail -y
	sudo apt-get --purge remove python3-flask-restless -y
	sudo apt-get --purge remove python3-flask-security -y
	sudo apt-get --purge remove python3-flask-session -y
	sudo apt-get --purge remove python3-flask-sqlalchemy -y
	sudo apt-get --purge remove python3-graphene -y
	sudo apt-get --purge remove python3-graphene-sqlalchemy -y
	sudo apt-get --purge remove python3-graphql-core -y
	sudo apt-get --purge remove python3-graphql-relay -y
	sudo apt-get --purge remove python3-grequests -y
	sudo apt-get --purge remove python3-kismetcapturefreaklabszigbee -y
	sudo apt-get --purge remove python3-kismetcapturertl433 -y
	sudo apt-get --purge remove python3-kismetcapturertladsb -y
	sudo apt-get --purge remove python3-kismetcapturertlamr -y
	sudo apt-get --purge remove python3-magic-ahupp -y
	sudo apt-get --purge remove python3-nassl -y
	sudo apt-get --purge remove python3-nplusone -y
	sudo apt-get --purge remove python3-pcapfile -y
	sudo apt-get --purge remove python3-pip -y
	sudo apt-get --purge remove python3-promise -y
	sudo apt-get --purge remove python3-rule-engine -y
	sudo apt-get --purge remove python3-rx -y
	sudo apt-get --purge remove python3-simplekv -y
	sudo apt-get --purge remove python3-speaklater -y
	sudo apt-get --purge remove python3-sqlalchemy-schemadisplay -y
	sudo apt-get --purge remove python3-syslog-rfc5424-formatter -y
	sudo apt-get --purge remove python3-tls-parser -y
	sudo apt-get --purge remove python3-webargs -y
	sudo apt-get --purge remove python3-webencodings -y
	sudo apt-get --purge remove rainbowcrack -y
	sudo apt-get --purge remove rcracki-mt -y
	sudo apt-get --purge remove reaver -y
	sudo apt-get --purge remove rebind -y
	sudo apt-get --purge remove redfang -y
	sudo apt-get --purge remove regripper -y
	sudo apt-get --purge remove responder -y
	sudo apt-get --purge remove rsmangler -y
	sudo apt-get --purge remove rtpbreak -y
	sudo apt-get --purge remove rtpflood -y
	sudo apt-get --purge remove rtpinsertsound -y
	sudo apt-get --purge remove rtpmixsound -y
	sudo apt-get --purge remove ruby-cms-scanner -y
	sudo apt-get --purge remove ruby-dm-core -y
	sudo apt-get --purge remove ruby-dm-do-adapter -y
	sudo apt-get --purge remove ruby-dm-migrations -y
	sudo apt-get --purge remove ruby-dm-sqlite-adapter -y
	sudo apt-get --purge remove ruby-espeak -y
	sudo apt-get --purge remove ruby-librex -y
	sudo apt-get --purge remove ruby-maxmind-db -y
	sudo apt-get --purge remove ruby-opt-parse-validator -y
	sudo apt-get --purge remove ruby-public-suffix -y
	sudo apt-get --purge remove sakis3g -y
	sudo apt-get --purge remove sbd -y
	sudo apt-get --purge remove sctpscan -y
	sudo apt-get --purge remove set -y
	sudo apt-get --purge remove sfuzz -y
	sudo apt-get --purge remove sidguesser -y
	sudo apt-get --purge remove siparmyknife -y
	sudo apt-get --purge remove sipp -y
	sudo apt-get --purge remove skipfish -y
	sudo apt-get --purge remove smali -y
	sudo apt-get --purge remove smtp-user-enum -y
	sudo apt-get --purge remove sniffjoke -y
	sudo apt-get --purge remove snmpcheck -y
	sudo apt-get --purge remove sparta -y
	sudo apt-get --purge remove spike -y
	sudo apt-get --purge remove spooftooph -y
	sudo apt-get --purge remove sqldict -y
	sudo apt-get --purge remove sqlninja -y
	sudo apt-get --purge remove sqlsus -y
	sudo apt-get --purge remove sslcaudit -y
	sudo apt-get --purge remove sslscan -y
	sudo apt-get --purge remove sslstrip -y
	sudo apt-get --purge remove sslyze -y
	sudo apt-get --purge remove tasksel -y
	sudo apt-get --purge remove tasksel-data -y
	sudo apt-get --purge remove tftpd32 -y
	sudo apt-get --purge remove thc-pptp-bruter -y
	sudo apt-get --purge remove thc-ssl-dos -y
	sudo apt-get --purge remove theharvester -y
	sudo apt-get --purge remove tlssled -y
	sudo apt-get --purge remove tnscmd10g -y
	sudo apt-get --purge remove truecrack -y
	sudo apt-get --purge remove twofi -y
	sudo apt-get --purge remove u3-pwn -y
	sudo apt-get --purge remove ua-tester -y
	sudo apt-get --purge remove unicorn-magic -y
	sudo apt-get --purge remove unicornscan -y
	sudo apt-get --purge remove uniscan -y
	sudo apt-get --purge remove unix-privesc-check -y
	sudo apt-get --purge remove urlcrazy -y
	sudo apt-get --purge remove veil -y
	sudo apt-get --purge remove voiphopper -y
	sudo apt-get --purge remove volafox -y
	sudo apt-get --purge remove wce -y
	sudo apt-get --purge remove webacoo -y
	sudo apt-get --purge remove webscarab -y
	sudo apt-get --purge remove webshells -y
	sudo apt-get --purge remove wifi-honey -y
	sudo apt-get --purge remove wifitap -y
	sudo apt-get --purge remove winexe -y
	sudo apt-get --purge remove wordlists -y
	sudo apt-get --purge remove wpscan -y
	sudo apt-get --purge remove xspy -y
	sudo apt-get --purge remove xsser -y
	sudo apt-get --purge remove zaproxy -y
	sudo apt-get --purge remove zenmap -y
	sudo apt-get --purge remove httrack -y
	sudo apt-get --purge remove sqlmap -y
	sudo apt-get --purge remove bbqsql -y
	sudo apt-get --purge remove crunch -y
	sudo apt-get --purge remove medusa -y
	sudo apt-get --purge remove ncrack -y
	sudo apt-get --purge remove ophcrack -y
	sudo apt-get --purge remove pyrit -y
	sudo apt-get --purge remove ophcrack-cli -y
	sudo apt-get --purge remove aircrack-ng -y
	sudo apt-get --purge remove chirp -y
	sudo apt-get --purge remove cowpatty -y
	sudo apt-get --purge remove mdk3 -y
	sudo apt-get --purge remove mfoc -y
	sudo apt-get --purge remove pixiewps -y
	sudo apt-get --purge remove wifite -y
	sudo apt-get --purge remove dirb -y
	sudo apt-get --purge remove dnsmap -y
	sudo apt-get --purge remove patator -y
	sudo apt-get --purge remove sucrack -y
	sudo apt-get --purge remove wfuzz -y
	sudo apt-get --purge remove apktool -y
	sudo apt-get --purge remove sslsniff -y
	sudo apt-get --purge remove ruby-msfprc-client -y
	sudo apt-get --purge remove nbtscan -y
	sudo apt-get --purge remove tracker -y
	sudo apt-get --purge remove termineter -y
	sudo apt-get --purge remove tracker-extract -y
	sudo apt-get --purge remove tracker-miner-fs -y
	sudo apt-get --purge remove driftnet -y
	sudo apt-get --purge remove ettercap-common -y
	sudo apt-get --purge remove dsniff -y
	sudo apt-get --purge remove macchanger -y
	sudo apt-get --purge remove mitmproxy -y
	sudo apt-get --purge remove netsniff-ng -y
	sudo apt-get --purge remove wireshark -y
	sudo apt-get --purge remove ettercap-graphical -y
	sudo apt-get --purge remove python-scapy -y
	sudo apt-get --purge remove python3-scapy -y
	sudo apt-get --purge remove tcpick -y
	sudo apt-get --purge remove wireshark-common -y
	sudo apt-get --purge remove wireshark-qt -y
	sudo apt-get --purge remove backdoor-factory -y
	sudo apt-get --purge remove cutycapt -y
	sudo apt-get --purge remove weevely -y
	sudo apt-get --purge remove lkl -y
	sudo apt-get --purge remove uberkey -y
	sudo apt-get --purge remove THC-vlogger -y
	sudo apt-get --purge remove PyKeylogger -y
	sudo apt-get --purge remove logkeys -y
	sudo apt-get --purge remove aisleriot gnome-mahjongg gnome-mines gnome-sudoku -y 
	sudo apt autoremove
	sudo apt autoclean
	
	cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
	

	printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
	printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
	cat /tmp/777s
	
}
echo "Protecting against SYN flood attacks"
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/10-network-security.conf

echo "Disabling ctrl-alt-delete"
systemctl mask ctrl-alt-del.target
systemctl daemon-reload

echo "Converting to use /etc/shadow"
pwconv

echo "---------Download rootkit and anti-virus programs----------------"
{
	apt install -y chkrootkit 
	apt install -y rkhunter
	apt --fix-broken install
	apt install debsums -y
	apt install apt-show-versions -y
    

	echo
	echo "Starting RKHunter scan"
	RKHUNTERCONF='/etc/default/rkhunter'
	RKCONF='/etc/rkhunter.conf'
	sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' "$RKHUNTERCONF"
  	sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="yes"/' "$RKHUNTERCONF"
	sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' "$RKCONF"
	sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' "$RKCONF"
	sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' "$RKCONF"
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	cp /var/log/rkhunter.log /home/logs/
	chmod 777 /home/logs/rkhunter.log

	echo "Starting chkrootkit scan"
	chkrootkit -q

	echo "Checking md5 checksums"
	debsums -ags

	echo "Showing upgradeable packages"
	apt-show-versions -u

	#echo "ClamAV scan is currently running"
	#apt-get install clamav clamav-daemon -y -qq
	#systemctl stop clamav-freshclam
	#freshclam
	#sudo wget https://database.clamav.net/daily.cvd
	#cp daily.cvd /var/lib/clamav/
	#systemctl start clamav-freshclam
	#touch ~/clamavscan.log
	#clamscan -riv --bell --remove / >> ~/clamavscan.log
	#cp ~/clamavscan.log /home/logs
	#chmod 777 /home/logs/clamavscan.log
    	
	
}
