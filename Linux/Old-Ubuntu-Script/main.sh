#!/usr/bin/env bash
###
# # (From Bash)
# source <(curl -fsSL https://github.com/BenWahlert/FHS-Cyber-Scripts/main/main.sh)
###

if [ "$EUID" -ne 0 ] ;
       then echo "Run as Root"
       exit
fi


sudo apt update
sudo apt install -y git
mkdir -p ~/tmp/cp
cd ~/tmp/cp || exit



#git clone https://github.com/wen012235/CP.git

#!/usr/bin/env bash
if [[ $(lsb_release -rs) == "16.04" ]]; then
	echo "Press 1 for a standard harden and 2 for a full harden"
        select yn in "1" "2"; do
            case $yn in
                1 ) bash ~/tmp/cp/CP/ubuntu16/cis-hardening/Canonical_Ubuntu_16.04_CIS_v1.1.0-harden.sh lvl1_workstation; break;;
                2 ) bash ~/tmp/cp/CP/ubuntu16/cis-hardening/Canonical_Ubuntu_16.04_CIS_v1.1.0-harden.sh lvl2_workstation; break;;
        
	
		
	    esac
        done
echo "done with Ubuntu 16 hardening"


elif [[ $(lsb_release -rs) == "18.04" ]]; then
	echo "Press 1 for a standard harden and 2 for a full harden"
	select yn in "1" "2"; do
	    case $yn in
		1 ) bash ~/tmp/cp/CP/ubuntu18/ubuntu-scap-security-guides/cis-hardening/Canonical_Ubuntu_18.04_CIS_v1.0.0-harden.sh lvl1_workstation; break;;
		2 ) bash ~/tmp/cp/CP/ubuntu18/ubuntu-scap-security-guides/cis-hardening/Canonical_Ubuntu_18.04_CIS_v1.0.0-harden.sh lvl2_workstation; break;;
	    esac
	done
echo "done with Ubuntu 18 hardening"
fi
echo "Would you like some CP Goodness?********removing mp3 and other files, removing bad programs, removing guest users, running rkhunter, and chrootkit******"
        select yn in "Yes" "No"; do
            case $yn in
                Yes )bash ~/tmp/cp/CP/CPgoodies1.sh
	#chmod 777 /etc/security/pwquality.conf
	#cp -f ~/tmp/cp/CP/pwquality.conf /etc/security/pwquality.conf 
	#echo 'minclass=4' >> /etc/security/pwquality.conf
	#chmod 644 /etc/security/pwquality.conf
                firefox_root="/usr/lib/firefox"
                if [ -d "$firefox_root" ]; then
                    install -m 644 ~/tmp/cp/CP/mozilla.cfg "$firefox_root/mozilla.cfg"
                    install -D -m 644 ~/tmp/cp/CP/autoconfig.js "$firefox_root/defaults/pref/autoconfig.js"
                else
                    echo "Firefox not found at $firefox_root; skipping Firefox configuration copy."
                fi
                break;;
	        No ) echo "ok"; break;;
            esac
        done

echo "###############################"
echo "####CP Goodness is complete####"
echo "###############################"


echo "Make sure to check the rootkit and antivirus logs!  Are you ready to reboot for all updates to take place?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) reboot; break;;
                No ) echo "When you have finished checking the logs and are ready to reboot, make sure to type 'sudo reboot' into the terminal window"; break;;
            esac
        done
