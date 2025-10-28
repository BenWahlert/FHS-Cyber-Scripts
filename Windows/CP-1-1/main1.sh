#!/usr/bin/env bash
###
# # (From Bash)
# source <(curl -fsSL https://github.com/wen012235/CP/blob/main/main.sh)
###

if [ "$EUID" -ne 0 ] ;
       then echo "Run as Root"
       exit
fi


sudo apt update
sudo apt install -y git
mkdir -p ~/tmp/cp
cd ~/tmp/cp
UFWDEFAULT='/etc/default/ufw'
if ! test -f "$UFWDEFAULT"; then
    echo "$UFWDEFAULT does not exist."

    if ! dpkg -l | grep ufw 2> /dev/null 1>&2; then
      echo 'ufw package is not installed.'
    fi

    return
  fi

  sed -i 's/IPT_SYSCTL=.*/IPT_SYSCTL=\/etc\/sysctl\.conf/' "$UFWDEFAULT"
  ufw --force enable



git clone https://github.com/wen012235/CP.git
echo "Would you like some CP Goodness?********removing mp3 and other files, removing bad programs, removing guest users, running rkhunter, and chrootkit******"
        select yn in "Yes" "No"; do
            case $yn in
                Yes )#bash ~/tmp/cp/CP/debloat.sh
		bash ~/tmp/cp/CP/CPgoodies1.sh
	chmod 777 /etc/security/pwquality.conf
	rm -f /etc/security/pwquality.conf
	cp -f ~/tmp/cp/CP/pwquality.conf /etc/security/pwquality.conf 
	chmod 777 /etc/pam.d/common-password
	rm -f /etc/pam.d/common-password
	cp -f ~/tmp/cp/CP/common-password /etc/pam.d/common-password
	#echo 'minclass=4' >> /etc/security/pwquality.conf
	chmod 644 /etc/security/pwquality.conf
	chmod 644 /etc/pam.d/common-password
	cp -f ~/tmp/cp/CP/mozilla.cfg /usr/lib/firefox/mozilla.cfg 
	chmod 644 /usr/lib/firefox/mozilla.cfg
	cp -f ~/tmp/cp/CP/autoconfig.js /usr/lib/firefox/defaults/pref/autoconfig.js 
	chmod 644 /usr/lib/firefox/defaults/pref/autoconfig.js; break;;
	        No ) echo "ok"; break;;
            esac
        done

echo "###############################"
echo "####CP Goodness is complete####"
echo "###############################"

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


elif [[ $(lsb_release -rs) == "20.04" ]]; then
	echo "Press 3 for a standard harden and 4 for a full harden"
	bash ~/tmp/cp/CP/ubuntu20/UBUNTU2004_LBK.sh
echo "done with Ubuntu 20 hardening"
fi


echo "Make sure to check the rootkit and antivirus logs!  Are you ready to reboot for all updates to take place?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) reboot; break;;
                No ) echo "When you have finished checking the logs and are ready to reboot, make sure to type 'sudo reboot' into the terminal window"; break;;
            esac
        done
