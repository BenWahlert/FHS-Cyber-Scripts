#!/bin/sh

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C80E383C3DE9F082E01391A0366C67DE91CA5D5F
sudo apt install apt-transport-https -y
echo 'Acquire::Languages "none";' | sudo tee /etc/apt/apt.conf.d/99disable-translations
echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
apt install debsums -y
apt install apt-show-versions -y
apt install lynis -y
apt update
apt upgrade -y
lynis update release
lynis audit system
