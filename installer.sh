#!/bin/bash
#---------------------------------------
txtund=$(tput sgr 0 1)
txtbld=$(tput bold)
green=$(tput setaf 2)
bldred=${txtbld}$(tput setaf 1)
red_color=$(tput setaf 1)
color_y=$(tput setaf 3)
bldblu=${txtbld}$(tput setaf 4)
bldwht=${txtbld}$(tput setaf 7)
txtrst=$(tput sgr0)
#---------------------------------------
requeries=true
func_Banner(){
	clear
	echo '   ============================='
	echo "   |$bldblu wifi-pumpkin Installer$txtrst|"
	echo '   ============================='
	echo "          Version: $(tput setaf 5)0.8.5 $txtrst"
	echo "usage: ./installer.sh --install | --uninstall"
}


usage(){
	echo "usage: ./installer.sh --install | --uninstall"
}

func_check_install(){
	if which $1 >/dev/null; then
		echo "----[$green✔$txtrst]----[$green+$txtrst] $1 Installed"
	else
		echo "----[$red_color✘$txtrst]----[$red_color-$txtrst] $1 not Installed "
		nome="$1"
		requeries=$nome
	fi
}

function program_is_installed {
	local return_=1
	type $1 >/dev/null 2>&1 || { local return_=0; }
	echo "$return_"
}

func_install(){
	func_Banner
	if [ "$(id -u)" != "0" ]; then
		echo -e "$(tput setaf 6)[-] This script must be run as root$(tput sgr0)" 1>&2
		exit 1
	fi
	apt-get update
	apt-get install -y python-pip libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
	apt-get install -y libarchive-dev
	apt-get install -y build-essential libnetfilter-queue-dev
	apt-get install -y python-qt4 python-scapy hostapd rfkill
	apt-get install -y python-dev git
	apt-get install -y libpcap-dev
	dist=$(tr -s ' \011' '\012' < /etc/issue | head -n 1)
    if [ "$dist" = "Kali" ]; then
        apt-get install libssl1.0
    fi
	pip install -r requirements.txt
	pip install mitmproxy==0.18.2
	echo "----------------------------------------"
	echo "[=]$bldblu checking dependencies $txtrst "
	func_check_install "hostapd"
	echo "----------------------------------------"
	dist=$(tr -s ' \011' '\012' < /etc/issue | head -n 1)
	check_arch=$(uname -m)
	echo "[$green+$txtrst] Distribution Name: $dist"
	echo "----------------------------------------"
    if [ "$dist" = "Ubuntu" ]; then
        apt-get install libjpeg8-dev -y
    fi
	echo "[=] $bldblu Install WiFi-Pumpkin $txtrst"
	if [ -d "$DIRECTORY" ]; then
		rm -r $DIRECTORY
	fi
	mkdir $DIRECTORY
	cp -r $path_install /usr/share/WiFi-Pumpkin/
	bin_install
	echo "[$green✔$txtrst] wifi-pumpkin installed with success"
	echo "[$green✔$txtrst] execute $bldred sudo wifi-pumpkin$txtrst in terminal"
	echo "[$green+$txtrst]$color_y P0cL4bs Team CopyRight 2015-2017$txtrst"
	echo "[$green+$txtrst] Enjoy"
	exit 0
}

bin_install(){
    echo "[$green✔$txtrst] binary::/usr/bin/"
    if which update-alternatives >/dev/null; then
        update-alternatives --install /usr/bin/wifi-pumpkin wifi-pumpkin /usr/share/WiFi-Pumpkin/wifi-pumpkin 1 > /dev/null
    else
        ln -sfT /usr/share/WiFi-Pumpkin/wifi-pumpkin /usr/bin/wifi-pumpkin
    fi
    cp wifi-pumpkin.desktop /usr/share/applications/wifi-pumpkin.desktop
    chmod +x /usr/share/WiFi-Pumpkin/wifi-pumpkin
}

uninstall(){
	if [ "$(id -u)" != "0" ]; then
		echo -e "$(tput setaf 6)[-] This script must be run as root$(tput sgr0)" 1>&2
		exit 1
	fi
	if [  -d "$DIRECTORY" ]; then
            if which update-alternatives >/dev/null; then
                update-alternatives --remove wifi-pumpkin /usr/share/WiFi-Pumpkin/wifi-pumpkin > /dev/null
            else
                rm /usr/bin/wifi-pumpkin
            fi
            rm /usr/share/applications/wifi-pumpkin.desktop
	    echo "[$red_color-$txtrst] Deleted Binary:$bldwht/usr/bin/wifi-pumpkin $txtrst"
            echo "[$red_color-$txtrst] Delete Path:$bldwht $DIRECTORY $txtrst"
	    rm -r $path_uninstall
	else
	    echo "[$red_color✘$txtrst] wifi-pumpkin is not Installed"
	fi
}
func_Banner
DIRECTORY="/usr/share/WiFi-Pumpkin"
Dir_isntall=$(pwd)
path_install=$Dir_isntall"/*"
path_uninstall=$DIRECTORY"/"
while [ "$1" != "" ]; do
    case $1 in
        --install ) shift
        func_install
        ;;
        --uninstall ) uninstall
        ;;
        -h | --help ) usage
        exit
        ;;
        * ) usage
        exit 1
    esac
    shift
done
