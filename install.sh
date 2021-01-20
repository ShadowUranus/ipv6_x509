#!/bin/bash
echo "#####################################"
echo "#  X.509数字证书合规性检测系统安装  #"
echo "#####################################"
echo "检测Python版本...."
if [ `python3 -c "import sys;print(sys.version_info>=(3,8) and sys.version_info<(3,9))"` == "True" ]
then
	echo "OK"
else 
	echo "系统需Python3.8环境，请先自行安装"
	exit 1
fi
echo "安装pip3...."
if [ -f /etc/redhat-release ]; then
    echo "Redhat Linux detected."
    sudo yum install python3-pip vim nmap -y
elif [ -f /etc/SuSE-release ]; then
    echo "Suse Linux detected."
    sudo zypper install python3-pip vim nmap
elif [ -f /etc/arch-release ]; then
    echo "Arch Linux detected."
    sudo pacman -Sy
    sudo pacman -S python3-pip vim nmap
elif [ -f /etc/mandrake-release ]; then
    echo "Mandrake Linux detected."
elif [ -f /etc/debian_version ]; then
    echo "Ubuntu/Debian Linux detected."
    sudo apt update
    sudo apt install python3-pip vim nmap -y
else
    echo "Unknown Linux distribution."
fi
echo "安装pipenv...."
pip3 install pipenv
echo "安装程序虚拟环境...."
pipenv install
echo "安装完成！请执行bash start.sh启动程序"
