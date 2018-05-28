#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#===================================================================#
# Autoinstall Shadowsocks-libev Server for CentOS & Debian & Ubuntu #
# Github: https://github.com/uxh/shadowsocks_bash                   #
# Author: https://www.banwagongzw.com & www.vultrcn.com             #
# Thanks: https://github.com/teddysun/shadowsocks_install           #
#===================================================================#

#Libsodium
libsodiumver="libsodium-1.0.16"
libsodiumurl="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

#Mbedtls
mbedtlsver="mbedtls-2.6.0"
mbedtlsurl="https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz"

#Init script
initscripturl="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"

#Current directory
currentdir=$(pwd)

#Stream cipher
ciphers=(aes-256-gcm aes-256-ctr aes-256-cfb chacha20-ietf-poly1305 chacha20-ietf chacha20 rc4-md5)

#CentOS dependencies
centosdependencies=(gettext openssl openssl-devel gcc autoconf automake make libtool libev-devel pcre pcre-devel c-ares-devel)

#Debian dependencies
debiandependencies=(gettext openssl build-essential autoconf automake libtool libev-dev libssl-dev zlib1g-dev libpcre3-dev libc-ares-dev)

#Color
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
plain="\033[0m"

#Check root
[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] Please run this script as root!" && exit 1

#Start information
startinformation() {
    clear
    echo "#=============================================================#"
    echo "# Autoinstall Shadowsocks Server for CentOS & Debian & Ubuntu #"
    echo "# Github: https://github.com/uxh/shadowsocks_bash             #"
    echo "# Author: https://www.banwagongzw.com & www.vultrcn.com       #"
    echo "#=============================================================#"
}

#Disable selinux
disableselinux() {
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Check system
checksystem() {
    local value=$1
    local release=""

    if cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /etc/*-release | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /etc/*-release | grep -Eqi "debian"; then
        release="debian"
    elif cat /etc/*-release | grep -Eqi "ubuntu"; then
        release="ubuntu"
    fi

    if [ "${value}" == "${release}" ]; then
        return 0
    else
        return 1
    fi
}

#Get centos version
getcentosversion() {
    if [[ -s /etc/redhat-release ]]; then
        cat /etc/redhat-release | grep -Eo "[0-9.]+"
    else
        cat /etc/issue | grep -Eo "[0-9.]+"
    fi
}

#Check centos version
checkcentosversion() {
    local value=$1
    local number=$(getcentosversion)
    local version=${number%%.*}

    if [ "${value}" == "${version}" ]; then
        return 0
    else
        return 1
    fi
}

#Check kernel version
checkkernelversion() {
    local kernelversion=$(uname -r | cut -d- -f1)
	local olderversion=$(echo "${kernelversion} 3.7.0" | tr " " "\n" | sort -V | head -n 1)
    if [ "${olderversion}" == "3.7.0" ]; then
        return 0
    else
        return 1
    fi
}

#Get ipv4
getipv4() {
    local ipv4=$(ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    [ -z ${ipv4} ] && ipv4=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    [ -z ${ipv4} ] && ipv4=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    [ ! -z ${ipv4} ] && echo -e "${ipv4}" || echo ""
}

#Get ipv6
get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

#Check install
checkinstall() {
    if [ "$(command -v ss-server)" ]; then
        echo -e "[${yellow}Warn${plain}] Shadowsocks server has already been installed!"
        exit 0
    fi
}

#Pre configure
preconfigure() {
    if checksystem centos || checksystem debian || checksystem ubuntu; then
        if checksystem centos; then
            if checkcentosversion 5; then
                echo -e "[${red}Error${plain}] This script does not support CentOS5!"
                exit 1
            fi
        fi
    else
        echo -e "[${red}Error${plain}] This script only supports CentOS, Debian and Ubuntu!"
        exit 1
    fi

    echo "Please Enter Shadowsocks's Password"
    read -p "(Default: Number123890):" shadowsockspwd
    [ -z ${shadowsockspwd} ] && shadowsockspwd="Number123890"
    echo "-------------------------"
    echo "Password = ${shadowsockspwd}"
    echo "-------------------------"

    while true
    do
        local randomport=$(shuf -i 9000-9999 -n 1)
        echo "Please Enter Shadowsocks's Port (1~65535)"
        read -p "(Default: ${randomport}):" shadowsocksport
        [ -z ${shadowsocksport} ] && shadowsocksport=${randomport}
        expr ${shadowsocksport} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
                echo "-------------------------"
                echo "Port = ${shadowsocksport}"
                echo "-------------------------"
                break
            fi
        fi
        echo -e "[${red}Error${plain}] Please enter a number between 1 and 65535!"
    done

    while true
    do
        echo "Please Select Shadowsocks's Stream Cipher"
        for ((i=1;i<=${#ciphers[@]};i++ ))
		do
            local cipher=${ciphers[${i}-1]}
            echo -e "${i}) ${cipher}"
        done
        read -p "(Default: ${ciphers[0]}):" ciphernumber
        [ -z ${ciphernumber} ] && ciphernumber=1
        expr ${ciphernumber} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${ciphernumber} -ge 1 ] && [ ${ciphernumber} -le ${#ciphers[@]} ] && [ ${ciphernumber:0:1} != 0 ]; then
                shadowsockscipher=${ciphers[${ciphernumber}-1]}
                echo "-------------------------"
                echo "Stream Cipher = ${shadowsockscipher}"
                echo "-------------------------"
                break
            fi
        fi
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}!"
    done

    if checksystem centos; then
        while true
        do
            echo "Please Select Whether to Disable Firewall (Y/N)"
            read -p "(Default: Y):" disablefirewall
            [ -z ${disablefirewall} ] && disablefirewall="Y"
            if [ "${disablefirewall}" == "Y" ] || [ "${disablefirewall}" == "y" ] || [ "${disablefirewall}" == "N" ] || [ "${disablefirewall}" == "n" ]; then
                echo "-------------------------"
                echo "Disable Firewall = ${disablefirewall}"
                echo "-------------------------"
                break
            fi
            echo -e "[${red}Error${plain}] Please enter Y or N!"
        done
    fi

    echo ""
    echo "Press Enter to start...or Press Ctrl+C to cancel"
    read -n 1
}

#Get shadowsocks lastest version
getshadowsockslastestversion() {
    echo -e "[${green}Info${plain}] Get shadowsocks-libev latest version start..."
    local lastestversion=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep "tag_name" | cut -d\" -f4)
    if [ -z ${lastestversion} ]; then
        echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed!"
        exit 1
    fi
    shadowsocksver="shadowsocks-libev-$(echo ${lastestversion} | sed -e 's/^[a-zA-Z]//g')"
    shadowsocksurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${lastestversion}/${shadowsocksver}.tar.gz"
    echo -e "[${green}Info${plain}] Get shadowsocks-libev latest version success!"
}

#Error detect dependencies
errordetectdependencies() {
    local command=$1
    local dependency=$(echo "${command}" | awk '{print $4}')
    echo -e "[${green}Info${plain}] Install ${dependency} start..."
    ${command}
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Install ${dependency} failed!"
        exit 1
    fi
    echo -e "[${green}Info${plain}] Install ${dependency} success!"
}

#Install dependencies
installdependencies() {
    if checksystem centos; then
        echo -e "[${green}Info${plain}] Install EPEL repository start..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release
        fi
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            echo -e "[${red}Error${plain}] Install EPEL repository failed!"
            exit 1
        fi
        if [ ! "$(command -v yum-config-manager)" ]; then
            yum install -y yum-utils
        fi
        if [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ]; then
            yum-config-manager --enable epel
        fi
        echo -e "[${green}Info${plain}] Install EPEL repository success!"
        for dependency in ${centosdependencies[@]}; do
            errordetectdependencies "yum install -y ${dependency}"
        done
    else
        apt-get update
        for dependency in ${debiandependencies[@]}; do
            errordetectdependencies "apt-get install -y ${dependency}"
        done
    fi
}

#Set firewall
setfirewall() {
    if checksystem centos; then
        echo -e "[${green}Info${plain}] Set firewall start..."
        if checkcentosversion 6; then
            if [ "${disablefirewall}" == "Y" ] || [ "${disablefirewall}" == "y" ]; then
                iptables -P INPUT ACCEPT
                iptables -P OUTPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -F
                service iptables stop
                chkconfig iptables off
                echo -e "[${green}Info${plain}] Firewall has been disabled!"
            else
                /etc/init.d/iptables status > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    iptables -L -n | grep -i "${shadowsocksport}" > /dev/null 2>&1
                    if [ $? -ne 0 ]; then
                        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                        /etc/init.d/iptables save
                        /etc/init.d/iptables restart
                    fi
                    echo -e "[${green}Info${plain}] Port ${shadowsocksport} has been opened!"
                else
                    echo -e "[${yellow}Warn${plain}] Firewall looks like not installed or running!"
                fi
            fi
        elif checkcentosversion 7; then
            if [ "${disablefirewall}" == "Y" ] || [ "${disablefirewall}" == "y" ]; then
                systemctl stop firewalld.service
                systemctl disable firewalld.service
                echo -e "[${green}Info${plain}] Firewall has been disabled!"
            else
                systemctl status firewalld > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    firewall-cmd --zone=public --add-port=${shadowsocksport}/tcp --permanent
                    firewall-cmd --zone=public --add-port=${shadowsocksport}/udp --permanent
                    firewall-cmd --reload
                    echo -e "[${green}Info${plain}] Port ${shadowsocksport} has been opened!"
                else
                    echo -e "[${yellow}Warn${plain}] Firewall looks like not installed or running!"
                fi
            fi
        fi
        echo -e "[${green}Info${plain}] Set firewall success!"
    fi
}

#Download
download() {
    local filename=$1

    if [ -s ${filename} ]; then
        echo -e "[${green}Info${plain}] ${filename} found!"
    else
        echo -e "[${green}Info${plain}] Download ${filename} start..."
        wget --no-check-certificate -c -t3 -T10 -O $1 $2
        if [ $? -eq 0 ]; then
            echo -e "[${green}Info${plain}] Download ${filename} success!"
        else
            echo -e "[${red}Error${plain}] Download ${filename} failed!"
            rm -rf ${filename}
            exit 1
        fi
    fi
}

#Install libsodium
installlibsodium() {
    echo -e "[${green}Info${plain}] Install ${libsodiumver} start..."
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${currentdir}
        download "${libsodiumver}.tar.gz" "${libsodiumurl}"
        tar zxf ${libsodiumver}.tar.gz
        cd ${libsodiumver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Install ${libsodiumver} failed!"
            rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
            exit 1
        fi
    fi
    echo -e "[${green}Info${plain}] Install ${libsodiumver} success!"
}

#Install mbedtls
installmbedtls() {
    echo -e "[${green}Info${plain}] Install ${mbedtlsver} start..."
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${currentdir}
        download "${mbedtlsver}-gpl.tgz" "${mbedtlsurl}"
        tar xf ${mbedtlsver}-gpl.tgz
        cd ${mbedtlsver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtlsver} install failed!"
            rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
            exit 1
        fi
    fi
    echo -e "[${green}Info${plain}] Install ${mbedtlsver} success!"
}

#Config shadowsocks
createshadowsocksjson() {
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if checkkernelversion; then
        fast_open="true"
    else
        fast_open="false"
    fi

    if checksystem centos; then
        if checkcentosversion 6; then
            fast_open="false"
        fi
    fi

    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi

    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
}

#Install Shadowsocks
installshadowsocks() {
    echo -e "[${green}Info${plain}] Install shadowsocks start..."
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
    fi
    ldconfig
    cd ${currentdir}
    download "${shadowsocksver}.tar.gz" "${shadowsocksurl}"
    tar zxf ${shadowsocksver}.tar.gz
    cd ${shadowsocksver}
    ./configure --disable-documentation && make && make install
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Shadowsocks install failed!"
        rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
        exit 1
    fi
    download "/etc/init.d/shadowsocks" "${initscripturl}"
    chmod +x /etc/init.d/shadowsocks
    if checksystem centos; then
        chkconfig --add shadowsocks
        chkconfig shadowsocks on
    else
        update-rc.d -f shadowsocks defaults
    fi
    /etc/init.d/shadowsocks start
    if [ $? -ne 0 ]; then
        echo -e "[${yellow}Warn${plain}] Start shadowsocks failed!"
        exit 1
    fi
    echo -e "[${green}Info${plain}] Install shadowsocks success!"
}

#End information
endinformation() {
    /etc/init.d/shadowsocks restart
    clear
    echo -e "Congratulations, Shadowsocks server install completed!"
    echo -e "------------------------------------------------------------"
    echo -e "Your Server IP        : \033[41;37m $(getipv4) \033[0m"
    echo -e "Your Server Port      : \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password         : \033[41;37m ${shadowsockspwd} \033[0m"
    echo -e "Your Encryption Method: \033[41;37m ${shadowsockscipher} \033[0m"
    echo -e "------------------------------------------------------------"
    local tmp1=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(getipv4):${shadowsocksport}" | base64 -w0)
    local tmp2="ss://${tmp1}"
    echo -e "${tmp2}"
    echo ""
}

#Install cleanup
installcleanup() {
    cd ${currentdir}
    rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
    rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
    rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
}

#Install Shadowsocks
autoinstallshadowsocks() {
    disableselinux
    startinformation
    checkinstall
    preconfigure
    getshadowsockslastestversion
    installdependencies
    setfirewall
    installlibsodium
    installmbedtls
    createshadowsocksjson
    installshadowsocks
    endinformation
    installcleanup
}

#Modify Shadowsocks
automodifyshadowsocks() {
    startinformation
    preconfigure
    setfirewall
    createshadowsocksjson
    endinformation
}

#Uninstall Shadowsocks
autouninstallshadowsocks(){
    startinformation
    echo "Are you sure uninstall Shadowsocks? (Y/N)"
    read -p "(Default: N):" answer
    [ -z ${answer} ] && answer="N"

    if [ "${answer}" == "Y" ] || [ "${answer}" == "y" ]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        chkconfig --del shadowsocks
        rm -fr /etc/shadowsocks-libev
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f /etc/init.d/shadowsocks
        echo "[${green}Info${plain}] Shadowsocks uninstall success."
    else
        echo
        echo "[${yellow}Warn${plain}] Uninstall cancelled!"
        echo
    fi
}

#Main control
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|modify|uninstall)
        auto${action}shadowsocks
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: $(basename $0) [install|uninstall]"
        ;;
esac
