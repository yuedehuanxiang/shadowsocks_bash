#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#==========================================================#
# One Click Install Shadowsocks Server for CentOS & Debian #
# Github: https://github.com/uxh/shadowsocks_bash          #
# Thanks: https://github.com/teddysun/shadowsocks_install  #
#==========================================================#

#Libsodium
libsodium_ver="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

#Mbedtls
mbedtls_ver="mbedtls-2.6.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz"

#Shadowsocks-libev
shadowsocks_libev_ver="shadowsocks-libev-3.1.3"
shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.1.3/shadowsocks-libev-3.1.3.tar.gz"

#Init script
init_script_url_centos="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"
init_script_url_debian="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev-debian"

#Current folder
cur_dir=`pwd`

#Stream ciphers
ciphers=(
aes-256-gcm
aes-256-ctr
aes-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

#Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

#Check root
[[ $EUID -ne 0 ]] && echo -e "${red}This script must be run as root!${plain}" && exit 1

#Start information
start_information(){
    clear
    echo "#==========================================================#"
    echo "# One Click Install Shadowsocks Server for CentOS & Debian #"
    echo "# Github: https://github.com/uxh/shadowsocks_bash          #"
    echo "# Thanks: https://github.com/teddysun/shadowsocks_install  #"
    echo "#==========================================================#"
}

#Check system
check_system(){
    local value=$1

    local release=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    fi

    if [ "$value" == "$release" ]; then
        return 0
    else
        return 1
    fi
}

#Get centos main version
get_centos_main_version(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

#Check centos main version
check_centos_main_version(){
    local num=$1

    local version="$(get_centos_main_version)"
    local main_ver=${version%%.*}

    if [ "$num" == "$main_ver" ]; then
        return 0
    else
        return 1
    fi
}

#Get public ip
get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

#Get char
get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

#Pre configure
pre_configure(){
    if check_system centos || check_system debian; then
        if check_system centos; then
            if check_centos_main_version 5; then
                echo -e "${red}This script do not support CentOS5!${plain}"
                exit 1
            fi
        fi
    else
        echo -e "${red}This script only support CentOS6/7 and Debian7/8!${plain}"
        exit 1
    fi

    if [ "$(command -v ss-server)" ]; then
        echo -e "${green}Shadowsocks server has already been installed.${plain}"
        exit 0
    fi

    echo "Please Enter Shadowsocks's Password"
    read -p "(Default: Number123890):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="Number123890"
    echo "-------------------------"
    echo "Password = ${shadowsockspwd}"
    echo "-------------------------"

    while true
    do
    dport=$(shuf -i 3000-8888 -n 1)
    echo -e "Please Enter Shadowsocks's Port (1~65535)"
    read -p "(Default: ${dport}):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo "-------------------------"
            echo "Port = ${shadowsocksport}"
            echo "-------------------------"
            break
        fi
    fi
    echo -e "${red}Please enter a number between 1 and 65535!${plain}"
    done

    while true
    do
    echo -e "Please Select Shadowsocks's Stream Cipher"
    for ((i=1;i<=${#ciphers[@]};i++ )); do
        hint="${ciphers[$i-1]}"
        echo -e "${i}) ${hint}"
    done
    read -p "(Default: ${ciphers[0]}):" pick
    [ -z "$pick" ] && pick=1
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${red}Please enter a number!${plain}"
        continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
        echo -e "${red}Please enter a number between 1 and ${#ciphers[@]}!${plain}"
        continue
    fi
    shadowsockscipher=${ciphers[$pick-1]}
    echo "-------------------------"
    echo "Stream Cipher = ${shadowsockscipher}"
    echo "-------------------------"
    break
    done

    echo
    echo "Press Enter to start...or Press Ctrl+C to cancel"
    char=`get_char`

    if check_system centos; then
        echo -e "${green}Install the EPEL repository.${plain}"
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum -y install epel-release
        fi
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            echo -e "${red}Install EPEL repository failed!${plain}"
            exit 1
        fi
        if [ ! "$(command -v yum-config-manager)" ]; then
            yum -y install yum-utils
        fi
        if [ x"`yum-config-manager epel | grep -w enabled | awk '{print $3}'`" != x"True" ]; then
            yum-config-manager --enable epel
        fi
        echo -e "${green}Install the EPEL repository complete.${plain}"
        yum -y install unzip openssl openssl-devel gettext gcc autoconf libtool automake make libev-devel pcre pcre-devel git c-ares-devel
    elif check_system debian; then
        apt-get update
        apt-get --no-install-recommends -y install gettext build-essential autoconf automake libtool openssl libssl-dev zlib1g-dev libpcre3-dev libev-dev libc-ares-dev
    fi
}

#Pre configure modify
pre_configure_modify(){
    echo "Please Enter Shadowsocks's Password"
    read -p "(Default: Number123890):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="Number123890"
    echo "-------------------------"
    echo "Password = ${shadowsockspwd}"
    echo "-------------------------"

    while true
    do
    dport=$(shuf -i 3000-8888 -n 1)
    echo -e "Please Enter Shadowsocks's Port (1~65535)"
    read -p "(Default: ${dport}):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo "-------------------------"
            echo "Port = ${shadowsocksport}"
            echo "-------------------------"
            break
        fi
    fi
    echo -e "${red}Please enter a number between 1 and 65535!${plain}"
    done

    while true
    do
    echo -e "Please Select Shadowsocks's Stream Cipher"
    for ((i=1;i<=${#ciphers[@]};i++ )); do
        hint="${ciphers[$i-1]}"
        echo -e "${i}) ${hint}"
    done
    read -p "(Default: ${ciphers[0]}):" pick
    [ -z "$pick" ] && pick=1
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${red}Please enter a number!${plain}"
        continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
        echo -e "${red}Please enter a number between 1 and ${#ciphers[@]}!${plain}"
        continue
    fi
    shadowsockscipher=${ciphers[$pick-1]}
    echo "-------------------------"
    echo "Stream Cipher = ${shadowsockscipher}"
    echo "-------------------------"
    break
    done

    echo
    echo "Press Enter to start...or Press Ctrl+C to cancel"
    char=`get_char`
}

#Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Set firewall
set_firewall(){
    if check_system centos; then
        echo -e "${green}Start set firewall...${plain}"
        if check_centos_main_version 6; then
            /etc/init.d/iptables status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                    /etc/init.d/iptables save
                    /etc/init.d/iptables restart
                else
                    echo -e "${green}Port ${shadowsocksport} has been opened!${plain}"
                fi
            else
                echo -e "${yellow}Firewall looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary!${plain}"
            fi
        elif check_centos_main_version 7; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
                firewall-cmd --reload
            else
                echo -e "${yellow}Firewall looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary!${plain}"
            fi
        fi
        echo -e "${green}Firewall set completed!${plain}"
    fi
}

#Download function
download() {
    local filename=${1}

    if [ -s ${filename} ]; then
        echo -e "${green}${filename} found.${plain}"
    else
        echo -e "${yellow}${filename} not found, download now.${plain}"
        wget --no-check-certificate -c -t3 -T3 -O ${1} ${2}
        if [ $? -eq 0 ]; then
            echo -e "${green}${filename} download completed.${plain}"
        else
            echo -e "${red}Failed to download ${filename}.${plain}"
            exit 1
        fi
    fi
}

#Download files
download_files(){
    cd ${cur_dir}
    download "${shadowsocks_libev_ver}.tar.gz" "${shadowsocks_libev_url}"
    download "${libsodium_ver}.tar.gz" "${libsodium_url}"
    download "${mbedtls_ver}-gpl.tgz" "${mbedtls_url}"
    if check_system centos; then
        download "/etc/init.d/shadowsocks" "${init_script_url_centos}"
    elif check_system debian; then
        download "/etc/init.d/shadowsocks" "${init_script_url_debian}"
    fi
}

#Install libsodium
install_libsodium() {
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf ${libsodium_ver}.tar.gz
        cd ${libsodium_ver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${red}${libsodium_ver} install failed!${plain}"
            exit 1
        fi
    else
        echo -e "${green}${libsodium_ver} already installed.${plain}"
    fi
}

#Install mbedtls
install_mbedtls() {
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        tar xf ${mbedtls_ver}-gpl.tgz
        cd ${mbedtls_ver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${red}${mbedtls_ver} install failed.${plain}"
            exit 1
        fi
    else
        echo -e "${green}${mbedtls_ver} already installed.${plain}"
    fi
}

# Config shadowsocks
config_shadowsocks(){
    local server_value="\"0.0.0.0\""

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
    "timeout":600,
    "method":"${shadowsockscipher}"
}
EOF
}

# Install Shadowsocks-libev
install_shadowsocks(){
    ldconfig
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_ver}.tar.gz
    cd ${shadowsocks_libev_ver}
    ./configure --disable-documentation
    make && make install
    if [ $? -eq 0 ]; then
        chmod +x /etc/init.d/shadowsocks
        chkconfig --add shadowsocks
        chkconfig shadowsocks on
        /etc/init.d/shadowsocks start
        if [ $? -eq 0 ]; then
            echo -e "${green}Shadowsocks-libev start success.${plain}"
        else
            echo -e "${yellow}Shadowsocks-libev start failure!${plain}"
        fi
    else
        echo
        echo -e "${red}Shadowsocks-libev install failed!${plain}"
        exit 1
    fi
}

#Install success
install_success(){
    clear
    echo -e "${green}Congratulations, Shadowsocks-libev server install completed!${plain}"
    echo -e "------------------------------------------------------------"
    echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
    echo -e "Your Server Port      : \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password         : \033[41;37m ${shadowsockspwd} \033[0m"
    echo -e "Your Encryption Method: \033[41;37m ${shadowsockscipher} \033[0m"
    echo -e "------------------------------------------------------------"
}

#Qr link
qr_link() {
    local tmp1=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
    local tmp2="ss://${tmp1}"
    echo -e "${tmp2}"
    echo
}

#Install cleanup
install_cleanup(){
    cd ${cur_dir}
    rm -rf ${shadowsocks_libev_ver} ${shadowsocks_libev_ver}.tar.gz
    rm -rf ${libsodium_ver} ${libsodium_ver}.tar.gz
    rm -rf ${mbedtls_ver} ${mbedtls_ver}-gpl.tgz
}

#Install Shadowsocks-libev
install_shadowsocks_libev(){
    start_information
    pre_configure
    disable_selinux
    set_firewall
    download_files
    install_libsodium
    install_mbedtls
    config_shadowsocks
    install_shadowsocks
    install_success
    qr_link
    install_cleanup
}

#Modify Shadowsocks-libev
modify_shadowsocks_libev(){
    start_information
    pre_configure_modify
    set_firewall
    config_shadowsocks
    /etc/init.d/shadowsocks restart
    install_success
    qr_link
}

# Uninstall Shadowsocks-libev
uninstall_shadowsocks_libev(){
    start_information
    echo "Are you sure uninstall Shadowsocks? (y/n)"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"

    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
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
        echo "${green}Shadowsocks uninstall success!${plain}"
    else
        echo
        echo "${yellow}Uninstall cancelled, nothing to do...${plain}"
        echo
    fi
}

#Main control
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|modify|uninstall)
        ${action}_shadowsocks_libev
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: `basename $0` [install|uninstall]"
        ;;
esac
