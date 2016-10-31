download_status() {
    wc=$(ps | grep wget | wc -l)
    if [[ $wc != "1" ]]; then
        (>&2 echo "0|Download In Progress")
        return
    fi
    if [[ -e "/tmp/download_err" ]]; then
        (>&2 echo "1|Download / Unzip Error")
        (>&2 cat /tmp/download_err)
        return
    fi
    if [[ ! -e "/tmp/download_md5" ]]; then
        (>&2 echo "2|MD5 File not found")
        return
    fi
    if [[ ! -e "/tmp/download_complete" ]]; then
        (>&2 echo "3|Currently Unzipping")
        return
    fi
    wc=$(cat /tmp/download_md5)
    if [[ -e "/tmp/download_complete" ]]; then
        echo "$wc"
        return
    fi
    (>&2 echo "9|State Unknown")
}

_download_and_deploy() {
    rm -rf /tmp/download_err
    rm -rf /tmp/download_md5
    rm -rf /tmp/download_complete
    _md5="$1"
    _url="$2"
    if [[ $_md5 == "" ]]; then
        echo "Invalid Arguments - MD5" > /tmp/download_err
        return
    fi
    if [[ $_url == "" ]]; then
        echo "Invalid Arguments - URL" > /tmp/download_err
        return
    fi
    rm -rf /mnt/sda1/portal.zip
    wget -q "$_url" -O /mnt/sda1/portal.zip 2>/dev/null 1>/dev/null
    md5=($(md5sum "/mnt/sda1/portal.zip"))
    if [[ $md5 != $_md5 ]]; then
        echo "MD5 Failed" > /tmp/download_err
        return
    fi
    echo "$md5" > /tmp/download_md5
    unzip -o /mnt/sda1/portal.zip -d /mnt/sda1 1>/tmp/unziplog 2>/tmp/unziperr
    err=$(cat /tmp/unziperr)
    if [[ $err != "" ]]; then
        echo "Zip Corrupt" > /tmp/download_err
        return
    fi
    echo "1" > /tmp/download_complete
}

download() {
    rm -rf /tmp/download_err
    rm -rf /tmp/download_md5
    rm -rf /tmp/download_complete
    mnt=$(mount | grep mnt)
    if [[ $mnt == "" ]]; then
        (>&2 echo "Mount Disk Missing")
        return
    fi
    wc=$(ps | grep wget | wc -l)
    if [[ $wc != "1" ]]; then
        (>&2 echo "Some Download is in process..")
        return
    fi
    _download_and_deploy $1 $2 2>/tmp/download_err &
    echo "Download in Process"
}


# download "8d22e07aca1e071718c5ec4d2266cc87" "http://220.249.11.166/portal.zip"



_stadump_tojson() {
   # disable globbing to avoid surprises
   set -o noglob
   # make temporary variables local to our function
   local AP S
   # read stdin of the function into AP variable
   printf '{\n'
   while read -r AP; do
     ## print lines only containing needed fields
     [[ $AP == "Station"* ]] && ( S=( ${AP/'Station '} ); printf '%b' "\"${S[0]/'(on'}\":{\n";)
     [[ $AP == *"rx bytes:"* ]] && ( S=( ${AP/'bytes: '} ); printf '%b' "\"rxbytes\":${S[2]},";)
     [[ $AP == *"rx packets:"* ]] && ( S=( ${AP/'packets: '} ); printf '%b' "\"rxpackets\":${S[2]},";)
     [[ $AP == *"tx bytes:"* ]] && ( S=( ${AP/'bytes: '} ); printf '%b' "\"txbytes\":${S[2]},";)
     [[ $AP == *"tx packets:"* ]] && ( S=( ${AP/'packets: '} ); printf '%b' "\"txpackets\":${S[2]},";)
     [[ $AP == *"tx retries:"* ]] && ( S=( ${AP/'retries: '} ); printf '%b' "\"txretries\":${S[2]},";)
     [[ $AP == *"tx failed:"* ]] && ( S=( ${AP/'failed: '} ); printf '%b' "\"txfailed\":${S[2]},";)
     [[ $AP == *"signal:"* ]] && ( S=( ${AP/'signal: '} ); printf '%b' "\"signal\":${S[0]},";)
     [[ $AP == *"signal avg:"*  ]] && ( S=( ${AP/'avg: '} ); printf '%b' "\"signalavg\":${S[2]},";)
     [[ $AP == *"connected time:"* ]] && ( S=( ${AP/'time: '} ); printf '%b' "\"time\":${S[2]}\n},";)
   done
   printf '}'
   set +o noglob
}

stadump_tojson() {
    tmp=$(_stadump_tojson <<< "$(iw $1 station dump)")
    tmp=${tmp/"},}"/"}}"}
    echo $tmp
}

_nearby() {
    set -o noglob
    local AP S
    while read -r AP; do
    ## print lines only containing needed fields
    [[ "${AP//'SSID: '*}" == '' ]] && printf '%b' "${AP/'SSID: '}\n"
    [[ "${AP//'signal: '*}" == '' ]] && ( S=( ${AP/'signal: '} ); printf '%b' "${S[0]},";)
    [[ "${AP//'freq: '*}" == '' ]] && ( S=( ${AP/'freq: '} ); printf '%b' "${S[0]},";)
    [[ "${AP//'last seen: '*}" == '' ]] && ( S=( ${AP/'last seen: '} ); printf '%b' "${S[0]},";)
    [[ "${AP//'BSS '*}" == '' ]] && ( S=( ${AP/'BSS '} ); printf '%b' "${S[0]/'(on'},";)
    done
    set +o noglob
}

nearby() {
    _nearby <<< "$(iw $1 scan)" | grep -v ",,,,"
}

_wlaninfo_tojson() {
   # disable globbing to avoid surprises
   set -o noglob
   # make temporary variables local to our function
   local AP S
   # read stdin of the function into AP variable
   printf '{'
   while read -r AP; do
     ## print lines only containing needed fields
     [[ $AP == *"channel"* ]] && ( S=( ${AP/'channel '} ); printf '%b' "\"channel\":${S[0]},";)
     [[ $AP == *"ssid"* ]] && ( S=( ${AP/'ssid '} ); printf '%b' "\"ssid\":\"${S[0]}\",";)
     [[ $AP == *"addr"* ]] && ( S=( ${AP/'addr '} ); printf '%b' "\"addr\":\"${S[0]}\",";)
     [[ $AP == *"txpower"* ]] && ( S=( ${AP/'txpower '} ); printf '%b' "\"txpower\":\"${S[0]}\"";)
     [[ $AP == *"wiphy"* ]] && ( S=( ${AP/'wiphy '} ); printf '%b' "\"wiphy\":${S[0]},";)
     [[ $AP == *"type"* ]] && ( S=( ${AP/'type '} ); printf '%b' "\"type\":\"${S[0]}\",";)
   done
   printf '}'
   set +o noglob
}

wlaninfo_tojson() {
    tmp=$(_wlaninfo_tojson <<< "$(iw $1 info)")
    tmp=${tmp/"},}"/"}}"}
    echo $tmp | grep -v '"addr":"dev"'
}


find_wlan_w_mode() {
    IF=$(iw dev | grep wlan | awk '{print $2}')
    mode=$1
    set -o noglob
    for _if in $IF 
    do
        ct=$(iw $_if info | grep "type $mode")
        if [[ $ct != "" ]]
        then
            echo $_if
            return
        fi
    done
    set +o noglob
}

#use this one to adapt to ALL conditions
wlaninfo_tojson_type() {
    iface=$(find_wlan_w_mode $1)
    if [[ $iface == "" ]]; then
        return
    fi
    wlaninfo_tojson $iface
}

#use this one to adapt to ALL conditions
stadump_tojson_type() {
    iface=$(find_wlan_w_mode $1)
    if [[ $iface == "" ]]; then
        return
    fi
    stadump_tojson $iface
}

_uci_has() {
    #lnk=$1
    #target=$2
    target=$2
    lnk=$1
    set -o noglob
    for word in $lnk
    do
        if [[ $word == $target ]] 
        then
            echo '1'
            return
        fi
    done
    set +o noglob
}

uci_has() {
    #lnk=$1
    #target=$2
    tx=$1
    target=$2
    lnk=$(uci get $tx 2>/dev/null)
    _uci_has "$lnk" "$target"
}

uci_build_list() {
    target=$1
    unique=$(echo "$2" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    uci delete $target
    set -o noglob
    for word in $unique
    do
        $(uci add_list $target=$word)
    done
    set +o noglob
}

uci_add_to_list() {
    target=$1
    unique=$(echo "$2" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    lst=$(uci get $target 2>/dev/null)
    set -o noglob
    for word in $unique
    do
        ct=$(_uci_has "$lst" "$word")
        if [[ $ct == "1" ]]
        then
            echo "SKIP $word"
        else
            $(uci add_list $target=$word)
        fi
    done
    set +o noglob
}

uci_remove_from_list() {
    target=$1
    unique=$(echo "$2" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    lst=$(uci get $target 2>/dev/null)
    set -o noglob
    for word in $unique
    do
        ct=$(_uci_has "$lst" "$word")
        if [[ $ct == "1" ]]
        then
            $(uci del_list $target=$word)
        else
            echo "SKIP $word"
        fi
    done
    set +o noglob
}


# uci_add_to_list "wifidog.rule_url.url" "p.test.aijee.cn as.test.aijee.cn p2.test.aijee.cn"
# uci_build_list "wifidog.rule_url.url" "p.test.aijee.cn as.test.aijee.cn"

export -f nearby
export -f stadump_tojson
export -f wlaninfo_tojson
export -f uci_add_to_list
export -f uci_build_list
export -f uci_remove_from_list
export -f stadump_tojson_type
export -f wlaninfo_tojson_type
export -f download
export -f download_status