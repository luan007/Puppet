HARDVER=0000

#openssl rsa -in mykey.pem -pubout > mykey.pub
export PS1=""
stty -echo
mkdir /tmp/cmd/
CONFDIR=/tmp/edge/configs

VER=0
DID=aa1
NID=NETWORK
echo "{{INIT}}$HARDVER:::$VER:::$DID:::$NID"

read Challenge
CHAL=$(echo $Challenge | openssl rsautl -oaep -encrypt -pubin -inkey /etc/edge/keys/second.pub | base64 | tr -d '\n')
echo "{{AUTH}}$CHAL"

_wrap_streams() {
    echo "$2" | base64 -d > "/tmp/cmd/run_$1";
    /bin/bash /tmp/cmd/run_$1
}

cleanup() {
    find /tmp/cmd -mmin +5 -mindepth 1 -type f -exec rm -f {} +
}

cmd() {
    cleanup
    echo ""
    echo "{{RUN}}$1"
    _wrap_streams "$@" 1>"/tmp/cmd/out_$1" 2>"/tmp/cmd/err_$1"
    # out=($(md5sum "/tmp/cmd/out_$1"))
    # err=($(md5sum "/tmp/cmd/err_$1"))
    echo "{{CMD}}$1"
}

fetch() {
    cleanup
    if [[ -f "/tmp/cmd/out_$1" && -f "/tmp/cmd/err_$1" ]]
    then
        out=($(base64 "/tmp/cmd/out_$1" | tr -d '\n'))
        err=($(base64 "/tmp/cmd/err_$1" | tr -d '\n'))
        out5=($(md5sum "/tmp/cmd/out_$1"))
        err5=($(md5sum "/tmp/cmd/err_$1"))
        echo "{{RESULT}}$1:$out:$err:$out5:$err5"
    else
        echo "{{NORESULT}}$1"
    fi
}

export -f _wrap_streams
export -f cmd
export -f fetch
export -f cleanup
/bin/bash # 2>/dev/null



#1.Send Cmd / Batch
#2.Wait for Cmd End
#3.Get Result & Err
