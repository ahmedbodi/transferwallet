#!/bin/bash
ip2dec () {
    local a b c d ip=$@
    IFS=. read -r a b c d <<< "$ip"
    printf '%d' "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}


IPS=`transferd masternode list | grep : | cut -d \" -f 2 | cut -d : -f 1`

printf '<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<array>\n'

for ip in $IPS;
do
    printf "<integer>"
    ip2dec $ip
    printf "</integer>\n"
done

printf '</array>\n</plist>'

