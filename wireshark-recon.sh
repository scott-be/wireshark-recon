#!/usr/bin/env bash

unset OPTA OPTB

INTERFACES=''
BLOCKED_MACS=''
SMART_MAC=0
OUTPUT_FILE=''

function print_help () {
    printf "%s\n" "Usage: $(basename $0) [arguments]"
    printf "\n"
    printf "%s\n" "Required arguments:"
    printf "%-15s %-54s\n" "-i INTERFACE" "Name of interface(s) (comma separated)"
    printf "%s\n" "Optional arguments:"
    printf "%-15s %-54s\n" "-h" "Print this help"
    printf "%-15s %-54s\n" "-b MAC" "MAC Addresse(s) to ignore (comma separated)"
    printf "%-15s %-54s\n" "-s" "Ignore the MAC address assocated with the  the int"
    printf "%-15s %-54s\n" "-o FILE" "Output pcap file"
}

while getopts ":i:b:sho:" OPT; do
  case $OPT in
    i)
        for i in $(echo $OPTARG | tr ',' '\n'); do
            INTERFACES="$INTERFACES -i $i"
        done
        ;;
    b)
        for i in $(echo $OPTARG | tr ',' '\n'); do
            BLOCKED_MACS="$BLOCKED_MACS and not ether host $i"
        done
        ;;
    s)
        SMART_MAC=1;;
    o)
        OUTPUT_FILE="-w $OPTARG.pcapng";;
    h)
        print_help
        exit 0
        ;;
    \?)
        echo "Invalid option: -$OPTARG" >&2
        ;;
    :)
        echo "-$OPTARG requires an argument."
        exit 1
        ;;
  esac
done

if [[ $INTERFACES == '' ]]; then
    echo "ERROR: Please enter a interface"
    print_help
    exit 1
fi

if [[ $SMART_MAC -eq 1 ]]; then
    for i in $(echo $INTERFACES | tr '\-i ' '\n'); do
        MAC_ADDR=$(ifconfig $i | grep -o -E '([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])')
        BLOCKED_MACS="$BLOCKED_MACS and not ether host $MAC_ADDR"
    done
fi

if hash multitail 2>/dev/null; then
    tshark $INTERFACES -f \"${BLOCKED_MACS:5}\" $OUTPUT_FILE &>/dev/null
    multitail -s 2 -t "IPv4 Hosts" -ts -l "tshark -f 'not ip6 and not arp $BLOCKED_MACS' $INTERFACES -n -N m -T fields -e ip.src -e eth.src -e eth.src_resolved" \
              -t "IPv6 Hosts" -ts -l "tshark -f 'not ip and not arp $BLOCKED_MACS' $INTERFACES -n -N m -T fields -e ipv6.src -e eth.src -e eth.src_resolved" \
              -t "DNS Servers" -l "tshark -f 'udp src  port 53 $BLOCKED_MACS' $INTERFACES -n -N m -T fields -e ip.src -e eth.src -e eth.src_resolved" \
              -t "Broadcast Addresses" -l "tshark -f 'ip and ether dst ff:ff:ff:ff:ff:ff and ip dst not 255.255.255.255 $BLOCKED_MACS' $INTERFACES -T fields -e ip.dst" \
              -t "Web Sites" -ts -l "tshark -f 'port 80 $BLOCKED_MACS' -Y 'http.request.method == GET' $INTERFACES -n -T fields -e http.host"
else
    echo "ERROR: multitail not found"
    exit 1
fi

## Flags
# -i <INT1,INT2...> Interface(s)
# -bm <MAC,MAC...>  Block MAC addresses
# -sb               Smart MAC block - using the given interface(s), add its MAC to the block list
# -o <FILE>         Output pcap file