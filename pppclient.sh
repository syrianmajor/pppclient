#!/bin/bash

# Client-side script for PPP-over-STUNNEL for Tcx Darknet

# CHANGED: 2012-01-19: do not use 'ifconfig' command anymore (it is part of a package that seems to be declared deprecated on various distros) - instead we strongly rely on the "ip" command.
# -KheOps

# CHANGED: 2012-05-30: try to prevent DNS from leaking due to Network Manager (or any other automatic network management system) automatically changing /etc/resolv.conf

# CHANGED: 2012-06-09: Corrected some bugs that caused some error messages to be displayed during periodic checks of /etc/resolv.conf and iptables counters

# CHANGED: 2012-07-04:
# - ask for full redirection before actually connecting;
# - use iptables LOG target to report details of blocked packets.

function datestamp {
    echo -n $(date +"%Y-%m-%d %H:%M:%S")
}

function print_log  {
    echo "------------ LOG ------------"
    cat /tmp/pppd.log-$id
    echo "-----------------------------"
    return 0
}

function print_error {
    echo -e "[$(date +'%H:%M:%S')] \E[1m\E[31mERR: $1\E[0m"
    return 0
}

function print_warning {
    echo -e "[$(date +'%H:%M:%S')] \E[1m\E[33mWARN: $1\E[0m"
    return 0
}

function print_right {
    local len=$(echo $1 | wc -m)
    echo -en "\E[$(($(tput cols) - 1 - $len))G\E[1m$1\E[0m"
    return 0
}

function print_center {
    local len=$(echo "$1" | wc -m)
    local leftcol=$(( ($(tput cols) - $len) / 2))
    echo -e "\E[${leftcol}G$1\E[0m"
}

# This function watches logs for iptables traces reporting blocked packets.
function watchfirewall {
    local packetcount=0

    tail -n 0 -f "$iptlogfile" | while read -r line; do
	if [ -n "$(echo $line | grep $iptpfx)" ]; then
	    packetcount=$(($packetcount + 1))
	    local msg=$(echo $line | sed s/.*"$iptpfx"'.* SRC=\([^ ]*\) DST=\([^ ]*\) .*PROTO=\([^ ]*\) .*UID=\([0-9]*\).*'/"Blocked packet ($packetcount): "'\1 > \2 (\3) from user ID \4'/);
	    print_warning "$msg"
	fi

	if [ ! -r $pidfile ]; then
	    exit
	fi
    done
}

# This function watches every second the status of /etc/resolv.conf and routing
# It sets them back to the right value if they were changed (in general this is
# due to NetworkManager)
function watchconfig {
    local terminate=no
    local sha1_resolvconf="$1"
    local watchgw="$2"
    local watchif="$3"
 
    while [ $terminate = no ]; do
	if [ ! -r $pidfile ]; then
	    terminate=yes
	else
	    if [ $(sha1sum /etc/resolv.conf | awk {'print $1'}) != $sha1_resolvconf ]; then
		print_warning "/etc/resolv.conf changed, putting ours back in place."
		echo "$resolvconf" >/etc/resolv.conf
	    fi
	    if [ $full = y -a -n "$watchgw" -a -n "$watchif" ]; then
		local curgw=$($ip_exec route | awk '/default/ { print $3 }')
		local curif=$($ip_exec route | awk '/default/ { print $5 }')

		if [ "$curgw" != "$watchgw" ]; then
		    print_warning "Gateway was changed externally to $curgw. Setting it (back) to $watchgw."
		    $ip_exec route del default || terminate=yes
		    $ip_exec route add default via $watchgw dev $watchif || terminate=yes
		fi
	    fi
	fi

	sleep 1
    done

    if [ -r $pidfile ]; then
	kill $pid 2>/dev/null
    fi
}

host=$1
port=$2
pwd=$(pwd)

[ -z "$host" -o -z "$port" ] && echo Syntax: $0 host port \[pppd options\] && exit

if [ -z "$(echo $host | egrep '^([0-9]{1,3}\.){3}[0-9]{1,3}')" ]; then host=$(dig +short | head -n 1); fi
if [ -z "$host" ]; then print_error "Unable to resolve hostname"; exit; fi

# Look for various required commands...
which pppd >/dev/null 2>&1 || (print_error "Could not find pppd" && kill $$)
which sha1sum >/dev/null 2>&1 || (print_error "Could not find sha1sum" && kill $$)
which uuidgen >/dev/null 2>&1 || (print_error "Could not find uuidgen" && kill $$)

stunnel_exec=$(which stunnel4 2>/dev/null || which stunnel 2>/dev/null)
[ -z "$stunnel_exec" ] && print_error "Could not find stunnel/stunnel4 executable" && exit

ip_exec=$(which ip 2>/dev/null)
[ -z "$ip_exec" ] && print_error "Could not find 'ip' executable" && exit

ipt=$(which iptables 2>/dev/null)
[ -z "$ipt" ] && print_error "Could not find iptables" && exit

ip6t=$(which ip6tables 2>/dev/null)
[ -z "$ip6t" ] && print_error "Could not find ip6tables" && exit

[ ! -r "$pwd/wnh-ca.crt" ] && print_error "SSL certificate file 'wnh-ca.crt' not found" && exit

[ -z "$(grep '^[0-9\.]*$' <<<$host)" ] && host=$(dig +short $host | head -n 1)
[ -z "$host" ] && print_error "Could not resolve hostname $host" && exit

gateway=$($ip_exec route | awk '/default/ { print $3 }')
[ -z "$gateway" ] && print_error "Could not get current gateway. Are you connected to the Internet?" && exit
dev=$($ip_exec route | awk '/default/ { print $5 }')

# Pre-set config
id=$(uuidgen)
iptpfx="PPPTCX-"$(echo $id | cut -d - -f 1)
resolvconf="nameserver 10.8.49.1
nameserver 8.8.8.8
nameserver 8.8.4.4"
stunnelconf="
client = yes
foreground = yes
verify = 2
CAfile = $pwd/wnh-ca.crt
connect = $host:$port
TIMEOUTconnect = 60
output = /tmp/stunnel.log-$id"

# iptables rules (DNS only for non full redirection)
dnsfw_udp="-o $dev -p udp --dport 53 -j DROP"
dnsfw_tcp="-o $dev -p tcp --dport 53 -j DROP"
dnslog_udp="-o $dev -p udp --dport 53 -j LOG --log-level 4 --log-prefix $iptpfx --log-ip-options --log-uid"
dnslog_tcp="-o $dev -p tcp --dport 53 -j LOG --log-level 4 --log-prefix $iptpfx --log-ip-options --log-uid"

# iptables rules (for full redirection)
routelog4="-o $dev ! -d $host -j LOG --log-level 4 --log-prefix $iptpfx --log-ip-options --log-uid"
routelog6="-o $dev -j LOG --log-level 4 --log-prefix $iptpfx --log-ip-options --log-uid"
routefw4="-o $dev ! -d $host -j DROP"
routefw6="-o $dev -j DROP"

iptlogfile=""

shift
shift

print_center "$(datestamp)"
print_center "PPP over SSL VPN client starting"

echo -----------
echo Host: $host
echo Port: $port
echo Current gateway: $gateway "($dev)"
echo -----------

# 0. Find where iptables messages will be logged to
echo -n "Looking for iptables logging... "
$ipt -I OUTPUT 1 -o lo -j LOG --log-level 4 --log-prefix "testTCX-$shortid" --log-ip-options --log-uid
ping -c 1 127.0.0.1 >/dev/null 2>&1
iptlogfile=$(grep -HZr "testTCX-$shortid" /var/log/ | awk -F '\0' {'print $1'} | head -n 1)
$ipt -D OUTPUT -o lo -j LOG --log-level 4 --log-prefix "testTCX-$shortid" --log-ip-options --log-uid
if [ -n "$iptlogfile" ]; then echo $(print_right "$iptlogfile"); else echo $(print_right "Not found!"); fi

# 1. Generate stunnel config
echo "$stunnelconf" >/tmp/stunnel.conf-$id

# 2. Retrieve interface list before pppd startup
oldiflist="("$($ip_exec addr | awk -F ': ' '/^[0-9]/ { print $2 }' | xargs | sed 's/ /|/g')")"

full=n
echo -n "Do you want to activate full redirection of your traffic (i.e. change default route)? [y/n] "
read full

# 3. Start pppd
echo -n "Starting pppd... "
pppd \
    noauth \
    pty "$stunnel_exec /tmp/stunnel.conf-$id" \
    linkname $id \
    logfile "/tmp/pppd.log-$id" \
    $@

echo $(print_right ok)

# 4. Wait a bit for interface to come up
maxwait=120
echo -n "Waiting for PPP interface (max: $maxwait seconds)... "

start=$(date +%s)
end=$(($start + $maxwait))

# 5. check interface has come up
while [ -z "$newif" ]; do
    newif=$($ip_exec addr | awk -F ': ' '/^[0-9]/ { print $2 }' | grep ppp | egrep -v "$oldiflist")

    [ -z "$newif" -a $(date +%s) -gt $end ] && \
	echo "Time up!"$(print_right error) && \
	print_log && \
	rm -f /tmp/*-$id && \
	exit

    sleep 1
done

echo $newif$(print_right ok)

pidfile=/var/run/ppp-$id.pid
pid=$(head -n 1 $pidfile)

# 6. Set routing to DN
maxwaitgw=240
start=$(date +%s)
end=$(($start + $maxwaitgw))

echo -n "Waiting for an IP address (max: $maxwaitgw seconds)... "
while [ -z "$gw" ]; do
    check_if=$(cat /proc/net/dev | egrep "^ *$newif:")

    [ -z "$check_if" ] && echo "Network interface '$newif' is down!"$(print_right error) && (kill $pid 2>/dev/null; print_log) && exit

    gw=$($ip_exec route show dev $newif 2>/dev/null | awk {'print $1'})
    dnip=$($ip_exec route show dev $newif 2>/dev/null | awk {'print $7'})

    [ -z "$gw" -a $(date +%s) -gt $end ] && echo "Gateway was not set!$(print_right error)" && kill $pid && print_log && exit

    sleep 1
done

echo "local IP: $dnip <-> gateway: $gw"$(print_right ok)
echo "Adding routes to darknet"
$ip_exec route add 10.7.0.0/16 via $gw dev $newif
$ip_exec route add 10.8.0.0/16 via $gw dev $newif

echo "Changing DNS servers in /etc/resolv.conf"

mv -f /etc/resolv.conf /tmp/resolv.conf-$id
echo "$resolvconf" >/etc/resolv.conf

if [ "$full" = "y" ]; then
    $ip_exec route add $host/32 via $gateway
    $ip_exec route del default
    $ip_exec route add default via $gw dev $newif
    echo "Blocking any traffic of $dev not destinated to the VPN endpoint ($host)"
    $ipt -I OUTPUT 1 $routefw4
    $ip6t -I OUTPUT 1 $routefw6
    $ipt -I OUTPUT 1 $routelog4
    $ip6t -I OUTPUT 1 $routelog6
else
    echo "Blocking and logging outbound traffic on port 53 (DNS) to interface $dev"
    $ipt -A OUTPUT $dnslog_tcp
    $ipt -A OUTPUT $dnslog_udp
    $ipt -A OUTPUT $dnsfw_tcp
    $ipt -A OUTPUT $dnsfw_udp
    $ip6t -A OUTPUT $dnslog_tcp
    $ip6t -A OUTPUT $dnslog_udp
    $ip6t -A OUTPUT $dnsfw_tcp
    $ip6t -A OUTPUT $dnsfw_udp
fi

watchconfig $(echo "$resolvconf" | sha1sum | awk {'print $1'}) $gw $newif &
if [ -n "$iptlogfile" ]; then
    watchfirewall &
fi

echo VPN is running - Hit CTRL+C to terminate it.

trap "echo Received SIGINT, shutting down && kill $pid" SIGINT

while [ -r $pidfile ]; do
    sleep 1
done

echo Terminated - restoring configuration.
print_log

if [ "$full" = y ]; then
    $ipt -D OUTPUT $routefw4
    $ip6t -D OUTPUT $routefw6
    $ipt -D OUTPUT $routelog4
    $ip6t -D OUTPUT $routelog6
else
    $ipt -D OUTPUT $dnsfw_tcp
    $ipt -D OUTPUT $dnsfw_udp
    $ipt -D OUTPUT $dnslog_tcp
    $ipt -D OUTPUT $dnslog_udp
    $ip6t -D OUTPUT $dnsfw_tcp
    $ip6t -D OUTPUT $dnsfw_udp
    $ip6t -D OUTPUT $dnslog_tcp
    $ip6t -D OUTPUT $dnslog_udp
fi

mv -f /tmp/resolv.conf-$id /etc/resolv.conf
rm -f /tmp/*-$id

if [ "$full" = "y" ]; then
    $ip_exec route add default via $gateway
    $ip_exec route del $host/32 via $gateway
fi

print_center "$(datestamp)"
print_center "VPN session terminating"
