#!/bin/bash


#NOTE:
# You must set the following line:
# options ipt_recent ip_pkt_list_tot=230 ip_list_tot=5000
# in file /etc/modprobe.d/xt_recent-param.conf
# so module xt_recent works effectively!
#
# see also 'modinfo xt_recent'


## Flush all existing rules, if needed
echo "Flushing all iptables filters and chains..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "Create and add rules for new BLACKLIST chain (where packets will be marked as BLACKLISTED)"
iptables -N BLACKLIST
iptables -A BLACKLIST -m recent --set --name BLACKLISTED --mask 255.255.255.255 --rsource
iptables -A BLACKLIST -j DROP


MY_EXT_IP=`dig +short myip.opendns.com @resolver1.opendns.com`
echo "External IP determined as ${MY_EXT_IP} ... "

TRUNK1IP=`getent hosts sip.megafon.bg | awk '{ print $1 ; exit }'`
TRUNK2IP=`getent hosts voice.portal.net.co | awk '{ print $1 ; exit }'`
TRUNK3IP=`getent hosts voice.portalnetworks.ca | awk '{ print $1 ; exit }'`
echo "External trunk IP's determined as ${TRUNK1IP} for sip.megafon.bg, ${TRUNK2IP} for voice.portal.net.co and ${TRUNK3IP} for voice.portalnetworks.ca ... "

LOCALNET="192.168.167.0/24"
echo "Local net (safe ip sources) set to ${LOCALNET} ... "
echo

echo "Accept all on 'lo' interface ..."
iptables -A INPUT -i lo -j ACCEPT

echo "Drop invalid packets ..."
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

echo "Allow ssh ports 22,992 from localnet ..."
iptables -A INPUT -s ${LOCALNET} -p tcp -m tcp -m multiport --dports 22,992 -j ACCEPT

echo "IPs with vicious ssh bruteforce attempts (invalid user) must be blocked for 24 hours; extra probes within this 24 hrs extend the punishment 24hr ahead; SSHBLACKLIST should be populated by external script analizing auth.log aka fail2ban..."
# Currently the script populates ssh attemps from invalid users
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 992 -m recent --update --seconds 86400 --hitcount 1 --name SSHBLACKLIST --mask 255.255.255.255 --rsource -j DROP
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 992 -m recent --remove --name SSHBLACKLIST --mask 255.255.255.255 --rsource

echo "Block ssh port 992 flood/bruteforce from internet (non-localnet) and allow new connection once in 127 sec ..."
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 992 -m recent --update --seconds 127 --name SSHSTOP --mask 255.255.255.255 --rsource -j DROP
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 992 -m recent --set --name SSHSTOP --mask 255.255.255.255 --rsource -j ACCEPT

# drop known bastards
# iptables -A INPUT -s 185.147.215.14 -j DROP
# iptables -A INPUT -s 81.171.58.55 -j DROP

echo "Allow ALL traffic from known trunks ..."
iptables -A INPUT -s ${TRUNK1IP}/32 -j ACCEPT
iptables -A INPUT -s ${TRUNK2IP}/32 -j ACCEPT
iptables -A INPUT -s ${TRUNK3IP}/32 -j ACCEPT

#allow from Niki
iptables -A INPUT -s 69.232.36.117/32 -j ACCEPT

#echo "Allow SIP traffic (udp/tcp 5060)  from known trunks ..."
#iptables -A INPUT -s ${TRUNK1IP}/32 -p udp -m udp --dport 5060:5061 -j ACCEPT
#iptables -A INPUT -s ${TRUNK2IP}/32 -p udp -m udp --dport 5060:5061 -j ACCEPT
#iptables -A INPUT -s ${TRUNK3IP}/32 -p udp -m udp --dport 5060:5061 -j ACCEPT

echo "If packet from untrusted source is marked as BLACKLISTED (this happens in BLACKLIST chain) and repeats more than once in last 4 hours - drop it ..."
iptables -A INPUT -m recent --rcheck --name BLACKLISTED --seconds 14400 --hitcount 1 --rsource -j DROP

echo "After being blocked 4 hours, we remove the IP from the BLACKLIST (if it has passed the previous rule, it has been more than 4 hr in BLACKLISTED) ..."
iptables -A INPUT -m recent --name BLACKLISTED --rsource --remove

echo "Allow udp 10000:20000 (RTP) packets from anywhere..."
iptables -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT

echo "Allow SIP traffic (udp/tcp 5060) from localnet ..."
iptables -A INPUT -s ${LOCALNET} -p tcp -m tcp --dport 5060:5061 -j ACCEPT
iptables -A INPUT -s ${LOCALNET} -p udp -m udp --dport 5060:5061 -j ACCEPT

echo "Block (drop or reject) known SIP scanners by string in UDP packet ..."
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "User-Agent: VaxSIPUserAgent" --algo bm --to 65535 -j DROP
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "User-Agent: friendly-scanner" --algo bm --to 65535 -j REJECT --reject-with icmp-port-unreachable
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "User-Agent: VaxSIPUserAgent" --algo bm --to 65535 -j DROP
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "User-Agent: friendly-scanner" --algo bm --to 65535 -j REJECT --reject-with icmp-port-unreachable


# danger this may block the good trunks if they are not explicitly allowed above!
# echo "Block (drop or reject) SIP messages pretending to come from our public IP, by string in UDP packet ..."
# iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "@${MY_EXT_IP}" --algo bm -j REJECT --reject-with icmp-port-unreachable

echo "If REGISTER SIP packet rate from untrusted source more than 60 per 120 sec (2 packets per 24s), first DROP, if faster than 60pkts/120 sec then send it to BLACKLIST chain ..."
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --set --name SIPREG --mask 255.255.255.255 --rsource
# blacklist wild registers
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --rcheck --seconds 30 --hitcount 30 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --rcheck --seconds 120 --hitcount 60 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j BLACKLIST
# drop moderate too frequent registers
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --update --seconds 120 --hitcount 40 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j DROP

iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --set --name SIPREG --mask 255.255.255.255 --rsource
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --rcheck --seconds 30 --hitcount 30 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --rcheck --seconds 120 --hitcount 60 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --update --seconds 120 --hitcount 40 --rttl --name SIPREG --mask 255.255.255.255 --rsource -j DROP

echo "If INVITE SIP packet rate from untrusted source more than 40 per 60 sec (2 packets=1call per 3s), send it to BLACKLIST chain ..."
# one call 2 packets at least over tcp; so we are allowing 10 calls per minute
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --set --name SIPINV --mask 255.255.255.255 --rsource
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --rcheck --seconds 180 --hitcount 90 --rttl --name SIPINV --mask 255.255.255.255 --rsource -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --update --seconds 60 --hitcount 40 --rttl --name SIPINV --mask 255.255.255.255 --rsource -j BLACKLIST

iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --set --name SIPINV --mask 255.255.255.255 --rsource
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --rcheck --seconds 180 --hitcount 90 --rttl --name SIPINV --mask 255.255.255.255 --rsource -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --update --seconds 60 --hitcount 40 --rttl --name SIPINV --mask 255.255.255.255 --rsource -j BLACKLIST

echo "For SIP other (non REGISTER/INVITE) packets from untrusted sources, blacklist/drop by SIP rate ..."
# we allow each src IP to send instantly 30 packets before ratelimiting gets into effect
# this 30 packets burst gets reset once every 20 seconds when the hashtable entry expires (--hashlimit-htable-expire 20000 for DROP) so they can effectively send 90 packets per minute without being dropped whatsoever,
#	just because of the burst=30; but the rate rule blocks higher rate, so entry expiration should not be an issue as 90/minite is not an issue
# the rule is that burstpackets/expire_in_seconds must be < hashlimit packets/second
# why do we allow 30pkt instaneous burst? An IP can have multiple SIP accounts (behind nat or not); we assume no more than 3.
# careful here: legit INVITE/REGISTER bursts packets here are also counted, a simple one-leg call generates 22 packets per IP here (as these are not state new - but any state!!)
# for example, 'nping -c 500 --delay 0.6 --udp -p 5060 voip.inss.ca' will start matching the drop rule after the bucket is exhausted,
# 'nping -c 400 --delay 0.29 --udp -p 5060 voip.inss.ca' will match the first blacklist entry (160/minute), and so on
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-above 600/minute --hashlimit-burst 30 --hashlimit-htable-expire 4000 --hashlimit-mode srcip --hashlimit-name sip_udp_limit1 -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-above 360/minute --hashlimit-burst 30 --hashlimit-htable-expire 6000 --hashlimit-mode srcip --hashlimit-name sip_udp_limit2 -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-above 200/minute --hashlimit-burst 30 --hashlimit-htable-expire 10000 --hashlimit-mode srcip --hashlimit-name sip_udp_limit3 -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-above 160/minute --hashlimit-burst 30 --hashlimit-htable-expire 12000 --hashlimit-mode srcip --hashlimit-name sip_udp_limit4 -j BLACKLIST
iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-above 94/minute --hashlimit-burst 30 --hashlimit-htable-expire 20000 --hashlimit-mode srcip --hashlimit-name sip_udp_limit5 -j DROP

iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-above 600/minute --hashlimit-burst 30 --hashlimit-htable-expire 4000 --hashlimit-mode srcip --hashlimit-name sip_tcp_limit1 -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-above 360/minute --hashlimit-burst 30 --hashlimit-htable-expire 6000 --hashlimit-mode srcip --hashlimit-name sip_tcp_limit2 -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-above 200/minute --hashlimit-burst 30 --hashlimit-htable-expire 10000 --hashlimit-mode srcip --hashlimit-name sip_tcp_limit3 -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-above 160/minute --hashlimit-burst 30 --hashlimit-htable-expire 12000 --hashlimit-mode srcip --hashlimit-name sip_tcp_limit4 -j BLACKLIST
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-above 94/minute --hashlimit-burst 30 --hashlimit-htable-expire 20000 --hashlimit-mode srcip --hashlimit-name sip_tcp_limit5 -j DROP

echo "...accept the rest generic SIP at 5060:5061"
iptables -A INPUT -p udp -m udp --dport 5060:5061 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -j ACCEPT

# these rules get obsoleted by the rules above
#echo "For SIP other (non REGISTER/INVITE) packets from untrusted sources allow SIP rate no more than 12/sec..."
#iptables -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-upto 12/sec --hashlimit-burst 8 --hashlimit-mode srcip,dstport --hashlimit-name sip_limit -j ACCEPT
#iptables -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-upto 12/sec --hashlimit-burst 8 --hashlimit-mode srcip,dstport --hashlimit-name sip_limit -j ACCEPT

echo "Accept all RELATED/ESTABLISHED ..."
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

echo "Accept few ICMP types as ping ..."
iptables -A INPUT -p icmp -m icmp --icmp-type 11 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 3 -m conntrack --ctstate NEW -j ACCEPT

echo "Allow all NEW connections on port 443 SSL ..."
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 443 -j ACCEPT

echo "Here come unknown meaningless packets: just DROP up to 10/sec packets per srcip..."
iptables -A INPUT -m hashlimit --hashlimit-mode srcip --hashlimit-upto 2/sec --hashlimit-burst 5 --hashlimit-name meaningless_packets_limit --j DROP

echo "...And send the rest (port scanners) to BLACKLIST so they stay blocked for 4 hour (can't discover any service after -m recent --rcheck --name BLACKLISTED entry above)."
iptables -A INPUT -j BLACKLIST


echo
echo "Iptables have been reset."
echo
echo "Run '/etc/init.d/netfilter-persistent save' if you like it."





