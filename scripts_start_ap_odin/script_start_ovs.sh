# This has been taken from https://gist.github.com/marciolm/9f0ab13b877372d08e8f

#Setup variables
#My local IP address is required for the ovsdb server.
MYIP=192.168.1.6
 
# This is the OpenFlow controller ID which we're going to load into the OVS
CTLIP=192.168.1.2
 
# This is our DataPath ID
DPID=0000000000000212
 
# This is the name of the bridge that we're going to be creating
SW=br0
 
#What ports are we going to put in the OVS?
#DPPORTS="eth0.1 eth0.2 eth0.3 eth0.4 wlan0 wlan0-2 wlan0-3"
DPPORTS="eth1.1"

#Alias some variables
VSCTL="ovs-vsctl --db=tcp:$MYIP:9999"
OVSDB=/tmp/ovs-vswitchd.conf.db
 
# Subroutine to wait until a port is ready
wait_port_listen() {
    port=$1
    while ! `netstat -na | grep $port` ; do
        echo -n .
        sleep 1
    done
}

# Kill off the servers and remove any stale lockfiles
/usr/bin/killall ovsdb-server
/usr/bin/killall ovs-vswitchd
rm /tmp/ovs-vswitchd.conf.db.~lock~
 
# Remove the OVS Database and then recreate.
rm -f $OVSDB

# ovsdg-tool is the Open vSwitch database management utility
# if you use #ovsdb-tool create [DB [SCHEMA]], then you create a DB with the given SCHEMA
ovsdb-tool create $OVSDB /usr/share/openvswitch/vswitch.ovsschema
 
# Start the OVSDB server and wait until it starts
ovsdb-server $OVSDB --remote=ptcp:9999:$MYIP &
#wait_port_listen 9999
sleep 5
 
# Start vSwitchd
ovs-vswitchd tcp:$MYIP:9999 --pidfile=ovs-vswitchd.pid --overwrite-pidfile -- &
 
# Create the bridge and pass in some configuration options
$VSCTL add-br $SW
#$VSCTL set bridge $SW protocols=OpenFlow10
 
#Configure the switch to have an OpenFlow Controller.  This will contact the controller.
$VSCTL set-controller $SW tcp:$CTLIP:6633

# Turn off the fail-safe mode
$VSCTL set-fail-mode $SW secure

#Cycle through the DataPath ports adding them to the switch
for i in $DPPORTS ; do
    PORT=$i
        ifconfig $PORT up
    $VSCTL add-port $SW $PORT
done
 
#Ensure that the switch has the correct DataPath ID
$VSCTL set bridge $SW other-config:datapath-id=$DPID

#Set some parameters for sFlow traffic control (see sFlow in http://openvswitch.org/support/dist-docs/ovs-vsctl.8.txt)
#$VSCTL --id=@sflow create sflow agent=eth1.1  target=\"$CTLIP:6343\" sampling=2 polling=20 -- -- set bridge $SW sflow=@sflow 
