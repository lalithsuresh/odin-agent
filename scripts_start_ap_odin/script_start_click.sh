./click a_agent.cli &
sleep 3
ifconfig ap up
ovs-vsctl --db=tcp:192.168.1.5:6632 add-port br0 ap
sleep 3
ovs-ofctl add-flow br0 in_port=1,dl_type=0x0800,nw_src=192.168.1.129,nw_dst=192.168.1.5,nw_proto=6,tp_dst=6777,actions=output:LOCAL


