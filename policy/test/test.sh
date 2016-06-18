sudo ip netns add web
sudo ip netns add app

sudo ip link add veth2 type veth peer link veth0
sudo ip link set veth0 netns web
sudo ip netns exec web ip link set veth0 up
sudo ip netns exec web ifconfig veth0 10.1.1.1/24

sudo ip link add veth3 type veth peer link veth0
sudo ip link set veth0 netns app
sudo ip netns exec app ip link set veth0 up
sudo ip netns exec app ifconfig veth0 10.1.1.2/24

sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip link set veth2 master br0
sudo ip link set veth3 master br0
sudo ip link set veth2 up
sudo ip link set veth3 up

sudo ip netns exec app ping 10.1.1.1
