#!/bin/bash

sudo ip netns del host1
sudo ip netns del host2
sudo ip netns del cont1
sudo ip netns del cont2
sudo ip link del veth1
sudo ip link del veth2
sudo ip link del br0

sudo pkill policy
sudo pkill hoverd


