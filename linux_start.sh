sudo ip addr add 192.168.0.1/24 dev wlp3s0
sudo ip link set dev wlp3s0 up
sudo ip address show dev wlp3s0
rm *.log
sudo ./server.py
