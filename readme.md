## How to install pan_protocol_stack
```bash
cmake CMakeLists.txt
make
```

## How to test it using the given network topology
```
sudo bash ./makeVNet < example.txt

#Disable kernel stack for all devices.

./tcptest_server 80 #start an echo server on port 80 on ns3
./ipRouter #start a router on ns2
./tcptest_client 10.100.2.2 80 #start an echo client on ns1. The 
client will connect to 10.100.2.2 port 80.
#Then you can type in any message you want to echo.
#Enable kernel stack for all devices. 
sudo bash ./removeVNet < example.txt
```

