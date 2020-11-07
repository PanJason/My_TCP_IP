## how to install pan_protocol_stack
```bash
cmake CMakeLists.txt
make
```

## how to test it using the given network topology
```
sudo bash ./makeVNet < example.txt
cd ./test
./eth_capture veth2-1  #start capturing on veth2-1.
./eth_send veth1-2 <MAC address of veth2-1> <Message you want to send>  #send a message from veth1-2 to veth2-1.
sudo bash ./removeVNet < example.txt
```

