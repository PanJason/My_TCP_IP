## How to install pan_protocol_stack
```bash
cmake CMakeLists.txt
make
```

## How to test it using the given network topology
```
sudo bash ./makeVNet < example.txt

#Disable kernel stack for both devices.

cd ./test
./ipServer veth2-1  #start capturing on veth2-1.
./ipClient veth1-2 <IP address in dot format> <Message you want to send>
sudo bash ./removeVNet < example.txt
```

