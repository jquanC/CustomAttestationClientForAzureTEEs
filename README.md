# Using mutual TLS to establish a fully connected network

Package `comm` implements a node that connects other known nodes via the mutual TLS protocol. A node runs a TLS server that listen to connection requests from other nodes. It also maintains all the TLS connections initiated either by other nodes or itself. Note that there is only one connection between every pair of nodes in the network.

To start a node, first new a communicator:

```golang
communicator := NewCommunicator(cfg, handleMessageFunc)
communicator.Start()
```

where `cfg` includes the node name, server ip address and locations of all the required certificate and key files, and `handleMessageFunc` is a function passed to `communicator` to handle any received data.

To terminate the node,

```golang
communicator.Close()
```

To broadcast data to other nodes,

```golang
communicator.Broadcast(data)
```

To send data to a node by its name,

```golang
peer := communicator.GetPeer(name)
if peer != nil {
    peer.Write(data)
}
```