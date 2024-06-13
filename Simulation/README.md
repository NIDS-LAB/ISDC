# Getting Started
## Reqirements 
[Mininet v2.3.1b1](https://github.com/mininet/mininet), [protobuf v3.18.1](https://github.com/google/protobuf), [PI](https://github.com/p4lang/PI), [gRPC v1.43.2](https://github.com/google/grpc.git), [BMV2 v1.15.0](https://github.com/p4lang/behavioral-model), [p4c v1.2.3.9](https://github.com/p4lang/p4c), [ptf](https://github.com/p4lang/ptf)

## Traffic dataset
* Attack traffic captures of covert channel available [here](https://turbina.gsd.inesc-id.pt/resources/mpt_detection/)
* Attack traffic captures DoS/DDoS available [here](https://www.unb.ca/cic/datasets/ddos-2019.html)
* Benign traffic captures available [here](https://www.caida.org/catalog/datasets/passive_dataset/)

## Running Simulation
1.	Install P4 Mininet Setup:
	*	Ensure you have the P4 Mininet environment installed.
2.	Create Simulation Environment:
	* Use the provided topology files to set up the simulation environment.
3.	Run Mininet Environment:
	*	Launch the Mininet environment using the provided P4 software switch code.
	*	Configure the routing paths using the path files located in the topology folders.
4.	Run Controller Script:
	*	Execute controller.py to connect switches controller to the data plane.
5.	Replay Traffic:
	*	Use Tcpreplay to replay the traffic through the network.
