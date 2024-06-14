# Getting Started

## Requirements 
- [Mininet v2.3.1b1](https://github.com/mininet/mininet)
- [protobuf v3.18.1](https://github.com/google/protobuf)
- [PI](https://github.com/p4lang/PI)
- [gRPC v1.43.2](https://github.com/google/grpc.git)
- [BMV2 v1.15.0](https://github.com/p4lang/behavioral-model)
- [p4c v1.2.3.9](https://github.com/p4lang/p4c)
- [ptf](https://github.com/p4lang/ptf)
- [Flower v1.6.0](https://flower.ai/)

## Traffic Dataset
- Attack traffic captures of covert channel available [here](https://turbina.gsd.inesc-id.pt/resources/mpt_detection/)
- Attack traffic captures DoS/DDoS available [here](https://www.unb.ca/cic/datasets/ddos-2019.html)
- Benign traffic captures available [here](https://www.caida.org/catalog/datasets/passive_dataset/)

After downloading the data, you need to prepare it for the simulation environment. This involves dividing the PCAP file into multiple pieces for each node’s generator and mapping the IP addresses from these data to the simulation settings. You can fine a preprocssed PCAP files in [here](https://github.com/NIDS-LAB/ISDC/tree/main/Simulation/example/pcap).

## Installation
First, we need to install the P4 Mininet environment. The simplest and quickest way to install is by using the script [install-p4dev-v5.sh](https://github.com/jafingerhut/p4-guide/blob/master/bin/install-p4dev-v5.sh), provided by the p4-guide GitHub repository. After you are done with the installation, make sure you also have Tcpreplay to replay the traffic. To install Flower for Fedetated Learning, you can refer [here](https://flower.ai/docs/framework/how-to-install-flower.html).

## DEMO

### To run the simulation:

1. **Copy Files:** 
   - Copy all files from the [miscellaneous](https://github.com/NIDS-LAB/ISDC/tree/main/Simulation/example/miscellaneous) directory to the [Simulation](https://github.com/NIDS-LAB/ISDC/tree/main/Simulation) directory. These files contain script and required informaiton to run the small-scale experiment. 
   - Copy the ASN topology, our smallest topology, to the same directory.

2. **Compile Code:** 
   - In the Simulation directory, type `make` to compile the code. This will bring you to the Mininet environment. You can type `nodes` or links `links` to get information of the topology.

3. **Launch the Controller:** 
   - To launch the control plane of the switch and attach it to the switches’ data plane, type:
     ```sh
     $sudo ./controller -n 18
     ```
   - Wait a few moments until the NOC of each switch attaches to the data plane. This is confirmed when all switches successfully announce their listening status.
   - You should also be able to see the `Command:` prompt in the terminal, which can be used to drop the collected data by switches.

4. **Configure Switch Routing:** 
   - Configure the switches’ routing by typing:
     ```sh
     $./sw_config.py -n 18 -w -c
     ```

5. **Send Traffic:** 
   - Finally, send the traffic generator by typing:
     ```sh
     $sudo bash send.sh
     ```
   - Once the traffic generation is finished, the simulation is done and the data is collected in the control plane of switches.
   - You can export the collected data by typing (make sure the contorl plane is done with processing of data by tracking process CPU usage):
     ```sh
     Command: Snap
     ```
     This will save the switch data into `result` directory.
6. **Model Training:**
   - Given the collected data, you can further leverage the Flower Framework for training a global model using the collected data.
   - First, you need to label the collected data and create the require format for the training process. We have already processed this data and placed it in the [ML](https://github.com/NIDS-LAB/ISDC/tree/main/ML) folder.
   - For model training, please refer to `FL.ipynb` in the directory.
