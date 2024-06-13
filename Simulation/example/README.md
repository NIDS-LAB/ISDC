## DEMO

### To run the simulation:

1. **Copy Files:** 
   - Copy all files from the [miscellaneous](https://github.com/NIDS-LAB/ISDC/tree/main/example/miscellaneous) directory to the [software](https://github.com/NIDS-LAB/ISDC/tree/main/Software) directory. 
   - Also, copy the ASN topology, our smallest topology, to the same directory.

2. **Compile Code:** 
   - In the Software directory, type `make` to compile the code. This will bring you to the Mininet environment.

3. **Launch the Controller:** 
   - To launch the control plane of the switch and attach it to the switches’ data plane, type:
     ```sh
     sudo ./controller -n 18
     ```
   - Wait a few moments until the NOC of each switch attaches to the data plane. This is confirmed when all switches successfully announce their listening status.

4. **Configure Switch Routing:** 
   - Configure the switches’ routing by typing:
     ```sh
     sudo ./sw_config.py -n 18 -w -c
     ```

5. **Send Traffic:** 
   - Finally, send the traffic generator by typing:
     ```sh
     sudo bash send.sh
     ```
   - Once the traffic generation is finished, the simulation is done and the data is collected in the control plane of switches.
