# Federated Learning with Flower Framework

This folder contains the data and the required codes for creating Federated Learning using the Flower framework for two types of data: DoS/DDoS and Covert Channel.

## Overview

Federated Learning is a machine learning approach that enables training models collaboratively without sharing raw data. This repository leverages the Flower framework to implement Federated Learning for the following datasets:
- **DoS/DDoS**: Dataset for Denial of Service (DoS) and Distributed Denial of Service (DDoS) attack detection.
- **Covert Channel**: Dataset for Covert Channel detection.

## Directory Structure

- `CIC/`: Contains the datasets and code required for training and evaluation of CIC.
  - `dataset/`: Data related to DoS/DDoS attacks extracted from [here](https://www.unb.ca/cic/datasets/ddos-2019.html).
  - `FL.ipynb`: Code related to model training and testing.

- `CovertChannel/`: Contains the datasets and code required for training and evaluation of CovertChannel.
  - `dataset/`: Data related to DoS/DDoS attacks extracted from [here](https://turbina.gsd.inesc-id.pt/resources/mpt_detection/)
  - `FL.ipynb`: Code related to model training and testing.
    
## Setup 

To run the code, you need the following packages installed:

- Flower (`flwr`) ([Flower v1.6.0](https://github.com/adap/flower))
- TensorFlow (`tensorflow`)
- NumPy (`numpy`)
- Pandas (`pandas`)
- Scikit-learn (`scikit-learn`)
- Jupyter Nootbook

You can install the required packages using:

```sh
pip install flwr tensorflow numpy pandas scikit-learn
