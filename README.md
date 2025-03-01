# papers-IDS-for-IOT
# Lightweight Feature-Based Intrusion Detection System (LF-IDS)

This repository contains the implementation of the LF-IDS model for IoT networks as described in the paper submitted to EPD-C 2025 Conference.

## Description
The LF-IDS uses a Random Forest classifier with lightweight features (Packet Size, Inter-arrival Time, Protocol) to detect intrusions in IoT networks. It simulates 20 virtual nodes using Docker containers.

## Requirements
- Python 3.7+
- Docker installed and running (https://www.docker.com/get-started)
- Install dependencies:
  ```bash
  pip install -r requirements.txt

  Usage

    Clone the repository:
 ```bash
git clone https://github.com/milad-amini-it/LF-IDS
cd LF-IDS

Run the script:
```bash

    python lf_ids.py
    Outputs:
        lf_ids_model.pkl: Trained model
        latency.png: Accuracy comparison plot
        Console logs: Accuracy and classification report

Data

Network traffic is simulated using 20 Docker containers, generating 1000 packets with 15% attack traffic.


License

[Free]

Author

[milad amini] - [milad.amini.it@gmail.com]
