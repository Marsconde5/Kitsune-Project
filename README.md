#Kitsune-Project

> Descrition
The purpose of this code is to show how Kitsune can be implemented in a medical environment. Medical data is incredibly sensitive information, and it's extremely important to protect. intruders on hospital networks may manipulate data from bedside monitors and create false readings, which can have potentially life threatening consequences. Kitsune is a lightweight network intrusion system that is meant to learn the typical patterns of network traffic and detect abnormalities on its own. This makes kitsune extremely cheap and easy to run in many environments.  in our demo, the Kitsune NIDS will monitor internet traffic on a hospital network(sample traffic provided and labeled as medical.py), and identify abnormalities and intrusions. The flag will produce the source of the intrusion. Our app is a concept meant to be used in a medical environment to detect and prevent malicious intrusions. 
>
> Sources
> 
> Original kitsune research paper
> 
> Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection
> https://arxiv.org/abs/1802.09089
> 
> Additional research paper
> 
> Machine Learning Based Cybersecurity Framework for Healthcare Application
> https://ieeexplore.ieee.org/abstract/document/11020534?casa_token=AnFKnJziOi0AAAAA:7SBu3OBVljlQrg72iyDq1eog3Lw0PWx3gaEyyMxW9Kjt-IS18pT7Hwl8DfYxl8e7bQX-TmKKqJA
> 
## Installation and Setup
This project must be run in a linux environment. Cython, scipy, and scapy must be installed for the code to run.
### Dependencies

```
pip3 install Cython
pip3 install scipy
pip3 install scapy



