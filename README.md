<h1 align="center">4th laboratory of the Network Security course @ UniTn: understanding the KRACK attacks</h1>
<div align="center">
    <img width="150px" src="https://github.com/NetSecGroup5/KRACKLab/blob/main/docs/images/firstPage/KRACK-logo-small.png?raw=true">
</div>
<p align="center"><b>K</b>ey <b>R</b>einstallation <b>A</b>tta<b>ck</b>s</p>

Cover image: KRACK vulnerability logo by Mathy Vanhoef <br>
Mathy Vanhoef, CC BY-SA 4.0, via Wikimedia Commons. File available at: https://www.krackattacks.com/images/logo.png

This repository is NOT OFFICIAL and NOT RELATED with the researchers who discovered and analyzed the KRACK vulnerabilities

## Table of contents
- [Introduction](#introduction)
- [Setup guides](#setup-guides)
  - [Exercise 2](#exercise-2)

# Introduction

This repository contains all the files, reports and procedure that were used during the 4th laboratory of the Network Security course @ UniTn. The laboratory consisted into explaining and replicating, mainly on a simulated and virtual environment the attacks discovered by Mathy Vanhoef. For additional information about the attack, it is suggested the reading of the vulnerability official website at <br> https://www.krackattacks.com/
> [!CAUTION]
> Reproduction of the step explained can and will expose the machine in which they are replicated to very harmful vulnerability. We discourage you to proceed, especially if YOU DON'T FULLY UNDERSTAND WHAT YOU ARE ABOUT TO DO. This guide is meant to be for research purposes ONLY.

# Setup guides

## Exercise 2

> [!CAUTION]
> This guide will install a very old Linux Kernel and other known vulnerable components. Usage of the computer after following the guide is VEHEMENTLY ADVISED AGAINST. It is STRONGLY SUGGESTED to use a Virtual Machine and disable all connectivity. DO NOT PROCEED IF YOU DON'T FULLY UNDERSTAND WHAT YOU ARE DOING: the machine will be exposed to various vulnerability.

- Clone the lab repo with in the Documents folder with the following command:
  ```
      git clone --recurse-submodules https://github.com/NetSecGroup5/KRACKLab.git
  ```
- Move to ```KRACKLab/lab/ex2/krackattacks-script/krackattack/```
- Run (require to install packages ```libnl-3-200``` ```libnl-3-dev``` ```libssl-dev``` and ```python3.12 venv```)
  ```
      ./build.sh
   ```
  and
  ```
      ./pysetup.sh
  ```
- Move to ```KRACKLab/lab/ex2/krackattacks-script/hostapd/``` and verify that there is hosatpd file. If not run from that directory
  ```
      make
  ```
- Move to ```KRACKLab/lab/ex2/mininet-wifi/```
- Run the following command to install Mininet-WiFi
  ```
    sudo util/install.sh -Wlnfv
  ```
- Move to the ```Downloads``` folder
- Obtain ```wpa_supplicant``` version ```2.3``` source code by executing
  ```
   wget https://w1.fi/releases/wpa_supplicant-2.3.tar.gz
  ```
- Extract it with the following command
  ```
   tar -xvzf wpa_supplicant-2.3.tar.gz wpa_supplicant-2.3/
  ```
- Move to the extracted folder
- Run
  ```
   cp defconfig .config
  ```
- Change the following line in the .config just created:
    - Uncomment ```CONFIG_LIBNL32=y```
    - Uncomment ```CONFIG_TLS=openssl``` and set it to ```CONFIG_TLS=internal```
- Compile executing the command (requires package ```libtommath-dev```)
  ```
  make
  ```
- Copy the executable called ```wpa_supplicant``` to ```KRACKLab/lab/ex2/``` and rename it in ```wpa_supplicant23```
- Install packages ```xclip``` ```wireshark``` (the first one needed for the python script, the other for performing analysis)
- Open wireshark with
    ```sudo wireshark```
  Go to ```Edit > Preferences > Protocols > IEEE 802.11 > Decryption keys > new field > Key Type``` select ```wpa-pwd`` and write ```abcdefgh:testnetwork``` as the key value.
  
  You will be able to set the CCMP Packet Number column after starting receiving packets: you need to select a packet, select ```IEEE 802.11 QoS Data``` in the package info,
  next go to ```CCMP parameters > CCMP Ext. Initialization Vector```, right click and fix the field as a column.
- Move to the ```Downloads``` folder
- Download Linux Kernel version 4.4 (fix for KRACK attack introduced in later versions) by running:
     ```
         wget https://kernel.ubuntu.com/mainline/v4.4-wily/linux-headers-4.4.0-040400-generic_4.4.0-040400.201601101930_amd64.deb
         wget https://kernel.ubuntu.com/mainline/v4.4-wily/linux-image-4.4.0-040400-generic_4.4.0-040400.201601101930_amd64.deb
     ```
- Install the downloaded packages with
  ```
  sudo dpkg -i linux*.deb
  ```
- Move to ```/etc/default/grub```
- Change GRUB configuration as follow:
    - Delete ```GRUB_TIMEOUT_STYLE=hidden```
    - Set ```GRUB_TIMEOUT=0``` to ```GRUB_TIMEOUT=10```
    - Delete ```GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"```
- Run the following command to update GRUB configuration
  ```
  sudo update-grub
  ```
- Restart and when GRUB loads select ``` other options > linux-kernel-4.4.0-generic```
- mark the start attack script as executable with
  ```
  chmod +x ./startAttack.sh
  ```
- Run ```ex2.py``` with
  ```
  sudo python3 ex2.py
  ```
