# Exercise 2 setup replication instructions

> [!CAUTION]
> This guide will install a very old Linux Kernel and other known vulnerable components. Usage of the computer after following the guide is VEHEMENTLY ADVISED AGAINST. It is STRONGLY SUGGESTED to use a Virtual Machine and disable all connectivity. DO NOT PROCEED IF YOU DON'T FULLY UNDERSTAND WHAT YOU ARE DOING: the machine will be exposed to various vulnerability.

- Clone the lab repo with in the Documents folder with the following command:
  ```
      git clone --recurse-submodules https://github.com/NetSecGroup5/KRACKLab.git
  ```
- Move to KRACKLab/lab/ex2/krackattacks-script/krackattack/
- Run (require to install packages ```libnl-3-200``` ```libnl-3-dev``` ```libssl-dev``` and ```python3.12 venv```)
  ```
      ./build.sh
   ```
  and
  ```
      ./pysetup.sh
  ```
- Move to KRACKLab/lab/ex2/krackattacks-script/hostapd and verify that there is hosatpd file. If not run from that directory
  ```
      make
  ```
- Move to KRACKLab/lab/ex2/mininet-wifi/
- Run the following command to install Mininet-WiFi
  ```
    sudo util/install.sh -Wlnfv
  ```
- Move to the Downloads folder
- Obtain wpa_supplicant 2.3 source code by executing
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
- Move to the Downloads folder
- Download Linux Kernel version 4.4 (fix for KRACK attack introduced in later version) by running:
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
- Restart and when grub load select ``` other options > linux-kernel-4.4.0-generic```
- Run ex2.py with (remember exe chmod +x ./startAttack.sh before start)
  ```
  sudo python3 ex2.py
  ```
