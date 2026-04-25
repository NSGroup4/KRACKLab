#import "../lib/common.typ": labNumber, vulnName, course, authors
#import "../lib/commonReport.typ": firstPage, indexPage, docBody

#firstPage("Laboratory "+labNumber, authors.matteo)

#pagebreak()

#indexPage()

#docBody([

  = Introduction

  == KRACK attacks: Key Reinstallation Attack
  //Max 1 pg. //Explain also what hostapd is, what wpa_supplicant is

  = Key Reinstallation Attack in a simulated environment

  == Environment replication
  
  The second exercise of the 4#super("th") laboratory consisted in a replication of the attack in a simulated environment created by Mininet-WiFi@mnwifi, a wireless network simulation software. The laboratory also uses a modified version of the `krack-test-client.py` script@script that Mathy Vanhoef created to test if a client was vulnerable to the Key Reinstallation Attack: in this version only the packet number and the eventual installation of an all-0 key would be tested.
  Apart from a vulnerable wpa_supplicant, a "compatible" Linux Kernel, like 4.4.0, has to be installed too, otherwise the script made by Mathy Vanhoef will say the supplicant is not vulnerable due to modification that were introduced in Linux.

  To summarize,the exercise require the following software:

  #figure(
    table(
      align: center+horizon,
      columns: (33%,33%,33%),
      table.header([*Program*],[*Version*],[*Source*]),
      [Mininet-WiFi], [Commit 070ea2d], [Official Mininet-WiFi website@mnwifi],
      [Official KRACK testing scripts by Mathy Vanhoef], [Commit 2dc8012], [Official repository for the script@script],
      [wpa_supplicant], [2.3], [Official website of wpa_supplicant@wpa_sup],
      [Xubuntu (Operating System)], [24.04.4 (minimal)], [Xubuntu official website@xubuntu],
      [Modified `krack-test-client.py` script, exercise wizard and other configuration files], [1.0], [Official GitHub repository of the fourth laboratory of the Network Security class @ UniTn (2025/26)@repo],
      [Linux Kernel (and relative headers)], [4.4.0-040400], [Ubuntu Linux Kernel 4.4 official download page@kernel4.4],
      [Wireshark], [4.6.4], [Official Wireshark website@wireshark]
    ),
    caption: [Environment requirements] 
  )

  After installing the operating system, the most straightforward way to install everything that is needed is by cloning the laboratory repository@repo with the command:
  ```shell-unix-generic
      git clone --recurse-submodules https://github.com/NetSecGroup5/KRACKLab.git
  ```
  This will automatically clone both the script and configuration files for the exercise, as well as the correct Mininet-WiFi repository and the original KRACK test scripts. After that, it is possible to install Mininet-WiFi by running, from the Mininet-WiFi folder located under `lab/ex2/mininet-wifi` of our git repository, the following command:
  ```shell-unix-generic
    sudo util/install.sh -Wlnfv
  ```

  Next, in order to prepare the environment necessary for executing the modified script, run, from the folder in `lab/ex2/krackattacks-script/krackattacks` the following two scripts:
  ```shell-unix-generic
      ./build.sh
      ./pysetup.sh
  ```

  Next, extract the source code of wpa_supplicant version 2.3, navigate to the wpa_supplicant folder, and, after generating the configuration files with `cp defconfig .config`, modify the file by uncommenting `CONFIG_LIBNL32=y` (a library needed for the compilation) and inserting the line `CONFIG_TLS=internal` (to allow compilation with the most recent openssl library, otherwise an older version would be required). Next, run `make` and copy the compiled executable inside the `lab/ex2` folder of our repository, renaming it in `wpa_supplicant23`.

  Finally, after installing Wireshark via `apt` or download and configuring it to decrypt WLAN messaging by adding `abcdefgh:testnetwork` (password and SSID of the compromised wireless Access Point, respectively) in `Edit > Preferences > Protocols > IEEE 802.11 > Decryption keys > new field > Key Type`, download the 4.4.0 Linux Kernel and relative headers, the install them by running:

  ```shell-unix-generic
  sudo dpkg -i linux*.deb
  ```

  Lastly, adjust your boot loader settings in order to boot with the older Kernel: it is now possible to run the 2#super("nd") exercise wizard by running:

  ```shell-unix-generic
  sudo python3 ex2.py
  ```

  It is possible to read a step-by-step guide on the laboratory repository@repo.

  == Testing with the wizard

  In order to ease the execution of the exercise, a graphical wizard was created to guide students through the various step. Executing it will allow to easily create the necessary network topology with Mininet-WiFi, made of two wireless network station, *fakeAp*, that will execute the modified testing script, and *sta1*, which will represent the victim.

  It is necessary to spend a few words to talk about the script: in summary, what it does is creating, by taking control over fakeAp wireless network card, an access point using *hostapd*, a software specifically designed for this task, modified in order for it to drop message 4 packets of the handshake so that it will automatically generate valid message 3 packets that the script will forward to *sta1*. Every message 4 is then analyzed to understand if an all-0 key has been reinstalled (by trying to decrypt the message) or if a packet number already used was, indeed, used again.

  The wizard will then make the user open a shell for fakeAp (to activate the script as just described by running a custom script called `startAttack.sh`, which copy the modified version of the script in the `krackattacks\krackattack` folder, the right hosatpd configuration in the `krackattacks\hostapd` folder, for then activating a python environment and running the script) and one for sta1 (to make the virtual device connect to the script network via a vulnerable instance of wpa_supplicant, all is possible using an appropriate configuration, see the `wifiConfig.conf` file, and the command `./wpa_supplicant23 -i sta1-wlan0 -c "wifiConfig.conf"`): as it is possible to read in @results, the script will correctly tell the user that sta1 re-used a packet number, indicating that the key reinstallation was successful.

  In order to better see the packet number re-use, the wizard invite the user to open Wireshark (which is automatically configured to capture only the packets of interest) and execute some `ping` to the Access Point with `sta1 ping -c 14 192.168.100.254` (this being the IP address of fakeAp): see @results for the results.

  #pagebreak()
  == Results <results>

  //Max 1 pg

  = Consequences of the attack

  The 802.11i standard allow the use of two different protocols for data confidentiality: TKIP and CCMP, both based on stream ciphers, which are a type of algorithm that encrypt messages with a XOR operation between the plaintext and a generated keystream. However, in both cases security is guarantee only if the keystream always change and does not contain predictable (_biased_) section.

  In case of TKIP, a stream cipher called RC4 is used, which is notoriously known to produce biased keystream and this is one of the reason why TKIP is now deprecated (see the RC4 NOMORE vulnerability@rc4nomore, which was also discovered by Mathy Vanhoef).

  CCMP, instead, use AES, a block cipher (therefore, an algorithm that divide the plaintext into blocks and encrypt each of them via various operations), in CCM mode: the keystream is guarantee to be unique as long as, under the same starting key, the Initalization Vector (IV), a combination of the sender MAC, some flags and a 48-bit nonce which is usually just the message number (therefore, it is used as a replay counter), is not repeated.

  The reason why it is essential for stream cyphers to not encrypt using the same keystream is related on how the XOR operator works. Considering M as the plaintext *M*\essage and K as the *K*\eystrem, the *C*\iphertext C is obtained by computing *M$xor$K*. Therefore, computing *C$xor$M* will make anyone obtain the keystream *K*. If a keystream is reused, this means it is possible to obtain a ciphertext *C'=M'$xor$K*. However, following a simple sequence of operation: *C$xor$C'*=*(M$xor$K)$xor$(M'$xor$K)*=*M$xor$K$xor$M'$xor$K*=*K$xor$K$xor$M'$xor$M* but, because of the XOR properties and given a random value A, *A$xor$A=0* and, *A$xor$0=A*, therefore we can say that *K$xor$K$xor$M'$xor$M*=*0$xor$M'$xor$M*=*M'$xor$M*. If M and M' are two normal packet, they will both contain frames of protocols like TCP, which are highly predictable, and since it is possible to easily guess correctly at least a portion of, for example, M', we can use that knowledge in the *M'$xor$M* operation to get the content of the original message *M*.

  The Key Reinstallation Attack cause a reinstallation of the PTK and, consequently, a reset of the packet number used in the IV of CCMP: based on what just discussed, a simple capture of packets before and after the re-installation is sufficient to be able to decrypt at least a portion of one of them: given the normal web traffic, nowadays over HTTPS, this will not make possible to decrypt the payload of the majority of packets, but it is still a very important vulnerability if HTTP is used, potentially breaking both confidentiality and integrity of the packets.

  More importantly, it has been discovered that wpa_supplicant version 2.4 and 2.5 have a more dangerous vulnerability: in order to be compliant with the 802.11 standard, both clear the temporal key from memory once it has been installed: this cause, if the key reinstallation attack is performed, the installation of an all-0 key, again breaking stream ciphers assumption of a non-predictable keystream and allowing to easily decrypt encrypted wireless messages.

  Finally, it was discovered that all Android 6.0 devices were shipped with a modified version of wpa_supplicant affected by the all-0 key problem. Given the diffusion of this operating system, impact of the Key Reinstallation Attack is critical nevertheless.


  //INCLUDE AI USAGE DECLARATION. MANDATORY. YOU CAN ADD LINES AFTER THE INCLUSION.
  #include "commonParagraph/AIUD.typ"
  == Additional information

  The information regarding the vulnerability and the possible consequences have been obtained from the published paper@krackattackpaper and the official website@krackattackwebsite of the vulnerability.

  In order to recreate the attack in a virtual environment, essential was the documentation found in the KRACK test scripts repository@script.

  #bibliography("sitography/Mtt/reportMttSit.yml", title: "Sitography")

], "Laboratory "+labNumber)