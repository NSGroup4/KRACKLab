#import "../lib/common.typ": labNumber, vulnName, course, authors
#import "../lib/commonReport.typ": firstPage, indexPage, docBody

#firstPage("Laboratory "+labNumber, authors.matteo)

#pagebreak()

#indexPage()

#docBody([

  = Introduction

  == KRACK attacks: Key Reinstallation Attack <intro>

  The KRACK attacks are a series of vulnerability that target both clients connected to Access Points and Access Points themselves: in this report one of them in particular will be discussed, that being the reinstallation of the *Pairwise Transient Key (PTK)* on a vulnerable client.

  Generally, in order to encrypt messages between clients and the Access Point, a *4-way handshake* is performed, as shown in the first four messages in the following @scheme:

  #grid(
    columns:(50%,50%),
    [
      #figure(
        image("img/Mtt/scheme.png", width: 70%),
        caption: [KRACK attack scheme, "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2" by Mathy Vanhoef@krackattackpaper]
      )#label("scheme")
    ],
    [
      *First*, the Access Point (called _"Authenticator"_), send a message to the client (called _"Supplicant"_), containing a random nonce and a replay counter (_ANonce_ and _r_, respectively). The client uses the *ANonce*, together with the *Pairwise Master Key (PMK)*, another newly generated nonce (called _"SNonce"_) and the client and Access Point MAC addresses, to generate the PTK, that is later divided into sub-keys: the *Key Encryption Key (KEK)*, to encrypt the *Group Temporal Key (GTK)*, a key that protect messages the Access Point send to its client, when this is delivered to newly connected client; the *Key Confirmation Key (KCK)*, that is used for integrity of the messages of this handshake, and the *Temporal Key (TK)*, used to protect data packets sent to the Access Point from the client with some ciphers like *CCMP*.
    ]
  )

  After that, the client sends, with the *second message* of the handshake, the *SNonce* to the Access Point (but not before securing the message for *integrity* using the *KCK*. Notice that all messages of the handshake from the second have an integrity check), *then* the Access Point sends the *GTK* to the client, together with a command for the client to install the *PTK*. Finally the client acknowledge the third message by sending a *fourth message* to the Access Point: this will make the Access Point install the *PTK*.

  Now, the problem: if another third message would arrive to the client, this will make the client *re-install the PTK* and *reset the packet counter*, an element used in *CCMP* to generate keystreams that are always different. What just described is precisely what happen in the KRACK attack: why this is problematic is explained in @consequences.

  Specifically, the Access Point usually runs a software called *hostapd* to create a wireless network, while the client uses another application, called *wpa_supplicant*, in order for it to be able to connect to Access Points: the KRACK vulnerability has been patched in modern versions of this wpa_supplicant, however *versions* like *2.3* are *still vulnerable* to what was just described since the *patch* was *not backported*.

  Finally, some versions of wpa_supplicant had a worse problem: for example, in *version 2.5* a change introduced probably in the effort of satisfying a suggestion in the 802.11 standard *caused*, upon reception of a repeated third message of the handshake, the *installation* of an *all-0 key*, _de facto_ providing *no confidentiality* over packets sent to the Access Point.

  = Key Reinstallation Attack in a simulated environment

  == Environment replication
  
  The *second exercise* of the 4#super("th") laboratory consisted in a replication of the attack in a *simulated environment* created by *Mininet-WiFi*@mnwifi, a wireless network simulation software. The laboratory also used a modified version of the  test  script `krack-test-client.py`@script that Mathy Vanhoef created to check whether a client was vulnerable to the Key Reinstallation Attack: in this version, only the *packet number* and the *eventual installation* of an *all-0 key* would be *tested*.
  Apart from a vulnerable wpa_supplicant, a "compatible" *Linux Kernel*, like *4.4.0*, has also to be *installed*: if not, *the script will state that the supplicant is not vulnerable* due to various modifications introduced in Linux.

  To summarize, the exercise requires the following software:

  #figure(
    table(
      align: center+horizon,
      columns: (33%,33%,33%),
      table.header([*Program*],[*Version* or *Commit ID*],[*Source*]),
      [*Mininet-WiFi*], [Commit 070ea2d], [Official Mininet-WiFi website@mnwifi],
      [*Official KRACK testing scripts by Mathy Vanhoef*], [Commit 2dc8012], [Official repository for the script@script],
      [*wpa_supplicant*], [2.3], [Official website of wpa_supplicant@wpa_sup],
      [*Xubuntu (Operating System)*], [24.04.4 (minimal)], [Xubuntu official website@xubuntu],
      [*Modified `krack-test-client.py` script, exercise wizard and other configuration files*], [1.0], [Official GitHub repository of the fourth laboratory of the Network Security class @ UniTn (2025/26)@repo],
      [*Linux Kernel (and relative headers)*], [4.4.0-040400], [Ubuntu Linux Kernel 4.4 official download page@kernel4.4],
      [*Wireshark*], [4.6.4], [Official Wireshark website@wireshark]
    ),
    caption: [Environment requirements] 
  )

  After installing the operating system, the most straightforward way to setup everything needed is by cloning the laboratory repository@repo with the following command:
  ```shell-unix-generic
      git clone --recurse-submodules https://github.com/NetSecGroup5/KRACKLab.git
  ```
  This will clone both the script and configuration files needed for the exercise, as well as the correct Mininet-WiFi repository and the original KRACK test scripts. After that, it is possible to install Mininet-WiFi by running, from the Mininet-WiFi folder located under *`lab/ex2/mininet-wifi`* of the cloned repository, the following command:
  ```shell-unix-generic
    sudo util/install.sh -Wlnfv
  ```

  Next, in order to compile a modified version of *hostapd* that rejects messages 4 of the handshake and to prepare the environment necessary for executing the modified script, run, from the folder in *`lab/ex2/krackattacks-script/krackattacks`* the following two scripts:
  ```shell-unix-generic
      ./build.sh
      ./pysetup.sh
  ```

  Next, extract the source code of wpa_supplicant version 2.3, navigate to the wpa_supplicant folder, and, after generating the configuration files with *`cp defconfig .config`*, modify such *`.config`* file by uncommenting *`CONFIG_LIBNL32=y`* (a library needed for the compilation) and inserting the line *`CONFIG_TLS=internal`* (to allow compilation with the most recent openssl library, otherwise an older version would be required). Next, run *`make`* and copy the compiled executable inside the *`lab/ex2`* folder of our repository, renaming it in *`wpa_supplicant23`*.

  Finally, after installing Wireshark and configuring it to decrypt WLAN messages by adding *`abcdefgh:testnetwork`* (*passphrase* and *SSID* of the wireless network, respectively) in *`Edit > Preferences > Protocols > IEEE 802.11 > Decryption keys > new field > Key Type`*, download the *4.4.0 Linux Kernel* and relative headers, then install them by running:

  ```shell-unix-generic
  sudo dpkg -i linux*.deb
  ```

  Lastly, adjust your boot loader settings in order to boot with the older Kernel. It is now possible to run the 2#super("nd") exercise wizard by executing in a terminal the command:

  ```shell-unix-generic
  sudo python3 ex2.py
  ```

  A side note: it is possible to read a step-by-step guide on the laboratory repository@repo.

  == Testing with the wizard

  #figure(
    image("img/Mtt/script.png", width: 40%),
    caption: [Interactive wizard - step 2 of 8]
  )

  In order to ease the execution of the exercise, a graphical wizard was created to guide students through the various steps. Executing it will allow to easily create the necessary network topology with Mininet-WiFi, made of two wireless stations: *fakeAp*, that will execute the modified testing script, and *sta1*, which will represent the victim. A diagram of the attack is displayed in @scheme.

  The modified script will create, by taking control of *fakeAp wireless network card*, an Access Point using the modified *hostapd* program: since it will drop all fourth messages of the handshake, it will be forced to *generate valid message 3 packets* that the script will then forward to *sta1*. *Every message 4* is however still *analyzed* in order to understand if an *all-0 key was installed* (by trying to decrypt the message) or if a *packet number* already used was, indeed, *used again*.

  The *wizard* will then make the user *open a shell for fakeAp* (used to activate the modified test script by running *`startAttack.sh`*, which *copy* the modified *test script* in the *`krackattacks\` `krackattack`* folder and the *hostapd configuration* in the *`krackattacks\hostapd`* folder, *activate* a needed *python environment* and, finally, *running* the *test script*) and one for *sta1* (used to make the *device* *connect* to the *test script network* via a *vulnerable* instance of *wpa_supplicant*; this is possible by using an appropriate configuration, contained in the *`wifiConfig.conf`* file, and the command *`./wpa_supplicant23 -i sta1-wlan0 -c "wifiConfig.conf"`*): as it is possible to read in @results, the script will correctly tell the user that sta1 re-used a packet number, indicating that the key reinstallation was successful.

  In order to better *see* the *packet number re-use*, the wizard invite, on the second step, to open *Wireshark* (which is automatically configured to capture only the packets of interest, these being EAPOL and ICMP packet) and execute, during the final step, some *`ping`* to the Access Point by executing *`sta1 ping -c 14 192.168.100.254`* (this being the IP address of fakeAp): see @results for the results.

  
  == Results <results>

  #figure(
    kind: image,
    grid(
      columns: (50%,50%),
      align: center+horizon,
      [#image("img/Mtt/scriptResult.png", width: 100%)],[#image("img/Mtt/wireshark.png", width: 85%)],
    ),
    caption: [Attack results on the modified script and on Wireshark with wpa_supplicant v2.3]
  )#label("result")

  After activating the modified KRACK test script and making sta1 connect to fakeAp, the attack results are immediately visible on the fakeAp shell: in fact, the *test script* will quickly advise the user that *a nonce was reused*, as visible in the leftmost picture in @result.

  The *effect* just described is also perfectly visible on the *Wireshark capture*: as reported in the rightmost picture in @result, in the *"CCMP Packet Number" column* (which is, as explained in @consequences, the *nonce used by* the stream cipher *CCMP*), by looking at the *first pink block* it is possible to *notice* how every *ping message sent by sta1* has a *growing number from 1 to 5* but, *after retransmission* of the *third message* of the handshake *and*, consequently, *the reinstallation of the key*, the *second pink block of messages* start again to be *numbered from 1*, unequivocal signature of a successful attack. 

  #figure(
    image("img/Mtt/scriptResult25.png", width: 41%),
    caption: "Attack result on the modified script with wpa_supplicant v2.5"
  )#label("result2")

  The modified script is also able to detect if a worser effect of the attack happened: specifically, the *installation of an all-0 key*. As described in @intro, this is the case when *wpa_supplicant* version *2.5* is running: in @result2 it is possible to see such vulnerability being *detected* by the modified *test script*.

  = Consequences of the attack <consequences>

  The *802.11i standard* allows the usage of two different protocols for data *confidentiality*: *TKIP* and *CCMP*, both based on *stream ciphers*, which are a type of algorithm that encrypt messages with a *XOR* (*$xor$*) operation *between* the *plaintext* and a generated *keystream*. However, *security is guarantee* only *if* the *keystream always change* and *does not contain predictable* (_biased_) *sections*.

  In case of *TKIP*, a *stream cipher* called *RC4* is *used*, which is *notoriously known to produce biased keystream* and this is one of the reason why TKIP is now *deprecated* (see the *RC4 NOMORE* vulnerability@rc4nomore, which was also discovered by Mathy Vanhoef).

  On the other hand, *CCMP* uses *AES*, a *block cipher* (therefore, an algorithm that divide the plaintext into blocks and encrypt each of them via various operations), in *CCM mode*: the *keystream is guarantee to be unique as long as*, under the same starting key, *the Initalization Vector (IV)*, a combination of the sender MAC, some flags and a 48-bit nonce which is usually just the packet number in most implementation of CCMP, *is not repeated*.

  The reason why it is essential for stream ciphers to not encrypt using the same keystream is related on how the XOR operator works. Considering *P* and *P'* as the *P*\laintext and *K* as the *K*\eystrem, *C*\iphertexts *C* and *C'* are obtained by computing *P $xor$ K*. If a keystream is reused, this means it is possible to obtain a ciphertext in the following way: *C' = P'$xor$ K*.
  
  However, the following operation can be performed: 
  #align(center)[
    #grid(
      columns: (20%,5%,20%,5%,20%,5%,20%),
      align: horizon+center,
      grid.cell(align: right)[*C $xor$ C'*],[$arrow.r.filled$],[*(P $xor$ K) $xor$ (P' $xor$ K)*],grid.cell(align: right)[$arrow.r.filled$],[*P $xor$ K $xor$ P' $xor$ K*],[$arrow.r.filled$],grid.cell(align: left)[*K $xor$ K $xor$ P' $xor$ P*]
    )
  ]
  
  Two XOR properties need now to be mentioned. Given a random value A:
  #align(center)[
      #grid(
      columns: (50%,50%),
      [*A $xor$ A = 0*],[*0 $xor$ A = A*]
    )
  ]

  Therefore, se further operation can be performed:

  #align(center)[
    #grid(
      columns: (30%,5%,30%,5%,30%),
      [*K $xor$ K $xor$ P' $xor$ P*], [$arrow.r.filled$], [*0 $xor$ P' $xor$ P*], [$arrow.r.filled$], [*P' $xor$ P*]
    )
  ]

  If *P* and *P'* are two common network packets, *they will both contain frames of common protocols* (like TCP, for example), which are *highly predictable*. Therefore, since it is possible to easily guess correctly at least a portion of, for example, *P'*, such knowledge can be used to perform the operation *P' $xor$ P*, which will output at least a portion of the content of *P*.

  The *Key Reinstallation Attack cause* a reinstallation of the PTK and, consequently, *a reset of the packet number* used in the *IV* of *CCMP*: based on what was just discussed, a simple *capture of packets* before and after the re-installation *is sufficient* to be able *to decrypt at least a portion of one of them*: given the normal web traffic, nowadays over HTTPS, this will not make possible to decrypt the payload of the majority of packets, but it is still a *very important vulnerability if HTTP is used*, potentially breaking both *confidentiality* and *integrity* of the *packets*.

  As briefly mentioned in @intro, it has been discovered that *wpa_supplicant* version *2.4* and *2.5* have a far more dangerous vulnerability: in order to be compliant with the 802.11 standard, they clear the temporal key from memory once it has been installed. *This causes the installation of an all-0 key*, again *breaking stream ciphers assumption of a non-predictable keystream* and allowing to easily decrypt encrypted wireless messages.

  Finally, it was discovered that *all Android 6.0 devices* were shipped with a modified version of *wpa_supplicant* *affected* by the *all-0 key problem*. Given the diffusion of this operating system, impact of the Key Reinstallation Attack is critical nevertheless.


  = Artificial Intelligence Usage Declaration and additional information

  == Usage of AI

  During the editing of this document, Artificial Intelligence (AI) based tools have been used in order to improve the clarity of the text after the content was already written.
  This process was performed in order to improve the readability, clarity and/or formatting of the document, or for other uses explicitly permitted by the #course regulation published on Google Classroom@classroomrules.

  As described in the #course regulation, AI was used only as an auxiliary support: we, as a team, truly believe in the importance of learning, and in the fact that knowledge is something that cannot be acquired without dedication and legitimate hard work.

  == Additional information

  The information regarding the vulnerability and the possible consequences have been obtained from the published paper@krackattackpaper and the official website@krackattackwebsite of the vulnerability.

  In order to recreate the attack in a virtual environment, essential was the documentation found in the KRACK test scripts repository@script.

  #bibliography("sitography/Mtt/reportMttSit.yml", title: "Sitography")

], "Laboratory "+labNumber)