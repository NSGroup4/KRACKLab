#import "../lib/common.typ": labNumber, vulnName, course
#import "../lib/commonSlide.typ": cover, slide

#cover([Laboratory #labNumber: The #vulnName vulnerability])

#slide("A small note regarding the VM",[
  
  #text(size: 1.5em)[

    - Username: _vm_
    - Password: _vm_

    *BE CAREFUL*: you *NEED*  to boot on Kernel 4.4 (test with _uname -r_ in a terminal)

    If not *REBOOT THE MACHINE* and go to "Advanced Options" > "Kernel 4.4 (generic)"

  ]

])

#slide("A small note regarding CCMP",[
  
  #text(size: 1.5em)[

    There are several protocols that can be used to protect data between AP and Client:
      - TKIP
      - CCMP
    
    TKIP used RC4 as a stream cipher -> no longer safe (RC4 NO MORE vulnerability)\
    CCMP use AES in CCM mode

    CCMP creates a keystream with various elements, putting them together in the Initializator Vector.

    Between these elements, a nonce is inserted for freshness, usually the packet number

    By reinstaling the PTK, the packet number is also bought to a previous value -> no more freshness -> keystream reuse -> confidentiality compromised

  ]

])

#slide("Exercise 2 (1/2)", [
  #text(size: 1.5em)[
    We will now test the knowledge we just acquired
  
    In order to see the vulnerability "in action", we'll use a simulated network environment with Mininet-WiFi.

    The topology consists of two things:
    - sta1: a wireless station that will act as a vulnerable client
    - fakeAp: an access point which will run a special python script

    In the station, you'll prompt a software, wpa_supplicant (a vulnerable version, 2.3), to connect to fakeAp.

    fakeAp will use another software called hostapd to create an access point.

    Note: hostapd has been modified in order for it to reject the message 4. \
    #h(2.5em) The script will forward message 3 to sta1 and check for nonce repetitions.
  
  ]
])

#slide("Exercise 2 (2/2)", [
  #text(size: 1.5em)[
    
    Follow the wizard you can run from the desktop

    NOTE: you will be prompted for inserting the vm password (which is _vm_) \
    NOTE: you need to be on Kernel 4.4. Test it by running _uname -r_ in a terminal
    NOTE: be careful with commands, it's _./wpa_supplicant23_ #h(1em) *WITH*  #h(1em) _./_

    A brief explanation on the wpa_supplicant command:

    ./wpa_supplicant23 -i sta1-wlan0 -c "wifiConfig.conf"

    - -i means "use the interface sta1-wlan0", sta1-wlan0 is the name of the wireless interface
    - -c "wifiConfig.conf", use the configuration file _wifiConfig.conf_, which simply contains the details of the network (SSID and passphrase)

  
  ]
])

#slide("Consequences", [
  #text(size: 1.5em)[
    
    Why the freshness is needed?

    Stream ciphers uses xor. Two properties:
    - A$xor$A=0
    - 0$xor$A=A

    Let's say we have:
    - C or C' ciphertext
    - K is the keystream
    - P and P' are plaintext

    C = P$xor$K and C' = P'$xor$K

    C$xor$C'= (P$xor$K) $xor$ (P'$xor$K) \
    C$xor$C'= P$xor$K$xor$P'$xor$K can be reorganized in K$xor$K$xor$P'$xor$P \

    But K$xor$K=0 -> 0$xor$P'$xor$P but 0$xor$P'=P' so we have P'$xor$P

    If we know part of P or P' (like an header) we can use it to decrypt the counterpart!


  
  ]
])

#slide("AI Usage Declaration and other information",[

  #align(center+horizon)[
    During the editing of this document, the team may have used Artificial Intelligence (AI) based tools in order to improve the clarity of the text after the content was already written.
    This process was performed in order to improve the readability, clarity and/or formatting of the document, or for other uses explicitly permitted by the #course regulation published on Google Classroom.

    As described in the #course regulation, AI was used only as an auxiliary support: we, as a team, truly believe in the importance of learning, and in the fact that knowledge is something that cannot be acquired without dedication and legitimate hard work.
  ]

])