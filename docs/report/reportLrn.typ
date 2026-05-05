#import "../lib/common.typ": labNumber, vulnName, course, authors
#import "../lib/commonReport.typ": firstPage, indexPage, docBody

#firstPage("Laboratory "+labNumber, authors.lorenzo)

#pagebreak()

#indexPage(imageList: false, tableList: false)

#docBody([
#show raw.where(block: true): code => box(
    fill: luma(90%),
    outset: 0.3em,
    radius: 0.4pt
)[#code]

  = Introduction
  This report aims to provide the necessary instructions and explanations
  needed to replicate the lab activity presented on May 6th 2026 for the
  Network Security course.

  To follow the activity, it is assumed that the reader knows some basics
  on Wireless networks (WLAN) and WPA2. Minimal knowledge on Linux command
  line may also prove useful.

  The focus for this report is the attack on the Fast BSS Transition handshake

  

  = Environment Setup
  == VM setup
  A virtual machine image is provided in the course's Classroom page
  alongside all other images used across all lab activities. The easiest
  way to prepare the environment is to download our image (Group 5) and
  load it into Virtualbox or any other compatible hypervisor. If you choose
  this option, the credentials to access the VM are:
  ```
  Username: vm
  Password: vm
  ```

  If you decide to recreate the environment from scratch, here are the
  steps you need to follow:
  + Start from Xubuntu 24.04.4 minimal @xubuntu
  + Install `wireshark`@wireshark and `arping`
  + Install `git` if not present, then clone our repository containing the
    necessary tools
    ```shell-unix-generic
    git clone --recurse-submodules https://github.com/NetSecGroup5/KRACKLab.git
    ```
  + From the cloned repository, install mininet wifi:
    ```
    cd lab/ex2/mininet-wifi
    sudo util/install.sh -Wlnfv
    ```
  + Run the setup scripts fro Vanoef's tools:
    ```shell-unix-generic
    # From the root of the repository:
    cd lab/ex2/krackattacks-script/krackattacks      
    ./build.sh
    ./pysetup.sh
    ```
  + Build hostapd and wpa_supplicant v2.3 from source:
    + Clone the hostapd repository
    + checkout into the 2_3 branch
    + in the hostapd/wpa_supplicant directory, copy the `defconfig` file into `.config`
    + In the `.config` file, uncomment these lines:
      ```
      LIBNL32=y
      IEEE80211R=y
      ```
      The first one relates to compilation libraries, the second one is to
      enable FT.

      If the build step fails, also uncomment the line
      ```shell-unix-generic
      CONFIG_TLS=openssl
      ```
      and edit it into
      ```shell-unix-generic
      CONFIG_TLS=internal
      ```

    + Compile both
      ```shell-unix-generic
      make clean
      make
      ```
    + If all goes well check the version of the compiled output:
      ```shell-unix-generic
      ./hostapd -v
      ```
      You should see 2.3
    + Download the linux kernel 4.4@kernel4.4 and related headers, then
      install them
      ```shell-unix-generic
      sudo dpkg -i linux*.deb
      ```
      #underline([Make sure to also edit the GRUB configs to add enough
      time to select the kernel you want on boot])
  
  == Exercise setup
  + Copy the vulnerable hostapd, wpa_supplicant and wpa_cli versions you've
    compiled into the `lab/ex3` directory of the repository
  + The exercise instructions assume you rename wpa_supplicant as `wpa_supp`.
    Also ensure all three of those executable have execution permissions\
    `chmod u+x <file>`
  + For convinience, copy the `lab/ex2/krackattack-scripts` directory
    into `lab/ex3/`, otherwise make sure to adjust the relative paths
    of future commands to accomodate for the new location.
  + From `lab/ex3`, copy the file `krack_ft.py` into
    `krackattack-scripts/krackattack`

  From here, you should be all set for exercise 3 of the lab

  = Attacking the Fast BSS Transition
  A set made of a single Access Point and one or more stations is called
  a Base Service Set. Many networks use multiple BSS, all under the
  same Service Set Identifier (*SSID*). Fast BSS Transition is used to
  drastically reduce the time it takes for a station to roam from one
  AP to the next within the same network.

  An FT handshake is initiated by the station and consists of:
  - `Authentication Request(SNonce)`
  - `Authentication Response(ANonce, SNonce)`
  - `Reassociation Request(ANonce, SNonce, MIC)`
  - `Reassociation Response(ANonce, SNonce, MIC, GTK)`

  According to the protocol, key installation should happen after the
  second message. This means that attempting to reinstall the key by replaying
  the first one will fail as the AP generates a different nonce to
  derive the key upon receiving a replayed Authentication Request.
  Instead, most implementations did the installation after the fourth
  message, causing a repeated Reassociation Request to be accepted and
  thus the key being reinstalled.

  \
  This attack only involves replaying a message, unlike other kinds of
  KRACK that need to also withhold packets. Therefore, this attack does
  not need a _Man in the Middle_ position to be performed, it only
  requires the ability to sniff and replay packets.


  = Exercise 3
  To do the exercise, start by launching the `ex3.py` script.
  On the Virtual Machine we have provided, you'll find a shortcut as an
  icon in your desktop, otherwise you can find it in the cloned
  repository under `lab/ex3`. Ensure you are running the script as
  root, as mininet wifi and wireshark require elevated privileges.

  The script will open a graphical interface with instructions and
  buttons used for running certain commands in a more convenient way.
  Manual interaction by the lab participant is still expected for the
  core part of the lab, the GUI will not do everything for you.

  == Start the simulated network
  Begin the exercise by using the GUI to run mininet wifi. The button
  will create the network topology used for the exercise:
  - sta1: our client
  - fakeAp1: our access point
  For the purpose of this exercise we only need a single access point.
  Keep in mind that in a real world scenario, FT requires 2 different
  APs to trigger while here we are able to force our station to roam.

  == Start the AP
  Use the GUI to open a terminal on the access point.
  Here we want to start the access point by running a vulnerable
  version of hostapd. In the current directory of the terminal you should
  see an executable for hostapd 2.3 and a file with a minimal configuration
  to support WPA2 and FT.

  Run the command:
  ```shell-unix-generic
  ./hostapd hostapd.conf
  ```
  Optionally add the `-d` flag for more detailed logs on the console

  While mininet wifi is able to create a node as an Access Point, both of
  ours are created as stations due to some challenges with assigning IP
  addresses for generating traffic that will be needed later on. It will
  still behave as an AP after manually running `hostapd`

  == Connect the station to the AP
  For the next step, use the GUI to open a terminal on the station.
  You should see an executable for wpa_supplicant shortened ad `wpa_supp`,
  as well as a minimal configuration file.

  The `wpa_supplicant` execution is wrapped by the attack script. It is
  a modified version of the testing script by Vanhoef@script, so running
  it requires us to move to the script's directory and activate the
  python virtual environment first:
  ```shell-unix-generic
  cd krackattack-scripts/krackattack
  source venv/bin/activate
  python3 krack_ft.py ../../wpa_supp -i sta1-wlan0 -c ../../supplicant.conf
  ```
  The script does 3 things:
  - Start wpa_supplicant
  - Create a monitoring interface to listen for FT handshake messages
  - Store and replay the first Reassociation Request it detects
  The main modification made to the script is that instead of replaying
  the Reassociation Request every time an encrypted frame is detected, it
  is replayed every 1.5 seconds.

  After a brief delay the station should connect to the AP

  == Force roaming to cause FT
  Use the GUI to open wireshark and then a terminal on the station.
  Start the copy of `wpa_cli` in the current directory:
  ```shell-unix-generic
  ./wpa_cli
  ```

  Within the cli, run these two commands:
  ```
  > status                 # Check connection infos
  > roam 02:11:11:11:11:11 # Force roaming to the station with that MAC (fakeAp1)
  ```
  The script running on the station should catch the Reassociation Request
  it sent and should begin replaying it over and over.
  Observe the repeating association requests and responses in wireshark

  == Generate traffic and observe results
  Use the button on the GUI to generate traffic. This is equivalent to
  running the `arping` command from the station to the AP.

  In wireshark, observe the CCMP Initialization Vector of the generated
  traffic. In a vulnerable environment those should be reset to 1 whenever
  an association response is sent.


  //INCLUDE AI USAGE DECLARATION. MANDATORY. YOU CAN ADD LINES AFTER THE INCLUSION.
  = Artificial Intelligence Usage Declaration and additional information
  For the writing of this specific report no artificial intelligence was
  used, for any purpose.
  //#include "commonParagraph/AIUD.typ"

  #bibliography("sitography/Lrn/reportLrnSit.yml", title: "Sitography")
], "Laboratory "+labNumber)
