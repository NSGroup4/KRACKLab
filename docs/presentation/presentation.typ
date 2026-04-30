#import "../lib/common.typ": labNumber, vulnName, course
#import "../lib/commonSlide.typ": cover, slide

#cover([Laboratory #labNumber: The #vulnName vulnerability])

#slide("A small note regarding the VM",[
  
  #grid(
    columns: (50%,50%),
    align: (x,y) => {
      if(x==1) {
        center
      } else {
        left
      }
    },
    [
      #text(size: 1.5em)[

        Login credentials are:

        - Username: *_vm_*
        - Password: *_vm_*

        *NOTE*: you *MUST* boot on Kernel 4.4.0 $arrow.r.filled$ You can check by running *_uname -r_* in a terminal)

        If not, *REBOOT THE MACHINE* and go to *_"Advanced options for Ubuntu"_* > *_"Kernel 4.4.0-040400-generic"_*

      ]
    ],
    [
      #image("img/Mtt/images/boot1.png", width: 60%)
      #image("img/Mtt/images/boot2.png", width: 60%)
    ]
  )

])

#slide("A small note regarding CCMP",[
  
  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[

      Several protocols usable for *confidentiality* between AP and Client:

      #list(marker: (_)=>{[#v(-0.2em) #image("img/Mtt/icons/mdi--key.svg")]},
        [*TKIP*],
        [*CCMP*]
      )
      
      - *TKIP* used *RC4* as a stream cipher $arrow$ *no longer safe* (*RC4 NOMORE* vulnerability);
      - *CCMP* use *AES* in *CCM* mode.

      CCMP: *keystream* with *various elements* together in the *Initialization Vector (IV)*.

      #align(center)[$arrow.b.filled$]

      *Nonce* should be inserted for freshness, but usually *packet number* is *used*

      PTK reinstallation $arrow.r.filled$ packet number reset $arrow.r.filled$ keystream reuse $arrow.r.filled$ confidentiality compromised (see later slides)

    ]
  ],
    [
      #figure(
        image("img/Mtt/images/stream-cipher.png"),
        numbering: none,
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.]
      )
    ]
  )

])

#slide("Exercise 2 (1/2)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
      
        Using a network simulator: *Mininet-WiFi*

        Topology:
        - *sta1*: vulnerable *wireless station*
        - *fakeAp*: an *access point*

        *sta1* $arrow.r.filled$ *wpa_supplicant* (*vulnerable version 2.3*) $arrow.r.filled$ *fakeAp*

        *fakeAp* $arrow.r.filled$ Python *detector script* $arrow.r.filled$ modified *hostapd istance*

        *NOTE*: hostapd *reject* message 4 *automatically*
        
        #align(center)[$arrow.b.filled$]
        
        The *script* will *forward message 3* to sta1 and *check for nonce repetitions*.
      
      ]
    ],
    [
      #v(2em)
      #move(dx: 30pt, dy: 0pt)[#image("img/Mtt/icons/game-icons--pc.svg", width: 30%) #v(-2em) #text(size:1.5em)[#align(center)[*sta1*]]] 
      
      #move(dx: 85pt, dy: 0pt)[#text(size: 4em)[$fence.dotted$]]
      #move(dx: 50pt, dy: 0pt)[#image("img/Mtt/icons/catppuccin--exe.svg", width: 20%) #align(center)[#text(size: 1.5em)[#h(-2em) *wpa_supplicant v2.3*]]]
      
      #move(dx: 180pt, dy: -255pt)[#text(size: 4em)[$arrow.l.r.filled$]]
      #move(dx: 250pt, dy: -354pt)[#image("img/Mtt/icons/mdi--router-wireless.svg", width: 25%) #text(size:1.5em)[#align(center)[*fakeAp*]]]
      #move(dx: 300pt, dy: -354pt)[#text(size: 4em)[$fence.dotted$]]
      #move(dx: 265pt, dy: -353pt)[#image("img/Mtt/icons/mdi--language-python.svg", width: 20%)]
    ]
  )
])

#slide("Exercise 2 (2/2)", [
  #text(size: 1.5em)[
    
    #grid(
      columns: (53%,47%),
      [
        Follow the *wizard* (*_Ex2 Wizard_*) you can *run* from the *Desktop*

        - *NOTE*: You'll be prompted for the *vm password* (which is *_vm_*);
        - *NOTE*: You *must* be on *Kernel 4.4*. Test it by running *_uname -r_* in a terminal.
        - *NOTE*: be careful with commands, it's \ *_./wpa_supplicant23_* #h(0.5em) *WITH*  #h(0.5em) *_./_*

        Explanation on the *wpa_supplicant command*:

        ```shell-unix-generic
        ./wpa_supplicant23 -i sta1-wlan0 -c "wifiConfig.conf"
        ```

        - *-i* means _*"use the interface sta1-wlan0"*_, *sta1-wlan0* is the *wireless interface* of *sta1*;
        - *-c* "wifiConfig.conf", use the *configuration file _wifiConfig.conf_*, which simply contains the *details of the network* (mainly *SSID* and *passphrase*)
      ],
      [
        #align(center+horizon)[#image("img/Mtt/images/ex2.png")]
      ]
    )
  ]
])

#slide("Consequences (1/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
      
        Why requiring *freshness*? \
        Stream ciphers use xor (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Given:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
      ]
    ],
    [
      #figure(
        image("img/Mtt/images/stream-cipher.png"),
        numbering: none,
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.]
      )
    ]
  )

])

#slide("Consequences (2/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*] 
      ]
    ],
    [
      #figure(
        image("img/Mtt/images/stream-cipher.png"),
        numbering: none,
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.]
      )
    ]
  )

])

#slide("Consequences (3/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
      ]
    ],
    [
      #figure(
        image("img/Mtt/images/stream-cipher.png"),
        numbering: none,
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.]
      )
    ]
  )

])

#slide("Consequences (4/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*K $xor$ K $xor$ P' $xor$ P*]
      ]
    ],
    [
      #figure(
        image("img/Mtt/images/stream-cipher.png"),
        numbering: none,
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.]
      )
    ]
  )

])

#slide("Consequences (5/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*K $xor$ K $xor$ P' $xor$ P*]
      ]
    ],
    [
      #grid(
        columns: (100%),
        [
          #text(size: 1.5em)[
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *K $xor$ K* = *0*] 
            #align(center)[$arrow.b.filled$]
            #align(center)[*0 $xor$ P' $xor$ P*]
          ]
        ],
        [
          
        ]
      )
    ]
  )
])

#slide("Consequences (6/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*K $xor$ K $xor$ P' $xor$ P*]
      ]
    ],
    [
      #grid(
        columns: (100%),
        [
          #text(size: 1.5em)[
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *K $xor$ K* = *0*] 
            #align(center)[$arrow.b.filled$]
            #align(center)[*0 $xor$ P' $xor$ P*]
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *0 $xor$ P'* = *P'*]
            #align(center)[$arrow.b.filled$]
            #align(center)[
              Remains *P' $xor$ P*
            ]
          ]
        ],
        [
          
        ]
      )
    ]
  )
])

#slide("Consequences (7/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*K $xor$ K $xor$ P' $xor$ P*]
      ]
    ],
    [
      #grid(
        columns: (100%),
        [
          #text(size: 1.5em)[
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *K $xor$ K* = *0*] 
            #align(center)[$arrow.b.filled$]
            #align(center)[*0 $xor$ P' $xor$ P*]
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *0 $xor$ P'* = *P'*]
            #align(center)[$arrow.b.filled$]
            #align(center)[
              Remains *P' $xor$ P*
            ]
            #align(center)[$arrow.b.filled$]
            #align(center)[
              Knowing *P* or *P'* (ex. header) $arrow.r.filled$ *decrypt the counterpart!*
            ]
          ]
        ],
        [
          
        ]
      )
    ]
  )
])

#slide("Consequences (8/8)", [

  #grid(
    columns: (50%,50%),
    [
      #text(size: 1.5em)[
        Stream ciphers uses *xor* (symbol being *$xor$*). Two properties:
        - *A $xor$ A* = *0*
        - *0 $xor$ A* = *A*
        Let's say we have:
        - *K* *reused keystream*
        - *P* and *P'* *plaintext*
        - *C* and *C'* *ciphertext*
        #align(center)[*C* = *P $xor$ K* and *C'* = *P' $xor$ K*] 
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C'* = *(P $xor$ K)* *$xor$* *(P' $xor$ K)*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*C $xor$ C*'= *P $xor$ K $xor$ P' $xor$ K*]
        #align(center)[$arrow.b.filled$]
        #align(center)[*K $xor$ K $xor$ P' $xor$ P*]
      ]
    ],
    [
      #grid(
        columns: (100%),
        [
          #text(size: 1.5em)[
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *K $xor$ K* = *0*] 
            #align(center)[$arrow.b.filled$]
            #align(center)[*0 $xor$ P' $xor$ P*]
            #align(center)[$arrow.b.filled$]
            #align(center)[*But* *0 $xor$ P'* = *P'*]
            #align(center)[$arrow.b.filled$]
            #align(center)[
              Remains *P' $xor$ P*
            ]
            #align(center)[$arrow.b.filled$]
            #align(center)[
              Knowing *P* or *P'* (ex. header) $arrow.r.filled$ *decrypt the counterpart!*
            ]
          ]
        ],
        [
          #v(2em)
          #text(size: 1.5em)[And sometimes it's even worse: *wpa_supplicant v2.5* installs an *all-0 key*]
        ]
      )
    ]
  )
])

#slide("AI Usage Declaration and other information",[

  #align(center+horizon)[
    During the editing of this document, the team may have used Artificial Intelligence (AI) based tools in order to improve the clarity of the text after the content was already written.
    This process was performed in order to improve the readability, clarity and/or formatting of the document, or for other uses explicitly permitted by the #course regulation published on Google Classroom.

    As described in the #course regulation, AI was used only as an auxiliary support: we, as a team, truly believe in the importance of learning, and in the fact that knowledge is something that cannot be acquired without dedication and legitimate hard work.
  ]

])