#import "../lib/common.typ": course, labNumber, vulnName
#import "../lib/commonSlide.typ": cover, slide

#cover([Laboratory #labNumber: The #vulnName vulnerability])

#slide("A small note regarding the VM", [

  #grid(
    columns: (50%, 50%),
    align: (x, y) => {
      if (x == 1) {
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
    ],
  )

])

#import "@preview/chronos:0.3.0"
#slide([The 4-way handshake], [
  #align(center + horizon, [
    #scale(160%)[
      #chronos.diagram({
        import chronos: *
        _par("S", display-name: "Supplicant")
        _par("A", display-name: "Access Point")

        _seq("A", "S", comment: "Message1(replay_counter, ANonce)")
        _seq("S", "A", comment: "Message2(replay_counter, SNonce)")
        _seq("A", "S", comment: "Message3(replay_counter + 1, GTK)")
        _seq("S", "A", comment: "Message4(replay_counter + 1)")
      })

      *4-way Handshake*
    ]
  ])
])

#slide("Exploiting the handshake (1/4)", [
  #align(center + horizon)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 1,
        columns: (60%, 40%),
        column-gutter: 1em,
        align: center,
        [#grid(
          rows: 3,
          columns: 1,
          row-gutter: 3em,
          align: left,
          [In this handshake implementation the state machine which determines exactly when and how keys are installed *was never detailed with sufficient precision*.],
          [The original WPA2 specifications *did not account* for the client's behavior upon receiving Message 3.],
          [Currently, the client *installs the PTK simply by verifying that the MIC is correct and the Replay Counter is valid*.],
        )],
        [#image("img/And/state.png", width: 100%)],
      )
    ]
  ]
])

#slide("Exploiting the handshake (2/4)", [
  #align(center + horizon)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 1,
        columns: (60%, 40%),
        column-gutter: 1em,
        align: center,
        [#grid(
          rows: 3,
          columns: 1,
          row-gutter: 3em,
          align: left,
          [An attacker intercepts and *blocks Message 4*, the Access Point will retransmit Message 3.],
          [The client will then reinstall the same key *without triggering any warnings or alarms.*],
          [This reinstallation *resets the packet number and the nonces/values* used for data packet encryption.],
        )],
        [#image("img/And/state.png", width: 100%)],
      )
    ]
  ]
])

#slide("Exploiting the handshake (3/4)", [
  #align(center + bottom)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 2,
        columns: 1,
        row-gutter: 1.5em,
        align: center,
        [With predictable nonces, an attacker who has captured the necessary handshake data can *potentially decrypt packets or replay them*],
        [#image("img/And/4way-att.png", width: 35%)],
      )
    ]
  ]
])

#slide("Exploiting the handshake (4/4)", [
  #align(center + bottom)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 2,
        columns: 1,
        row-gutter: 1.5em,
        align: center,
        [The fact that the standard did not specify the exact timing for key installation or the precise method for testing the replay counter led to *various implementations of the protocol*],
        [#image("img/And/where.png", width: 35%)],
      )
    ]
  ]
])


#slide("Exercise 1 - Handshake simulator (1/2)", [
  #align(horizon)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 2,
        columns: 1,
        row-gutter: 5em,
        align: left,
        [In this exercise we will simulate the KRACK Attack from a *theoretical perspective*.],
        [#set par(
            leading: 1.2em,
          )
          + Open the *“Ex1 Simulation”* script
          + You will be presented with *3 terminals*
            + One simulating the AP
            + One simulating the Client
            + One simulating the Man-In-The-Middle
          + Let’s play for some time…
        ],
      )
    ]
  ]

])

#slide("Exercise 1 - Handshake simulator (2/2)", [
  #align(horizon + center)[
    #block(width: auto)[
      #image("img/And/E0-0.png", width: auto)
    ]
  ]

])

#slide("A small note regarding CCMP", [
  #grid(
    columns: (50%, 50%),
    [
      #text(size: 1.5em)[

        Several protocols usable for *confidentiality* between AP and Client:

        #list(marker: _ => { [#v(-0.2em) #image("img/Mtt/icons/mdi--key.svg")] }, [*TKIP*], [*CCMP*])

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
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.],
      )
    ],
  )

])

#slide("Exercise 2 (1/2)", [

  #grid(
    columns: (50%, 50%),
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
      #move(dx: 30pt, dy: 0pt)[#image("img/Mtt/icons/game-icons--pc.svg", width: 30%) #v(-2em) #text(
          size: 1.5em,
        )[#align(center)[*sta1*]]]

      #move(dx: 85pt, dy: 0pt)[#text(size: 4em)[$fence.dotted$]]
      #move(dx: 50pt, dy: 0pt)[#image("img/Mtt/icons/catppuccin--exe.svg", width: 20%) #align(center)[#text(
          size: 1.5em,
        )[#h(-2em) *wpa_supplicant v2.3*]]]

      #move(dx: 180pt, dy: -255pt)[#text(size: 4em)[$arrow.l.r.filled$]]
      #move(dx: 250pt, dy: -354pt)[#image("img/Mtt/icons/mdi--router-wireless.svg", width: 25%) #text(
          size: 1.5em,
        )[#align(center)[*fakeAp*]]]
      #move(dx: 300pt, dy: -354pt)[#text(size: 4em)[$fence.dotted$]]
      #move(dx: 265pt, dy: -353pt)[#image("img/Mtt/icons/mdi--language-python.svg", width: 20%)]
    ],
  )
])

#slide("Exercise 2 (2/2)", [
  #text(size: 1.5em)[

    #grid(
      columns: (53%, 47%),
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
        #align(center + horizon)[#image("img/Mtt/images/ex2.png")]
      ],
    )
  ]
])

#slide("Consequences (1/8)", [

  #grid(
    columns: (50%, 50%),
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
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.],
      )
    ],
  )

])

#slide("Consequences (2/8)", [

  #grid(
    columns: (50%, 50%),
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
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.],
      )
    ],
  )

])

#slide("Consequences (3/8)", [

  #grid(
    columns: (50%, 50%),
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
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.],
      )
    ],
  )

])

#slide("Consequences (4/8)", [

  #grid(
    columns: (50%, 50%),
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
        caption: [Stream Cipher image by #link("https://commons.wikimedia.org/wiki/File:Stream_cipher.svg")[Sissssou] under CC BY-SA 3.0. Available on Wikimedia Commons.],
      )
    ],
  )

])

#slide("Consequences (5/8)", [

  #grid(
    columns: (50%, 50%),
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
        columns: 100%,
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
    ],
  )
])

#slide("Consequences (6/8)", [

  #grid(
    columns: (50%, 50%),
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
        columns: 100%,
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
              Remains *C $xor$ C'* = *P' $xor$ P* $arrow.r.filled$ *P* = *C $xor$ C' $xor$ P'*
            ]
          ]
        ],
        [

        ]
      )
    ],
  )
])

#slide("Consequences (7/8)", [

  #grid(
    columns: (50%, 50%),
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
        columns: 100%,
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
              Remains *C $xor$ C'* = *P' $xor$ P* $arrow.r.filled$ *P* = *C $xor$ C' $xor$ P'*
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
    ],
  )
])

#slide("Consequences (8/8)", [

  #grid(
    columns: (50%, 50%),
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
        columns: 100%,
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
              Remains *C $xor$ C'* = *P' $xor$ P* $arrow.r.filled$ *P* = *C $xor$ C' $xor$ P'*
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
    ],
  )
])

//
// Fast BSS Transition
//

#show raw: code => box(
  fill: luma(90%),
  outset: 0.3em,
  radius: 0.4pt,
)[#code]


#slide([Fast BSS Transition (1/2)], [
  #grid(
    columns: (50%, 50%),
    [
      #text(size: 1.5em, [
        An *AP* and a set of *stations* are called a _Base Service Set (BSS)_

        \
        *Fast BSS Transition (FT)* allows stations to quickly switch between APs in the same protected network

        \
        - Similar structure the 4-way handshake
        - Initiated by the supplicant
        - Does _not_ require a new 4-way handshake with the new AP

        \
        #underline([No message in the FT handshake contains a replay counter])
      ])
    ],
    [
      #align(center + horizon, [
        #chronos.diagram({
          import chronos: *
          _par("Supplicant")
          _par("Access Point")

          _seq("Supplicant", "Access Point", comment: "Authorization Request (SNonce)", comment-align: "center")
          _seq(
            "Access Point",
            "Supplicant",
            comment: "Authorization Response (ANonce, SNonce)",
            comment-align: "center",
          )
          _delay(name: "PTK installation")
          _seq(
            "Supplicant",
            "Access Point",
            comment: "Reassociation Request (ANonce, SNonce, MIC)",
            comment-align: "center",
          )
          _seq(
            "Access Point",
            "Supplicant",
            comment: "Reassociation Response (ANonce, SNonce, MIC, GTK)",
            comment-align: "center",
          )
          _seq("Access Point", "Supplicant", comment: "Encrypted data", comment-align: "center")
        })

        *FT Handshake*
      ])

    ],
  )
])

#slide([Fast BSS Transition (2/2)], [
  #grid(
    columns: (50%, 50%),
    [
      #text(size: 1.5em, [
        Implementations reinstall the key *after the Reassociation Response* instead of after the
        Authentication Response
        - This is _not_ a protocol weakness

        \
        Data frames can be transmitted/accepted after the Reassociation Request has been sent

        \
        An attacker can sniff and replay the Reassociation Request and cause the AP to reinstall the key and
        reuse nonces

        \
        #underline([This attack *does not* need a Man in the Middle position])
      ])
    ],
    [
      #align(center + horizon, [
        #chronos.diagram({
          import chronos: *
          _par("S", display-name: "Supplicant")
          _par("M", display-name: "Attacker")
          _par("A", display-name: "Access Point")

          _seq("S", "A", comment: "Authorization Request (SNonce)", comment-align: "center")
          _seq("A", "S", comment: "Authorization Response (ANonce, SNonce)", comment-align: "center")
          _seq("S", "A", comment: "Reassociation Request (ANonce, SNonce, MIC)", comment-align: "center")
          _seq("A", "S", comment: "Reassociation Response (ANonce, SNonce, MIC, GTK)", comment-align: "center")
          _delay(name: "PTK installation")
          _seq("A", "S", comment: "Encrypted data", comment-align: "center")
          _seq("M", "A", comment: "Reassociation Request (ANonce, SNonce, MIC)", comment-align: "center")
          _seq("A", "S", comment: "Reassociation Response (ANonce, SNonce, MIC, GTK)", comment-align: "center")
          _delay(name: "PTK reinstallation")
          _seq("A", "S", comment: "Encrypted data with reused nonces", comment-align: "center")
        })

        *Key reinstallation attack against the FT Handshake*
      ])

    ],
  )
])


#slide([Exercise 3 -- Setup], [
  #text(size: 1.5em)[
    #grid(
      columns: (50%, 50%),
      [
        *Open the GUI for Ex3 from your desktop*

        \
        The network topology is simulated using mininet wifi

        \
        The station runs `wpa_supplicant` wrapped inside the testing script

        \
        The AP runs a vulnerable version of `hostapd` (2.3)

        \
        In a real world scenario we'd need a second AP for roaming

        \
        If mininet doesn't start, try again after running\
        ```shell-unix-generic sudo mn -c```

      ],
      [
        #text(size: 1em, weight: "bold")[Simulated network topology]
        #set align(center)

        *sta1*
        #ellipse[
          krack_ft.py
          #ellipse[
            wpa_supplicant
          ]
        ]
        // ARROW
        #text(size: 4em)[
          #v(-1em)
          $arrow.t.b.filled$
          #v(-0.8em)
        ]
        #ellipse[
          hostapd
        ]
        *fakeAp1*
      ],
    )
  ]
])


#slide([Exercise 3 -- Commands], [
  #text(size: 1.5em)[
    #underline([Mind the "./", we do not want to use the programs installed on the system])

    *On the AP's terminal:*\
    ```shell-unix-generic
    ./hostapd hostapd.conf    # Run hostapd with the given configuration file
    ```

    *On the station's 1st terminal:*\
    ```shell-unix-generic
    cd krackattacks-scripts/krackattack/ # Navigate to the script's directory
    source venv/bin/activate             # Activate the python virtual environment

    # Start the supplicant with the attack script, on the station's wireless interface and
    # with the given configurations
    python3 krack_ft.py ../../wpa_supp -i sta1-wlan0 -c ../../supplicant.conf
    ```

    *On the station's 2nd terminal:*\
    ```shell-unix-generic
    ./wpa_cli                 # Open the interactive cli
    ```

    *Inside wpa_cli:*\
    ```shell-unix-generic
    > status                  # Show informations about the current connection
    > roam 02:11:11:11:11:11  # Force roaming to thhe station with this MAC address (fakeAp1)
    ```

  ]
])


#slide([Exercise 3 -- Results], [
  #text(size: 1.5em)[
    Use the GUI to generate some traffic (this uses the ``` arping``` command) and observe the
    CCMP Packet Numbers in Wireshark.\

    \
    #align(center)[
      #grid(
        columns: (20%, 30%, 30%, 20%),
        [
          #v(5em)
          Packet numbers are incremented normally
        ],
        [
          Safe
          #image("img/FT/NonVulnerable.png")
        ],
        [
          Vulnerable
          #image("img/FT/Vulnerable.png")
        ],
        [
          #v(5em)
          Packet numbers are repeating after every Reassociation Response
        ],
      )
    ]
  ]
])

#slide([Mitigations], [
  #align(
    center,
    [
      #text(size: 1.5em)[
        *Update your system*\
        Hostapd and wpa_supplicant 2.6 and above only install a key if it is fresh\
        Modern Linux kernels automatically drop replayed packets


        \
        *Enable Protected Management Frames*\
        Management frames sent after the 4-way handshake are protected\
        This includes FT frames, disassociation and deauthentication frames...

      ]

      \
      #text(size: 2em)[
        What do you think will happen if you repeat exercise 3 with the
        system's version of hostapd?\
        (without the "./")
      ]
    ],
  )
])

#slide("Exercise 4 - Hardware Demo (1/6)", [
  #align(center + horizon)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 3,
        columns: 1,
        row-gutter: 3em,
        align: left,
        [The final exercise is a practical *demonstration*],
        [Replicating the attack using *real hardware* to establish a *channel-based MitM position*.],
        [We will observe how earlier versions of Android, specifically those *prior to version 6.1*, are particularly vulnerable to the KRACK attack.],
      )
    ]
  ]
])

#slide("Exercise 4 - Hardware Demo (2/6)", [
  #align(horizon + center)[
    #block(width: auto)[
      #image("img/And/AP.jpg", width: auto)
    ]
  ]
])

#slide("Exercise 4 - Hardware Demo (3/6)", [
  #align(horizon + center)[
    #block(width: auto)[
      #image("img/And/PI.jpg", width: auto)
    ]
  ]
])

#slide("Exercise 4 - Hardware Demo (4/6)", [
  #align(horizon + center)[
    #block(width: auto)[
      #image("img/And/Tablet.jpg", width: auto)
    ]
  ]
])

#slide("Exercise 4 - Hardware Demo (5/6)", [
  #align(horizon + center)[
    #block(width: auto)[
      #image("img/And/config.png", width: 105%)
    ]
  ]
])

#slide("Exercise 4 - Hardware Demo (6/6)", [
  #align(center + horizon)[
    #block(width: auto)[
      #set text(size: 1.5em)
      #grid(
        rows: 2,
        columns: 1,
        row-gutter: 2em,
        align: center,
        [#image("img/And/notAP.png", width: 45%)],
        [*“On reception of message 4, the Authenticator verifies that the Key Replay Counter field value is one that it used on this 4-way handshake.”*],
      )
    ]
  ]
])

//
// AI Usage Disclosure
//
#slide("AI Usage Declaration and other information", [

  #align(center + horizon)[
    During the editing of this document, the team may have used Artificial Intelligence (AI) based tools in order to improve the clarity of the text after the content was already written.
    This process was performed in order to improve the readability, clarity and/or formatting of the document, or for other uses explicitly permitted by the #course regulation published on Google Classroom.

    As described in the #course regulation, AI was used only as an auxiliary support: we, as a team, truly believe in the importance of learning, and in the fact that knowledge is something that cannot be acquired without dedication and legitimate hard work.
  ]

])
