#import "../lib/common.typ": labNumber, vulnName
#import "../lib/commonSlide.typ": cover, slide

#cover([Laboratory #labNumber: The #vulnName vulnerability])

#slide("Test", [

  #figure(
    image("../images/firstPage/KRACK-logo-small.png", width: 20%),
    caption: [#vulnName logo by Mathy Vanhoef, licensed under #link("https://creativecommons.org/licenses/by-sa/4.0")[CC BY-SA 4.0], available on the #link("https://www.krackattacks.com/images/logo.png")[#vulnName website]]
  )

  test
])