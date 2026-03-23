#import "../lib/common.typ": labNumber, vulnName
#import "../lib/commonReport.typ": firstPage, indexPage, docBody

#firstPage("Laboratory "+labNumber)

#pagebreak()

#indexPage()

#docBody([

  = Test

  == Test2

  #figure(
      table(
      columns: (50%,50%),
      stroke: black,
      [a], [aa],
    ),
    caption: "test",
  )

  #figure(
    image("../images/firstPage/KRACK-logo-small.png", width: 20%),
    caption: [#vulnName logo by Mathy Vanhoef, licensed under #link("https://creativecommons.org/licenses/by-sa/4.0")[CC BY-SA 4.0], available on the #link("https://www.krackattacks.com/images/logo.png")[#vulnName website]]
  )
  
  

], "Laboratory "+labNumber)