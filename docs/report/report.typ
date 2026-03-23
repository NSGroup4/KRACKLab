#import "../lib/common.typ": labNumber, vulnName, course
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
  
  = Artificial Intelligence Usage Declaration and other information

  During the editing of this document, the team may have used Artificial Intelligence (AI) based tools in order to improve the clarity of the text after the content was already written.
  This process was performed in order to improve the readability, clarity and/or formatting of the document, or for other uses explicitly permitted by the #course regulation published on Google Classroom.

  As described in the #course regulation, AI was used only as an auxiliary support: we, as a team, truly believe in the importance of learning, and in the fact that knowledge is something that cannot be acquired without dedication and legitimate hard work.

], "Laboratory "+labNumber)