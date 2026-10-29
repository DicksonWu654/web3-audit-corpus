# Site design

The site should read like a reference archive for security research, not a product landing page. People come to it
to look things up, read findings and download files, so the type, layout and colour are set for reading and scanning.

## Direction

- **Two voices and a code face.** Literata, a book face, sets titles, ledes and finding text: the publishers' words
  get the reading face. Archivo sets the interface: navigation, buttons, labels, tables and numbers, with tabular
  figures where numbers line up. Martian Mono is kept for things that really are code: commands, field names in the
  record specimen, publisher ids, file names and hashes. Before this pass the mono face set headings, navigation,
  buttons and every label, which was the main thing that made the site look generated.
- **Rules, not boxes.** Sections, lists and tables are separated by hairline and 2px ink rules. The record carousel,
  the download files, the project index and the figures are ruled lists rather than cards, and the
  current page in the navigation is underlined, not filled.
- **One strong colour system.** The severity ramp (critical to unknown) is the only saturated colour, and it always
  means severity: the strip above the masthead, badges, swatches and the severity tables. The accent is a deep print
  blue used for links and the main chart series. Paper and ink stay in the cool grey and navy family of the launch
  cards.
- **Width where it pays.** Pages run to 1480px (search to 1600px). Prose keeps a 72-character measure; tables, the
  chart grid, the project index and the search results use the width. On search, results and the inline preview sit
  side by side at 2:3, and the filters fold behind the Filters button while a finding is open.

## What changed in this pass

- Fonts: headings, ledes, finding titles and text now use Literata (it was already shipped in `src/assets/fonts`, with
  `OFL-Literata.txt`, but unused). Archivo replaces the mono face on navigation, buttons, labels and tables. No new font
  files were added and nothing is loaded from another host.
- Removed the uppercase eyebrow above the hero, the middle-dot byline on finding pages (now "Firm audit of Project,
  date"), the pill shapes on project chips, class tags and coverage marks, and the coloured bullet before the no-key
  line.
- Severity badges have one fixed width, so every label fits and lines up. "Informational" is shown as "Info", with the
  full word as the accessible name and tooltip.
- The carousel keeps advancing under reduced motion (the slides swap without a fade); it pauses off screen, when the tab
  is hidden, on mouse hover and on keyboard focus.
- Wider layout on all pages, a wider and full-height search preview, and space reserved for the carousel so the landing
  page does not jump when it loads.
