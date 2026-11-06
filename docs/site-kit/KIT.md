# Lock site kit

One look for every Lock site (locksql, lockmq, lockfile, lockhttp, locklog)
and every Lock README, in the Lock Family identity: "a printed ticket that a
human signs" (lockfamily `docs/identity.md`). Reference implementation:
locksql, branch `docs/polish-site-readme` (its `site/` and `README.md`).

```
kit/
  assets/tokens.css        lockfamily origin/main, unchanged (fonts, colours, space)
  assets/fonts/            lockfamily origin/main, unchanged (woff2 + OFL licences)
  assets/lock-site.css     the shared stylesheet (identical bytes in every Lock repo)
  assets/copy.js           Copy button of the install box
  assets/logos/            lockfamily logos: mark, locksql, lockmq, lockfile, lockhttp, lea
  snippets/head.html       <head>: meta, SEO, fonts preload, the two stylesheets, scripts
  snippets/header.html     skip link + header (logo, wordmark, nav)
  snippets/hero-template.html   the hero, with an optional ticket aside
  snippets/install-box.html     the Homebrew copy-paste box (two variants)
  snippets/family-strip.html    the family list of the footer
  snippets/footer.html     footer: about, the Lock's links, family strip, licence
  tools/banner_svg.py      README banners (docs/assets/banner-light.svg, banner-dark.svg)
  tools/og.html            template of the 1200x630 og.png and the 180px touch icon
  screens/                 locksql, every page, 1440 and 390 px, light and dark
```

## Apply it to a site

1. **Worktree** from fresh `origin/main` (SPEC.md, Process).
2. **Copy assets** into `site/assets/`: `tokens.css`, `lock-site.css`,
   `copy.js`, `fonts/` (all files). Do not edit `lock-site.css` in a repo:
   change it here and copy it everywhere. Keep the site's own `anchors.js`
   (section links; the stylesheet styles `.heading-anchor` and `.anchor-toast`).
3. **Logo**: `site/assets/logo.svg` = lockfamily `assets/<lock>.svg`
   (`mark.svg` for a Lock without its own: locklog today). It switches light
   and dark by itself.
4. **Delete** the old `site/assets/style.css` and any unused old assets
   (locksql had `site/assets/banner-*.svg` nobody referenced). Grep first.
5. **Every page** (`index.html`, `install/`, `how-it-works/`, `security/`,
   `faq/`, `404.html`): replace `<head>` with `head.html`, the header with
   `header.html`, the footer with `footer.html` (which takes
   `family-strip.html` at `{{FAMILY_STRIP}}`). Content markup stays: the
   stylesheet keeps the old class names (`.cards`, `.facts`, `.steps`,
   `.term`, `.diagram`, `.table-wrap`, `.yes/.no/.partial`, `.limits`, `.faq`,
   `.more`, `.notice`, `.demo*`, `.family`, `.here`, `.family-line`,
   `.link-line`, `.cmt`, `.cols-3`, `.compare`, `.engines`, …).
6. **Home hero**: replace it with `hero-template.html`. The aside (a ticket
   of what waits for the human) is optional; without it the hero is one column.
   Old hero extras (`.intro`, `.facts`) still render, but the SPEC wants the
   lead at most 2 sentences: move the rest below.
7. **Inner pages**: put `<p class="eyebrow">Page name</p>` before the `<h1>`.
8. **Rewrite the content** per SPEC (short paragraphs, agent-neutral, family
   links to repos). Old `.cards.family` sections can go: the footer lists the
   family on every page.
9. **og.png / apple-touch-icon.png**: copy `tools/og.html` into `site/`,
   fill its placeholders, render it at 1200x630 with headless Chrome (and the
   logo alone on `--card` at 180x180), save as `site/assets/og.png` and
   `apple-touch-icon.png`, then delete the HTML.
10. **Check** (below), then commit, push, PR.

Placeholders: `{{LOCK}}`, `{{TITLE}}`, `{{DESCRIPTION}}`, `{{URL}}`
(canonical), `{{DOMAIN}}` (`https://<site>` without a slash), `{{OG_ALT}}`,
`{{ROOT}}` (`""` on the home page, `../` one level down, `/` on 404.html),
`{{HOME}}` (`./` on the home page, else `{{ROOT}}`), `{{PITCH}}`,
`{{VERSION}}` (`v0.17.x`). In the header, put `aria-current="page"` on the
current page's link and drop the `data-nav` attributes. In the family strip,
put `aria-current="true"` on the current Lock's `<li>` (CSS adds "this site").

## Classes you will want

- `.status.auto` / `.asked` / `.denied` / `.you`: a decision word in its
  identity colour (approved by a rule, waiting for you, denied, a human).
- `.ticket`, `.ticket-face`, `.ticket-head`, `.ticket-fields` (a `<dl>`),
  `.ticket-stub`, `.stamp` (`.stamp.denied`), `.masked`: the family ticket.
- `.install` + `.install-head` + `<span class="cmd">`: the copy box.
- `.hub-line`: the dashed line under the hero (the family and `lox run`).
- `.label` / `.eyebrow`: a printed form's label (mono, small capitals).
- `<pre class="diagram">`: an ASCII drawing on paper; `<pre class="term">`
  or a plain `<pre>`: a dark terminal, in both themes.
- Every `<section>` `<h2>` in `main` is numbered `01`, `02`… automatically,
  under a 2px ink rule (FAQ questions: `Q01`…; `.limits`: "fine print").
  A `.visually-hidden` h2 is not counted.

## Install box rules

- One `<span class="cmd">` per command, a real newline between them, nothing
  else in the `<pre>`: no prompt (CSS draws `$ `), no comment. `copy.js`
  copies the `.cmd` texts joined by newlines; without `.cmd` it copies the
  lines without `$ ` and without `#` comments.
- Without JS the box is a selectable `<pre>`; the button, its `aria-label`
  and a polite `role="status"` live region are added by `copy.js`.
  `navigator.clipboard` first, `execCommand("copy")` as a fallback, and if
  both fail it selects the text and says "Press Ctrl+C".
- **The Lock formulas do not depend on `lox`.** `brew install
  davidgodefroid/tap/<lock>` alone leaves `lox add` / `lox run` missing. The
  box installs both: `brew install davidgodefroid/tap/lox
  davidgodefroid/tap/<lock>`. Check again with
  `gh api repos/DavidGodefroid/homebrew-tap/contents/Formula --jq '.[].name'`
  (today: lockfamily, lox, lea, locksql, lockmq, lockfile [Linux only],
  lockhttp; no locklog, no lockssh): a Lock without a formula uses the
  commented variant of `install-box.html`.

## README

Template: SPEC.md. Shared pieces:

**Banner** (from the repo root; needs `pip install fonttools brotli`, run it
from a venv):

```sh
python3 kit/tools/banner_svg.py --name <lock> \
  --tagline "<one short sentence>" \
  --logo site/assets/logo.svg --fonts site/assets/fonts --out docs/assets
```

It draws the text as outlines from the family fonts, so GitHub (which shows
README SVGs through `<img>`, without web fonts) renders it exactly; ~35 KB per
file. `--text` writes `<text>` with a font stack instead, if fontTools is not
available (looks generic: avoid). `--check` compares with the files on disk.
Each file has fixed colours; the README picks one:

```html
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <img alt="<lock>: <tagline>" src="docs/assets/banner-light.svg" width="600">
  </picture>
</p>
```

**Badges**: these four, this order, these colours (identity tokens: `1f4a9c`
is `--sign`, `575146` is `--ink-2`); replace `<repo>`, drop Go for a non-Go
repo, drop release for a repo without releases:

```html
<p align="center">
  <a href="https://github.com/DavidGodefroid/<repo>/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/DavidGodefroid/<repo>/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/DavidGodefroid/<repo>/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/DavidGodefroid/<repo>?include_prereleases&sort=semver&label=release&color=1f4a9c"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-575146"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/DavidGodefroid/<repo>?color=575146&logo=go&logoColor=white"></a>
</p>
```

No other badges (platform, cgo…): they move into the Install section text.

**The Lock Family table** (identical in every README):

```markdown
| Repo | What it does |
|---|---|
| [lockfamily](https://github.com/DavidGodefroid/lockfamily) | The family site ([lockfamily.dev](https://lockfamily.dev)) and the one-line installer. |
| [locksql](https://github.com/DavidGodefroid/locksql) | SQL databases: the agent queries, PII comes back masked; connections and writes wait for you. |
| [lockmq](https://github.com/DavidGodefroid/lockmq) | RabbitMQ: masked queue inspection; reading messages and acting on queues wait for you. |
| [lockfile](https://github.com/DavidGodefroid/lockfile) | Files (S3, SFTP, disk): the agent asks yes/no questions about files it never reads. |
| [lockhttp](https://github.com/DavidGodefroid/lockhttp) | Outbound HTTP(S): reads of trusted hosts pass; anything that sends data or reaches an unknown host waits for you. |
| [locklog](https://github.com/DavidGodefroid/locklog) | Logs: masked, bounded log search; the agent reads the logs, not the people in them. |
| [lockssh](https://github.com/DavidGodefroid/lockssh) | Commands over SSH: allow-listed commands run at once, the rest waits for you; the key never leaves the console. |
| [lockhub](https://github.com/DavidGodefroid/lockhub) | The approval hub and its `lox` CLI: `lox run` approves outside the agent's harness and never sees values in clear. |
| [lockkit](https://github.com/DavidGodefroid/lockkit) | The shared Go core of every Lock: console, policies, masking, signed tickets, audit, MCP. |
| [lea](https://github.com/DavidGodefroid/lea) | Runs many agents in containers, wired to the Locks. |
```

Long reference material leaves the README for `docs/*.md`, whole (locksql:
`docs/configuration.md`, `console.md`, `architecture.md`, `safety.md`,
`install.md`), then grep the repo for links to the old README anchors
(`README.md#configuration`, …) and repoint them.

## Checks

- The repo's own: `.github/workflows/*.yml`, `go vet ./...`, `go test ./...`,
  `scripts/hygiene.sh` and site or docs tests if any.
- Serve `site/` (`python3 -m http.server PORT --bind 127.0.0.1`, **pick an
  unusual port**: other agents serve their sites too, and a busy port shows
  you someone else's site), then fetch every page and check every local
  `href`/`src`/`#fragment`, and the `github.com/.../<repo>/blob/main/...`
  links against the files and Markdown headings of your worktree.
- Screenshots, light and dark, 1440 and 390 px, through the DevTools
  protocol (`Emulation.setEmulatedMedia` with `prefers-color-scheme`;
  `--force-dark-mode` is not needed). Look at them. Check no horizontal
  overflow on the phone.

## Pitfalls met on locksql

- Port 8765 was already serving another agent's lockfamily site: the first
  screenshots were of the wrong site.
- Facts in the old pages had gone stale: TLS "verifies by default" (the
  default is `prefer` since v0.15), "no auto mode" (`lox run` has one since
  v0.17), lockhub "asks for the typed instance name" on production (no Lock
  sets that flag today), approvals "in the console" (in lockhub). Re-check
  every claim against CHANGELOG and docs, not against the old site.
- `lox up` is deprecated in lockhub (it says "use lox run"); `lox add` starts
  the console, `lox run` serves decisions. Some Lock docs still say `lox up`.
- `lox add` wires Claude Code (`<lock> init claude`): say so, and give the
  `init codex|cursor|gemini` alternative.
- Box-drawing characters are not in the family's Latin-subset mono; the
  stylesheet uses a system mono for `pre.diagram` so boxes stay aligned.
- The demo videos were recorded on the old purple theme: they stay, framed
  by an ink border, captioned "an agent (here Claude Code)".
