# harpi-portfolio

Personal cybersecurity portfolio — [harpi.cc](https://harpi.cc/)

Hugo static site using [hugo-theme-terminal v4](https://github.com/panr/hugo-theme-terminal). Black background, green + amber accents. No JS frameworks, no tracking, no bloat.

## Deployment

| Repo | Branch | URL | Purpose |
|------|--------|-----|---------|
| `har-pi.github.io` | `master` | [harpi.cc](https://harpi.cc/) | Current live site (custom domain) |
| `harpi-portfolio` | `legacy` | [har-pi.github.io/harpi-portfolio](https://har-pi.github.io/harpi-portfolio/) | Archived original version |

Both repos use the same GitHub Actions workflow (`.github/workflows/hugo.yaml`). The workflow auto-detects the correct `baseURL` from GitHub Pages settings at build time.

### Deploying to the live site

Push `master` to the `har-pi.github.io` repo:

```bash
git remote add live git@github.com:har-pi/har-pi.github.io.git
git push live master
```

## Sections

| Path | Content |
|------|---------|
| `/blog/` | Methodology posts, HTB writeups, tooling notes |
| `/research/` | CVE writeups, PoC development, responsible disclosure |
| `/about/` | Cyberpunk operative dossier card — alias, certs, capabilities |

## Local dev

```bash
hugo server -D
# → http://localhost:1313/
```

Theme is a git submodule — clone with:

```bash
git clone --recurse-submodules https://github.com/har-pi/harpi-portfolio
```

## Where to change things

### Content

All content is in `content/`. Each section has an `_index.md` for the landing page intro.

| What | File |
|------|------|
| About page content | `content/about/_index.md` (YAML frontmatter — layout is in `layouts/about/list.html`) |
| Blog intro text | `content/blog/_index.md` |
| Research intro text | `content/research/_index.md` |
| New blog post | Create `content/blog/my-post.md` with frontmatter (see below) |
| New HTB writeup | Create `content/blog/htb-machinename.md` with `tags: ["htb"]` |
| New CVE/research | Create `content/research/cve-name.md` |

### Site config

| What | File | Section |
|------|------|---------|
| Site title, baseURL | `config.yaml` | top-level |
| Menu items | `config.yaml` | `menu.main` |
| Social links (footer + landing) | `config.yaml` | `params.social` (GitHub, HTB, Mastodon, email, GPG) |
| Footer quote | `layouts/partials/footer.html` | hardcoded Gibson quote |

### Styling

| What | File |
|------|------|
| Colors (re-theme here) | `static/style.css` → `:root` RGB variables (`--accent-rgb`, `--amber-rgb`, etc.) |
| Dossier card (About) | `static/style.css` → `.dossier-*` classes |
| Dossier content | `content/about/_index.md` → YAML frontmatter (alias, certs, capabilities, specializations) |
| Menu pill size/style | `static/style.css` → `.navigation-menu__inner li a` |
| Section title size | `static/style.css` → `.index-content h1.section-title` |
| Post card styling | `static/style.css` → `.post.on-list` |
| Landing page buttons | `static/css/animate-style.css` → `.landing-nav__link` |
| Landing page social icons | `static/css/animate-style.css` → `.link-icon` |
| Landing page title size | `static/css/animate-style.css` → `.item-title` |
| Code syntax highlighting | `static/css/syntax.css` — Chroma classes (palette-matched) |

### Layout templates

| What | File |
|------|------|
| Homepage (video + glitch) | `layouts/_default/index.html` |
| Section listing pages | `layouts/_default/list.html` |
| Header (logo + nav) | `layouts/partials/header.html` |
| Navigation menu | `layouts/partials/menu.html` |
| About page (dossier card) | `layouts/about/list.html` |
| Footer | `layouts/partials/footer.html` |

**Do not edit files inside `themes/terminal/`** — override them by creating files in `layouts/` with the same path.

### Frontmatter for new posts

```yaml
---
title: "Post Title"
date: 2025-01-01
description: "One-line summary"
tags: ["web-security", "checklist"]
draft: false
---
```

For HTB writeups, add `difficulty` and `platform`:

```yaml
---
title: "HTB: MachineName"
date: 2025-01-01
tags: ["htb", "linux"]
difficulty: "medium"
platform: "linux"
draft: false
---
```
