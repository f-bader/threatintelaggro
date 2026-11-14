---
name: threat-intel-aggro-ui
description: Build, refine, and visually validate the Threat Intel Aggro web UI, including responsive layouts and expanded article, detection, IOC, feed, and settings details.
---

# Threat Intel Aggro UI

Use this skill whenever changing the UI in this repository.

## Visual language

- Preserve the dark operations-console look: near-black canvas, restrained cyan accents, fine panel borders, compact uppercase labels, sans-serif content headings, and monospaced metadata.
- Keep the existing filled square markers; labels beside them should be vertically centered. Do not add decorative numbers to workspace tabs or section markers.
- Use the existing button styles for actions. Action links should look like buttons where they sit with buttons; reserve underlined text links for article/source navigation.
- Keep spacing and control heights consistent across an action row. Long labels, values, and filenames should wrap without widening the page.

## Layout behavior

- Treat the inbox search and advanced filters as one toolbar. When expanded, filters stay in normal document flow in a stable second row below Search; never float over article content. Keep the article stream title readable beside the toolbar at tablet widths.
- Keep the inbox filter form at a stable flex-basis on wide screens so opening its advanced grid does not resize the form or shift the basic search/read-state/Search controls. Recheck the same control coordinates in collapsed and expanded states.
- Let the advanced filter grid fit as many controls as possible on one row (`auto-fit` with a readable minimum control width); wrap only when the available panel width cannot fit them cleanly. Give the form the available width beside the stream title on desktop so wide screens do not wrap filters unnecessarily.
- Align inputs, checkboxes, selects, and submit buttons to a shared baseline. On narrow screens, reflow controls into clear rows rather than clipping them or shrinking them until labels become unreadable.
- In IOC lifetime settings, keep number inputs aligned across each grid row even when one field has helper text. Place Save Lifetimes on a separate row so it does not occupy a field slot.
- Preserve intentional horizontal scrolling only for genuinely wide data tables. Inline editors and their Save/approval controls should remain visible within their containing row or panel.
- For grid/flex children that contain variable content, use `min-width: 0`. Wrap long prose and identifiers (`overflow-wrap: anywhere` where appropriate). KQL/code blocks may wrap or scroll within their own bounded panel, but must not create page-level horizontal overflow.
- Keep expanded `<details>` content visually attached to its card. Headings, lists, code, action buttons, and status controls should retain clear spacing and alignment when open.
- In IOC views, long type labels and values must wrap or use a bounded column. Keep category/filter values de-duplicated, and only offer filter options that occur in the current data set.
- IOC article-source and VirusTotal links that share a row with actions should use the same compact outlined button treatment. Allow long article titles to wrap inside their bounded link instead of widening the row or falling back to underlined text.

## Review workflow

1. Inspect the page markup and nearby CSS before changing layout; prefer a small, scoped adjustment over a global override.
2. Start or reuse the local app at `http://127.0.0.1:5088`. Preserve its existing SQLite data while reviewing.
3. Use the built-in browser to inspect every workspace tab. Exercise the open states that change geometry: inbox advanced filters and article intelligence, detection KQL/playbook/telemetry panels, feed edit and OPML disclosures, and IOC/settings panels.
4. Check both visual alignment and measurable geometry. At each available viewport, confirm `document.documentElement.scrollWidth <= document.documentElement.clientWidth`; inspect panel/control bounds for clipping, overlaps, inconsistent baselines, and unexpected title wrapping.
5. Review a narrow viewport as well as desktop. Recheck expanded states after any CSS change, and make sure controls remain reachable without a horizontal page scroll.
6. Avoid submitting forms or changing stored article/IOC/feed status during visual QA unless the task explicitly requires a behavior test. Report any viewport or browser limitation clearly.

## Project files

- Global styles and responsive breakpoints: `src/ThreatIntelAggro/wwwroot/css/site.css`
- Razor page views: `src/ThreatIntelAggro/Pages/`
