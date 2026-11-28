---
name: reconkit
description: Desktop front end for a scope-safe recon CLI
colors:
  bg: "#07090E"
  surface: "#0F141C"
  raised: "#1A2230"
  hover: "#253042"
  border: "#5F7088"
  text: "#E6EBF2"
  muted: "#9AA6B8"
  disabled: "#5F6B7D"
  accent: "#38C8F0"
  accent-hi: "#6FD9F7"
  accent-down: "#1FA8D4"
  on-accent: "#07090E"
  ok: "#6FD9F7"
  error: "#F87171"
  info: "#9DB8D9"
  bg-light: "#F3F5F9"
  surface-light: "#FFFFFF"
  raised-light: "#E1E6EE"
  hover-light: "#CDD5E1"
  border-light: "#77859A"
  text-light: "#07090E"
  muted-light: "#475467"
  disabled-light: "#97A1B0"
  accent-light: "#00739E"
  accent-hi-light: "#005F84"
  accent-down-light: "#004C6A"
  on-accent-light: "#FFFFFF"
  ok-light: "#00739E"
  error-light: "#B91C1C"
  info-light: "#2F5683"
typography:
  heading:
    fontFamily: "Segoe UI (TkDefaultFont)"
    fontSize: "11pt"
    fontWeight: 700
  body:
    fontFamily: "Segoe UI (TkDefaultFont)"
    fontSize: "10pt"
    fontWeight: 400
  mono:
    fontFamily: "Consolas (TkFixedFont)"
    fontSize: "10pt"
    fontWeight: 400
rounded:
  none: "0px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.none}"
    padding: "6px 18px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hi}"
  button-primary-pressed:
    backgroundColor: "{colors.accent-down}"
  button:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.none}"
    padding: "6px 12px"
  button-hover:
    backgroundColor: "{colors.hover}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.none}"
    padding: "4px 6px"
---

# Design

Recorded from the shipped code in `reconkit/gui.py` (`PALETTES`, `theme()`, `App.__init__`) on 2026-11-27. The code is the source of truth. Update this file when the code changes.

## Overview

A one-window desktop tool in the Operate mode: a form (Target, Scan options, Report), an action bar, and a log. Both themes share the same role names. The palette is night black, moon white and bioluminescent blue. The window follows the Windows light or dark app setting, and dark is the default elsewhere: dark mode is a moon-white form on night black, and light mode turns it around, with night-black text on moon white and a deeper blue accent so it keeps its contrast.

## Colors

- Neutrals (bg, surface, raised, hover, border, the text tones) carry almost all of the window. In dark mode, surfaces get lighter as they rise: bg, then surface, then raised.
- The bioluminescent blue accent appears only on the one primary action (Run scan), focus borders, and success. Red is only for errors. Progress steps in the log use a paler, moonlit blue.
- Measured contrast: body and muted text are at least 6:1 on their surfaces in both themes. Input borders are 3.7:1 (dark) and 3.8:1 (light). Text on the accent is 10.1:1 (dark) and 5.3:1 (light).

## Typography

Three sizes only: 11pt bold for section headings, 10pt for everything else, and 10pt monospace for the scope editor and the log, which hold code-like data. All sizes scale with the Windows Accessibility > Text size setting.

## Layout

- Window padding is 24 px left and right, 16 px top and bottom. Rows are 4 px apart, a heading has 24 px above and 8 px below, and the action bar has 24 px above.
- One left edge: labels sit in column 0, and every field, the scope editor and the inline error start at column 1.
- The domain error has a reserved line, so showing it never shifts the layout. The form scrolls when the screen is too short, and focus scrolls into view.

## Elevation & Depth

Flat. There are no shadows; depth comes from surface tone.

## Shapes

Square corners throughout (the clam theme). Every border is 1 px.

## Components

- Buttons and inputs are at least 24×24 px (measured at 100% scaling). Every interactive control shows an accent focus border.
- Disabled buttons use the disabled text tone and lose their fill.
- The status line states every outcome in words, so color is never the only signal.

## Do's and Don'ts

- Do keep the authorized-use line visible at the foot of the window.
- Do keep the accent on the one primary action.
- Don't add hex values outside `PALETTES`.
- Don't add a capability the CLI lacks.
