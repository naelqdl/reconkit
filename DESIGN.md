---
name: reconkit
description: Desktop front end for a scope-safe recon CLI
colors:
  bg: "#0F172A"
  surface: "#1B2336"
  raised: "#273449"
  hover: "#334155"
  border: "#64748B"
  text: "#E2E8F0"
  muted: "#94A3B8"
  disabled: "#64748B"
  accent: "#22C55E"
  accent-hi: "#4ADE80"
  accent-down: "#16A34A"
  on-accent: "#0F172A"
  ok: "#4ADE80"
  error: "#F87171"
  info: "#7DD3FC"
  bg-light: "#F8FAFC"
  surface-light: "#FFFFFF"
  raised-light: "#E2E8F0"
  hover-light: "#CBD5E1"
  border-light: "#7C8BA1"
  text-light: "#0F172A"
  muted-light: "#475569"
  disabled-light: "#94A3B8"
  accent-light: "#15803D"
  accent-hi-light: "#166534"
  accent-down-light: "#14532D"
  on-accent-light: "#FFFFFF"
  ok-light: "#15803D"
  error-light: "#B91C1C"
  info-light: "#0369A1"
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

A one-window desktop tool in the Operate mode: a form (Target, Scan options, Report), an action bar, and a log. Both themes share the same role names. The window follows the Windows light or dark app setting, and dark is the default elsewhere.

## Colors

- Neutrals (bg, surface, raised, hover, border, the text tones) carry almost all of the window. In dark mode, surfaces get lighter as they rise: bg, then surface, then raised.
- The accent appears only on the one primary action (Run scan), focus borders, and success. Red is only for errors, blue only for progress steps in the log.
- Measured contrast: body and muted text are at least 6:1 on their surfaces in both themes. Input borders are 3.3:1 (dark) and 3.5:1 (light). Text on the accent is 7.8:1 (dark) and 5.0:1 (light).

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
