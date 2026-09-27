# Thesis figures

Redrawn Chapter Three figures for *Thesis_Final*, updated for the move from the
standalone Next.js dashboard to the native Wazuh dashboard plugin.

Each figure exists as an `.svg` (editable source) and a 2x `.png` (what you
actually insert - Google Docs does not accept SVG uploads). Regenerate the PNGs
after editing any SVG; see **Rendering** below.

| File | Figure | Insert at |
|---|---|---|
| `fig-3-2-system-architecture.svg` / `.png` | 3.2 Full on-premise system architecture | §3.3 |
| `fig-3-5-approval-sequence.svg` / `.png` | 3.5 Human-in-the-loop approval and remediation sequence | §3.4.4 |
| `fig-3-6-deployment.svg` / `.png` | 3.6 Full deployment infrastructure | §3.4.5 |

`style.css` holds the shared colour tokens and type scale. It is reference only -
the values are inlined into each SVG, because an SVG uploaded to Google Docs
cannot reach an external stylesheet.

## What changed, and why

**Figure 3.2** - one label. The `interrupt()` node read *"approve / reject in
Next.js UI"*; it now reads *"approve / reject in Wazuh dashboard"*. The
architecture itself was already correct, so nothing else moved.

**Figure 3.5** - restructured, because the old sequence had become factually
wrong rather than merely out of date. It showed `Analyst -> Wazuh AR` directly,
implying the analyst's browser issues the active response. It does not: the
plugin's *server* side is the only component that calls the backend, and the
response is issued with the analyst's own short-lived Wazuh token. A
`Plugin server` lifeline is therefore added between Guardrail and Analyst, and
the execute message now originates there. Six messages instead of four.

**Figure 3.6** - the `Next.js dashboard` container becomes
`Wazuh dashboard + plugin`. This is a deployment-shape change, not a rename: the
interface is no longer a container in the app tier at all. The app tier is now
FastAPI + PostgreSQL only, and the interface ships as a plugin inside the Wazuh
dashboard container (`dashboard-plugin/install.sh`).

## Style

Matches the existing chapter: pastel fills on thin strokes, Calibri, and the
legend already used in Figure 3.2 - AI/LLM (purple), Safety (orange), Human
(blue), Action (green), Infra/data (grey). Figure 3.5's lifeline heads are grey,
as in the original, rather than colour-coded.

## Rendering

```bash
npm install @resvg/resvg-js
node render.js          # see docs/figures/render.js
```

PNGs are emitted at 2x (1520px wide) for print quality. Calibri must be
installed locally or the renderer substitutes a fallback face and the figures
will not match the document body.

## Still to do

The captions inside the document are handled by suggestions already in
*Thesis_Final*; these files replace the **images** only. Insert each with
`Insert > Image > Upload from computer`, then delete the old figure.
