// Render the thesis figure SVGs to 2x PNGs for insertion into Google Docs
// (Docs will not accept SVG uploads).
const fs = require('fs');
const path = require('path');
const { Resvg } = require('@resvg/resvg-js');

const dir = 'C:/Users/akinb/DOcuments/Dev/wazuh-guardrailed-agent/docs/figures';
const SCALE = 2;

for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.svg'))) {
  const svg = fs.readFileSync(path.join(dir, file), 'utf8');
  const resvg = new Resvg(svg, {
    fitTo: { mode: 'zoom', value: SCALE },
    font: { loadSystemFonts: true, defaultFontFamily: 'Calibri' },
    background: 'white',
  });
  const png = resvg.render();
  const out = path.join(dir, file.replace(/\.svg$/, '.png'));
  fs.writeFileSync(out, png.asPng());
  const { width, height } = png;
  console.log(`${file} -> ${path.basename(out)}  ${width}x${height}`);
}
