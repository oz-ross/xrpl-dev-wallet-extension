/**
 * Generates PNG icons for the XRPL Dev Wallet Chrome extension.
 *
 * Layers (bottom → top):
 *   1. Black background
 *   2. Large crossed hammer + chisel (centre)
 *   3. XRPL official logo composited with "screen" blend — black areas
 *      become transparent so the tools show through behind the logo.
 *
 * Run: npm run generate-icons
 */
const sharp = require('sharp');
const fs   = require('fs');
const path = require('path');

const ICONS_DIR = path.join(__dirname, '..', 'icons');
const SOURCE    = path.join(__dirname, '..', '..', 'XRPL - Black.png');
const SIZES     = [16, 48, 128];

// ─────────────────────────────────────────────────────────────────────────────
// Hammer + chisel SVG — 128 × 128, centred, large.
//
//   • Chisel  at +45° (behind)
//   • Hammer  at −45° (in front)
//   • Warm amber handle, dark-steel head, silver chisel shaft
// ─────────────────────────────────────────────────────────────────────────────
const TOOLS_SVG = `\
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">

  <!-- ── CHISEL  (+45°, back) ── -->
  <g transform="translate(64,64) rotate(45)">
    <!-- Shaft -->
    <rect x="-5" y="-52" width="10" height="104" rx="3"
          fill="#78909c"/>
    <!-- Bevelled cutting tip -->
    <polygon points="-5,52 5,52 0,66"
             fill="#b0bec5"/>
    <!-- Striking cap -->
    <rect x="-7" y="-61" width="14" height="11" rx="2.5"
          fill="#8d6e63"/>
  </g>

  <!-- ── HAMMER  (−45°, front) ── -->
  <g transform="translate(64,64) rotate(-45)">
    <!-- Wooden handle -->
    <rect x="-5.5" y="-8" width="11" height="62" rx="3"
          fill="#b45309"/>
    <!-- Dark-steel head -->
    <rect x="-22" y="-35" width="44" height="28" rx="4"
          fill="#37474f"/>
    <!-- Face highlight (striking face) -->
    <rect x="-20" y="-33" width="15" height="8" rx="2"
          fill="#607d8b" opacity="0.9"/>
    <!-- Poll (back of head) -->
    <rect x="10" y="-31" width="10" height="20" rx="2"
          fill="#455a64"/>
  </g>

</svg>`;

// ─────────────────────────────────────────────────────────────────────────────
async function generate() {
  fs.mkdirSync(ICONS_DIR, { recursive: true });

  // 1. Solid black base (128 × 128)
  const black = await sharp({
    create: { width: 128, height: 128, channels: 4,
              background: { r: 0, g: 0, b: 0, alpha: 1 } },
  }).png().toBuffer();

  // 2. Composite tools onto the black base
  const withTools = await sharp(black)
    .composite([{ input: Buffer.from(TOOLS_SVG), blend: 'over' }])
    .toBuffer();

  // 3. Resize the official XRPL logo to 128 × 128
  const xrplLogo = await sharp(SOURCE).resize(128, 128).toBuffer();

  // 4. Composite the XRPL logo using "screen" blend mode.
  //    Screen treats black as fully transparent, so the white curly-brace
  //    logo stays white while the black background reveals the tools beneath.
  const composed = await sharp(withTools)
    .composite([{ input: xrplLogo, blend: 'screen' }])
    .toBuffer();

  // 5. Export at each required size
  for (const size of SIZES) {
    const outPath = path.join(ICONS_DIR, `icon${size}.png`);
    await sharp(composed).resize(size, size).png().toFile(outPath);
    console.log(`Generated ${outPath}  (${size}×${size})`);
  }

  console.log('\nDone.');
}

generate().catch(err => { console.error(err); process.exit(1); });
