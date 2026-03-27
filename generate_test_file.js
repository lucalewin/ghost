import { writeFileSync } from "fs";

/**
 * Reverses the malicious decoder math to turn raw bytes
 * into invisible Unicode Variation Selectors.
 */
function encodeToInvisible(text) {
  // Convert the plain text into a raw byte array (0-255)
  const buffer = Buffer.from(text, "utf-8");
  let invisibleString = "";

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    let codePoint;

    // The exact reverse of the math you found in the exploit:
    if (byte >= 0 && byte <= 15) {
      // Map 0-15 to the first Variation Selector block (0xFE00 - 0xFE0F)
      codePoint = byte + 0xfe00;
    } else if (byte >= 16 && byte <= 255) {
      // Map 16-255 to the supplementary block (0xE0100 - 0xE01EF)
      codePoint = byte - 16 + 0xe0100;
    }

    // Convert the calculated hex value back into a Unicode character
    invisibleString += String.fromCodePoint(codePoint);
  }

  return invisibleString;
}

// 1. Define a harmless message to hide
const benignMessage = "SUCCESS: The Rust CI scanner caught the hidden payload!";

// 2. Encode it into invisible characters
const hiddenPayload = encodeToInvisible(benignMessage);

// 3. Wrap it in some normal-looking JavaScript to simulate a real file
const fileContent = `
// This file looks completely normal to the naked eye.
function doSomethingNormal() {
    console.log("Just standard application logic here.");
}

// But there are hidden bytes between these backticks!
const hiddenData = \`${hiddenPayload}\`;

doSomethingNormal();
`;

// 4. Write it to disk so your Rust scanner can test it
const outputPath = "./poisoned_test_file.js";
writeFileSync(outputPath, fileContent, "utf-8");

console.log(`✅ Generated ${outputPath}`);
console.log(
  `The file contains ${Buffer.from(benignMessage).length} hidden bytes.`,
);
