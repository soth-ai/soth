import path from "node:path";
import { fileURLToPath } from "node:url";

const configDir = path.dirname(fileURLToPath(import.meta.url));

export default {
  plugins: {
    // Resolve imports/sources relative to dashboard/, even if commands run from repo root.
    "@tailwindcss/postcss": { base: configDir },
  },
};
