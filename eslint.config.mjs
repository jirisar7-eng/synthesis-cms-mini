import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/.synthesis/**",
      "**/scripts/governance/**",
      "**/node_modules/**",
      "**/dist/**",
      "**/coverage/**",
    ],
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    ...js.configs.recommended,
  },
  {
    files: [
      "apps/**/*.{ts,tsx}",
      "core/**/*.{ts,tsx}",
      "contracts/**/*.{ts,tsx}",
      "sdk/**/*.{ts,tsx}",
      "modules/**/*.{ts,tsx}",
      "project-packs/**/*.{ts,tsx}",
      "packages/**/*.{ts,tsx}",
      "tests/**/*.{ts,tsx}",
    ],
    extends: [...tseslint.configs.strictTypeChecked],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);
