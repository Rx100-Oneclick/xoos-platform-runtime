import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "es2022",
  minify: false,
  external: ["react", "react-dom", "react-dom/client", "react/jsx-runtime"]
});
