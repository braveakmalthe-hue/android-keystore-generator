import type { NextConfig } from "next";

// GitHub Pages project sites are served from a subdirectory:
// https://braveakmalthe-hue.github.io/android-keystore-generator/
const basePath = "/android-keystore-generator";

const nextConfig: NextConfig = {
  // Emit a fully static site into `out/` when running `next build`
  output: "export",

  // GitHub Pages needs directory-style URLs: /about/ -> /about/index.html
  trailingSlash: true,

  // Required for GitHub Pages project pages (repo served under /<repo-name>)
  basePath,

  // Image optimization requires a server; disable it for static hosting
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
