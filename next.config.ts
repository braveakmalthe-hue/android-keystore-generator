import type { NextConfig } from "next";

// GitHub Pages project sites are served from a subdirectory:
// https://braveakmalthe-hue.github.io/android-keystore-generator/
// Vercel serves the app at the site root, so only apply the Pages-specific
// settings when building inside GitHub Actions (GITHUB_ACTIONS is set there).
const isGitHubPages = process.env.GITHUB_ACTIONS === "true";

const nextConfig: NextConfig = {
  // Emit a fully static site into `out/` when deploying to GitHub Pages
  ...(isGitHubPages && { output: "export" as const }),

  // GitHub Pages needs directory-style URLs: /about/ -> /about/index.html
  ...(isGitHubPages && { trailingSlash: true }),

  // Required for GitHub Pages project pages (repo served under /<repo-name>)
  ...(isGitHubPages && { basePath: "/android-keystore-generator" }),

  // Image optimization requires a server; disable it for static hosting
  ...(isGitHubPages && { images: { unoptimized: true } }),
};

export default nextConfig;
