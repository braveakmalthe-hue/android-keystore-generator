import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Android Keystore Generator",
  description: "Generate Android Keystore files (PKCS#12 / JKS) 100% client-side in your browser",
};

/**
 * Applies the persisted theme before first paint so there is no flash of the
 * wrong theme. Runs synchronously in <head>; keeps keys in one place via the
 * shared constants (mirrored in components/theme.ts).
 */
const themeInitScript = `
(function () {
  try {
    var STORAGE_KEY = "app-theme";
    var ACCENT_KEY = "app-theme-accent";
    var THEMES = ["light", "dark", "system"];
    var ACCENTS = ["blue", "violet", "emerald", "rose", "orange"];

    function read(key, allowed, fallback) {
      var value = null;
      try { value = window.localStorage.getItem(key); } catch (e) {}
      return allowed.indexOf(value) !== -1 ? value : fallback;
    }

    var theme = read(STORAGE_KEY, THEMES, "system");
    var accent = read(ACCENT_KEY, ACCENTS, "blue");
    var dark =
      theme === "dark" ||
      (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);

    var root = document.documentElement;
    root.classList.toggle("dark", dark);
    root.dataset.accent = accent;
    root.style.colorScheme = dark ? "dark" : "light";
  } catch (e) {}
})();
`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-screen flex flex-col bg-background text-foreground">{children}</body>
    </html>
  );
}
