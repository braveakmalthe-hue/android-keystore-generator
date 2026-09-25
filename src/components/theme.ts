export const THEME_STORAGE_KEY = "app-theme";
export const ACCENT_STORAGE_KEY = "app-theme-accent";

export const THEMES = ["light", "dark", "system"] as const;
export type Theme = (typeof THEMES)[number];

export const ACCENTS = ["blue", "violet", "emerald", "rose", "orange"] as const;
export type Accent = (typeof ACCENTS)[number];

export type ThemePrefs = { theme: Theme; accent: Accent };

/** Server/first-render snapshot before localStorage is available. */
export const DEFAULT_THEME_PREFS: ThemePrefs = { theme: "system", accent: "blue" };

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as readonly string[]).includes(value);
}

export function isAccent(value: unknown): value is Accent {
  return typeof value === "string" && (ACCENTS as readonly string[]).includes(value);
}

/* ------------------------------------------------------------------ */
/* Tiny external store for useSyncExternalStore                        */
/* ------------------------------------------------------------------ */

const THEME_CHANGE_EVENT = "app-theme-change";

let cachedPrefs: ThemePrefs | null = null;

/** Stable snapshot for useSyncExternalStore (same reference between notifications). */
export function getThemeSnapshot(): ThemePrefs {
  if (cachedPrefs === null) {
    try {
      const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
      const storedAccent = window.localStorage.getItem(ACCENT_STORAGE_KEY);
      cachedPrefs = {
        theme: isTheme(storedTheme) ? storedTheme : DEFAULT_THEME_PREFS.theme,
        accent: isAccent(storedAccent) ? storedAccent : DEFAULT_THEME_PREFS.accent,
      };
    } catch {
      cachedPrefs = DEFAULT_THEME_PREFS;
    }
  }
  return cachedPrefs;
}

/** Subscribe to theme changes (ours + other tabs via the `storage` event). */
export function subscribeToTheme(onChange: () => void): () => void {
  const handler = (): void => {
    cachedPrefs = null; // force re-read on next getSnapshot
    onChange();
  };
  window.addEventListener(THEME_CHANGE_EVENT, handler);
  window.addEventListener("storage", handler);
  return () => {
    window.removeEventListener(THEME_CHANGE_EVENT, handler);
    window.removeEventListener("storage", handler);
  };
}

/** Applies theme/accent to <html>, persists, and notifies subscribers. */
export function applyTheme(theme: Theme, accent: Accent): void {
  const root = document.documentElement;
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  root.classList.toggle("dark", dark);
  root.style.colorScheme = dark ? "dark" : "light";
  root.dataset.accent = accent;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    window.localStorage.setItem(ACCENT_STORAGE_KEY, accent);
  } catch {
    // Private mode / storage disabled — theme still applies for this session.
  }
  cachedPrefs = { theme, accent };
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}
