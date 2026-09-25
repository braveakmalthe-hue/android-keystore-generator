"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Check, Monitor, Moon, Palette, Sun } from "lucide-react";
import {
  ACCENTS,
  applyTheme,
  DEFAULT_THEME_PREFS,
  getThemeSnapshot,
  subscribeToTheme,
  type Accent,
  type Theme,
} from "./theme";

const THEME_LABELS: Record<Theme, { label: string; icon: typeof Sun }> = {
  light: { label: "Light", icon: Sun },
  dark: { label: "Dark", icon: Moon },
  system: { label: "System", icon: Monitor },
};

const ACCENT_SWATCH_CLASSES: Record<Accent, string> = {
  blue: "bg-blue-600 dark:bg-blue-500",
  violet: "bg-violet-600 dark:bg-violet-500",
  emerald: "bg-emerald-600 dark:bg-emerald-500",
  rose: "bg-rose-600 dark:bg-rose-500",
  orange: "bg-orange-600 dark:bg-orange-500",
};

export function ThemeToggle() {
  const prefs = useSyncExternalStore(subscribeToTheme, getThemeSnapshot, () => DEFAULT_THEME_PREFS);
  const [open, setOpen] = useState(false);
  const [systemDark, setSystemDark] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Track OS preference so the System option can show the effective mode.
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setSystemDark(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  // Close the popover on outside click / Escape.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const selectTheme = useCallback(
    (next: Theme) => {
      applyTheme(next, prefs.accent);
      setOpen(false);
    },
    [prefs.accent],
  );

  const selectAccent = useCallback(
    (next: Accent) => {
      applyTheme(prefs.theme, next);
    },
    [prefs.theme],
  );

  const { theme, accent } = prefs;
  const effectiveDark = theme === "dark" || (theme === "system" && systemDark);
  const ActiveIcon = theme === "dark" ? Moon : theme === "system" ? Monitor : Sun;

  return (
    <div ref={containerRef} className="relative">
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={`Theme: ${THEME_LABELS[theme].label}. Change theme`}
          className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-border bg-card px-3 text-sm font-medium text-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <ActiveIcon className="h-4 w-4" aria-hidden="true" />
          <span className="hidden sm:inline">{THEME_LABELS[theme].label}</span>
        </button>

        {/* Accent swatches (hidden on small screens; available in the menu) */}
        <div
          role="radiogroup"
          aria-label="Accent color"
          className="hidden items-center gap-1 rounded-lg border border-border bg-card px-1.5 py-1 md:flex"
        >
          {ACCENTS.map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={accent === option}
              aria-label={`${option} accent`}
              onClick={() => selectAccent(option)}
              className={`relative h-6 w-6 rounded-full transition-transform hover:scale-110 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none ${ACCENT_SWATCH_CLASSES[option]}`}
            >
              {accent === option && (
                <Check
                  className="absolute inset-0 m-auto h-3.5 w-3.5 text-white"
                  aria-hidden="true"
                />
              )}
            </button>
          ))}
        </div>
      </div>

      {open && (
        <div
          role="menu"
          aria-label="Theme options"
          className="absolute right-0 z-50 mt-2 w-56 rounded-xl border border-border bg-card p-1.5 shadow-xl shadow-black/10 dark:shadow-black/40"
        >
          {(Object.keys(THEME_LABELS) as Theme[]).map((option) => {
            const Icon = THEME_LABELS[option].icon;
            const selected = theme === option;
            return (
              <button
                key={option}
                type="button"
                role="menuitemradio"
                aria-checked={selected}
                onClick={() => selectTheme(option)}
                className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none ${
                  selected
                    ? "bg-accent font-medium text-accent-foreground"
                    : "text-foreground hover:bg-accent"
                }`}
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
                <span className="flex-1 text-left">{THEME_LABELS[option].label}</span>
                {option === "system" && (
                  <span className="text-xs text-muted-foreground">
                    ({effectiveDark ? "dark" : "light"})
                  </span>
                )}
                {selected && <Check className="h-4 w-4 text-primary" aria-hidden="true" />}
              </button>
            );
          })}

          <div className="my-1.5 border-t border-border" />

          <div className="flex items-center justify-between gap-2 px-3 py-1.5">
            <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
              <Palette className="h-3.5 w-3.5" aria-hidden="true" />
              Accent
            </span>
            <div role="radiogroup" aria-label="Accent color" className="flex items-center gap-1.5">
              {ACCENTS.map((option) => (
                <button
                  key={option}
                  type="button"
                  role="radio"
                  aria-checked={accent === option}
                  aria-label={`${option} accent`}
                  onClick={() => selectAccent(option)}
                  className={`relative h-5 w-5 rounded-full transition-transform hover:scale-110 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none ${
                    ACCENT_SWATCH_CLASSES[option]
                  } ${accent === option ? "ring-2 ring-ring ring-offset-1 ring-offset-card" : ""}`}
                >
                  {accent === option && (
                    <Check
                      className="absolute inset-0 m-auto h-3 w-3 text-white"
                      aria-hidden="true"
                    />
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
