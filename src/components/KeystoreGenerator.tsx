"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from "react";
import { pki, md, asn1, pkcs12 } from "node-forge";
import type { pki as ForgePki } from "node-forge";
import {
  AlertTriangle,
  Check,
  Copy,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileDown,
  Info,
  KeyRound,
  LoaderCircle,
  Lock,
  RotateCcw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

type FormState = {
  alias: string;
  password: string;
  validityYears: number;
  commonName: string;
  organizationalUnit: string;
  organization: string;
  locality: string;
  state: string;
  country: string;
};

type FormErrors = Partial<Record<keyof FormState, string>>;

type OutputState = {
  filename: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
  alias: string;
  validityYears: number;
};

type CopyTarget = "sha1" | "sha256" | "gradle";

type StatusMessage = { kind: "success" | "error"; text: string };

const MIN_PASSWORD_LENGTH = 6;
const MIN_VALIDITY_YEARS = 25;
const MAX_VALIDITY_YEARS = 100;
const DEFAULT_VALIDITY_YEARS = 30;

const INITIAL_FORM: FormState = {
  alias: "upload-key",
  password: "",
  validityYears: DEFAULT_VALIDITY_YEARS,
  commonName: "",
  organizationalUnit: "",
  organization: "",
  locality: "",
  state: "",
  country: "",
};

const INITIAL_OUTPUT: OutputState = {
  filename: "",
  sha1Fingerprint: "",
  sha256Fingerprint: "",
  alias: "",
  validityYears: DEFAULT_VALIDITY_YEARS,
};

/* ------------------------------------------------------------------ */
/* Helpers — pure, no React                                            */
/* ------------------------------------------------------------------ */

/** Strip unsafe characters from the alias so it can be used as a filename. */
function sanitizeFilename(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "");
  return cleaned.length > 0 ? cleaned : "keystore";
}

/** Split a DER byte buffer into uppercase colon-separated hex pairs. */
function formatHexFingerprint(bytes: string): string {
  return (bytes.match(/.{2}/g) ?? []).join(":").toUpperCase();
}

/**
 * Build forge subject/issuer attributes from the certificate identity form
 * values. forge resolves the X.509 OID from the long attribute name, so
 * "name" must be e.g. "commonName" (not "CN"); shortName is for display.
 */
function buildNameAttributes(form: FormState): ForgePki.CertificateField[] {
  const attributes: ForgePki.CertificateField[] = [];
  const entries: Array<[string, string, string]> = [
    ["CN", "commonName", form.commonName],
    ["OU", "organizationalUnitName", form.organizationalUnit],
    ["O", "organizationName", form.organization],
    ["L", "localityName", form.locality],
    ["ST", "stateOrProvinceName", form.state],
    ["C", "countryName", form.country],
  ];
  for (const [shortName, longName, value] of entries) {
    if (value.trim().length > 0) {
      attributes.push({ shortName, name: longName, value: value.trim() });
    }
  }
  return attributes;
}

/**
 * Runs the full cryptographic pipeline. This is only ever invoked from a
 * client-side event handler (never during SSR):
 *
 * 1. RSA-2048 key pair generation (forge.pki.rsa.generateKeyPair)
 * 2. Self-signed X.509 certificate, signed with SHA-256
 * 3. Certificate DER encoding → SHA-1 / SHA-256 fingerprints
 * 4. PKCS#12 container (key + cert, password protected) → DER → Uint8Array
 *
 * Returns the DER-encoded PKCS#12 bytes plus display metadata.
 * Never logs or retains key material beyond the lifetime of this function.
 */
function runCryptoPipeline(form: FormState): { bytes: Uint8Array; metadata: OutputState } {
  // 1. RSA-2048 key pair.
  const keyPair = pki.rsa.generateKeyPair(2048);

  // 2. Self-signed certificate.
  const certificate = pki.createCertificate();
  certificate.publicKey = keyPair.publicKey;
  certificate.serialNumber = "01";
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + form.validityYears);
  certificate.validity.notBefore = now;
  certificate.validity.notAfter = notAfter;

  const attributes = buildNameAttributes(form);
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes); // self-signed: issuer === subject

  certificate.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
      keyCertSign: true,
      cRLSign: true,
    },
    { name: "subjectKeyIdentifier" },
  ]);

  certificate.sign(keyPair.privateKey, md.sha256.create());

  // 3. Fingerprints over the certificate DER.
  const certDer = asn1.toDer(pki.certificateToAsn1(certificate)).getBytes();
  const sha1 = md.sha1.create();
  sha1.update(certDer);
  const sha256 = md.sha256.create();
  sha256.update(certDer);
  const sha1Fingerprint = formatHexFingerprint(sha1.digest().toHex());
  const sha256Fingerprint = formatHexFingerprint(sha256.digest().toHex());

  // 4. PKCS#12 container, with the alias stored as the bag's friendlyName
  // so Android/Gradle `keyAlias` lookups resolve correctly.
  const p12Asn1 = pkcs12.toPkcs12Asn1(keyPair.privateKey, certificate, form.password, {
    friendlyName: form.alias.trim(),
  });
  const p12Der = asn1.toDer(p12Asn1).getBytes();

  // Copy DER bytes out of the forge buffer before returning.
  const bytes = new Uint8Array(new ArrayBuffer(p12Der.length));
  for (let i = 0; i < p12Der.length; i++) {
    bytes[i] = p12Der.charCodeAt(i);
  }

  const filename = `${sanitizeFilename(form.alias)}.keystore`;

  return {
    bytes,
    metadata: {
      filename,
      sha1Fingerprint,
      sha256Fingerprint,
      alias: form.alias.trim(),
      validityYears: form.validityYears,
    },
  };
}

/** Trigger a client-side Blob download and always revoke the object URL. */
function downloadKeystore(bytes: Uint8Array, filename: string): void {
  const blob = new Blob([bytes.buffer as ArrayBuffer], {
    type: "application/x-pkcs12",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  try {
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    URL.revokeObjectURL(url);
  }
}

/** Validate the form; returns a map of field → error message. */
function validateForm(form: FormState): FormErrors {
  const errors: FormErrors = {};

  if (form.password.length < MIN_PASSWORD_LENGTH) {
    errors.password = `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }

  const alias = form.alias.trim();
  if (alias.length === 0) {
    errors.alias = "Key alias is required.";
  }

  if (form.commonName.trim().length === 0) {
    errors.commonName = "Common Name (CN) is required.";
  }

  const country = form.country.trim();
  if (!/^[A-Za-z]{2}$/.test(country)) {
    errors.country = "Country must be exactly 2 letters (e.g. US, DE, IN).";
  }

  if (
    form.validityYears < MIN_VALIDITY_YEARS ||
    form.validityYears > MAX_VALIDITY_YEARS
  ) {
    errors.validityYears = `Validity must be between ${MIN_VALIDITY_YEARS} and ${MAX_VALIDITY_YEARS} years.`;
  }

  return errors;
}

/* ------------------------------------------------------------------ */
/* Small presentational components                                     */
/* ------------------------------------------------------------------ */

function CopyButton({
  target,
  copiedTarget,
  onCopy,
  ariaLabel,
  className = "",
}: {
  target: CopyTarget;
  copiedTarget: CopyTarget | null;
  onCopy: (target: CopyTarget) => void;
  ariaLabel: string;
  className?: string;
}) {
  const copied = copiedTarget === target;
  return (
    <button
      type="button"
      onClick={() => onCopy(target)}
      aria-label={ariaLabel}
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-md border border-border bg-slate-800/60 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700/60 hover:text-white focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none ${
        copied ? "text-emerald-400" : ""
      } ${className}`}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function FieldShell({
  label,
  htmlFor,
  error,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  error?: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-sm font-medium text-slate-200">
        {label}
      </label>
      {children}
      {error ? (
        <p role="alert" className="flex items-center gap-1.5 text-xs text-red-400">
          <TriangleAlert className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-slate-500">{hint}</p>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main component                                                      */
/* ------------------------------------------------------------------ */

export function KeystoreGenerator() {
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [errors, setErrors] = useState<FormErrors>({});

  const [isGenerating, setIsGenerating] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [output, setOutput] = useState<OutputState>(INITIAL_OUTPUT);
  const [showPassword, setShowPassword] = useState(false);
  const [generatedFilename, setGeneratedFilename] = useState("");
  const [copiedTarget, setCopiedTarget] = useState<CopyTarget | null>(null);
  const [status, setStatus] = useState<StatusMessage | null>(null);

  const copyTimerRef = useRef<number | null>(null);
  const statusTimerRef = useRef<number | null>(null);

  useEffect(() => {
    const copyTimer = copyTimerRef;
    const statusTimer = statusTimerRef;
    return () => {
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
      if (statusTimer.current !== null) window.clearTimeout(statusTimer.current);
    };
  }, []);

  const setField = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setErrors((prev) => {
      if (!prev[key]) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  const handleInputChange =
    (key: keyof FormState) => (event: ChangeEvent<HTMLInputElement>) => {
      setField(key, event.target.value);
    };

  const handleCountryChange = (event: ChangeEvent<HTMLInputElement>) => {
    // Allow typing, but normalise to uppercase as the user writes.
    setField("country", event.target.value.toUpperCase());
  };

  const handleValidityChange = (event: ChangeEvent<HTMLInputElement>) => {
    setField("validityYears", Number.parseInt(event.target.value, 10));
  };

  const toggleShowPassword = useCallback(() => {
    setShowPassword((prev) => !prev);
  }, []);

  const handleGenerate = useCallback(() => {
    const validationErrors = validateForm(form);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      setStatus({ kind: "error", text: "Please fix the highlighted fields before generating." });
      return;
    }

    setErrors({});
    setError(null);
    setIsSuccess(false);
    setStatus(null);

    // Let React paint the "Generating RSA-2048..." state before the CPU-heavy
    // synchronous forge work blocks the main thread.
    setIsGenerating(true);
    setTimeout(() => {
      try {
        const { bytes, metadata } = runCryptoPipeline(form);

        downloadKeystore(bytes, metadata.filename);

        setOutput(metadata);
        setGeneratedFilename(metadata.filename);
        setIsSuccess(true);
        setIsGenerating(false);
        setStatus({
          kind: "success",
          text: `Keystore generated successfully. ${metadata.filename} was downloaded to your device.`,
        });

        // Best-effort cleanup of sensitive references. GC-observable only.
        bytes.fill(0);
      } catch (err) {
        // Never surface raw key material or internal forge errors.
        setIsGenerating(false);
        setIsSuccess(false);
        const stage =
          err instanceof Error && err.message.includes("generateKeyPair")
            ? "RSA key generation failed."
            : err instanceof Error && err.message.includes("pkcs12")
              ? "PKCS#12 packaging failed."
              : "Keystore generation failed. Please try again.";
        setError(stage);
        setStatus({ kind: "error", text: stage });
      }
    }, 50);
  }, [form]);

  const handleCopy = useCallback(
    async (target: CopyTarget) => {
      let text: string;
      if (target === "sha1") {
        text = output.sha1Fingerprint;
      } else if (target === "sha256") {
        text = output.sha256Fingerprint;
      } else {
        text = [
          "android {",
          "    signingConfigs {",
          "        release {",
          `            storeFile file("${generatedFilename || "upload-key.keystore"}")`,
          '            storePassword "••••••••"',
          `            keyAlias "${output.alias || "upload-key"}"`,
          '            keyPassword "••••••••"',
          "        }",
          "    }",
          "}",
        ].join("\n");
      }

      try {
        await navigator.clipboard.writeText(text);
        setCopiedTarget(target);
        setStatus({ kind: "success", text: "Copied to clipboard." });
        if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = window.setTimeout(() => setCopiedTarget(null), 2000);
      } catch {
        setStatus({ kind: "error", text: "Clipboard access failed. Select the value and copy it manually." });
      }
    },
    [output.sha1Fingerprint, output.sha256Fingerprint, output.alias, generatedFilename],
  );

  const handleReset = useCallback(() => {
    setForm(INITIAL_FORM);
    setErrors({});
    setError(null);
    setIsSuccess(false);
    setOutput(INITIAL_OUTPUT);
    setGeneratedFilename("");
    setStatus(null);
  }, []);

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 lg:px-8">
      {/* ---------------- Header ---------------- */}
      <header className="mb-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-blue-500/30 bg-blue-500/10">
              <Lock className="h-6 w-6 text-blue-400" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                Android Keystore Generator
              </h1>
              <p className="mt-1 text-sm text-slate-400">
                Create a signing keystore for your Android app — right in your browser.
              </p>
            </div>
          </div>
          <span className="inline-flex w-fit items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-1.5 text-xs font-medium text-emerald-400">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            100% Client-Side
          </span>
        </div>

        {/* Security notice */}
        <div
          role="note"
          aria-label="Security notice"
          className="mt-6 flex items-start gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-3"
        >
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
          <p className="text-sm text-emerald-300/90">
            <span className="font-semibold">🔒 100% Client-Side</span> — Your private key and
            password never leave this browser. All cryptography runs locally on your device.
          </p>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-5">
        {/* ---------------- Configuration card ---------------- */}
        <section
          aria-labelledby="config-heading"
          className="rounded-2xl border border-border bg-card p-6 shadow-xl shadow-black/20 lg:col-span-3"
        >
          <div className="mb-6 flex items-center gap-3">
            <KeyRound className="h-5 w-5 text-blue-400" aria-hidden="true" />
            <h2 id="config-heading" className="text-lg font-semibold text-white">
              Configuration
            </h2>
          </div>

          <div className="grid gap-5 sm:grid-cols-2">
            <FieldShell
              label="Key Alias"
              htmlFor="alias"
              error={errors.alias}
              hint="Used as the key identifier and filename."
            >
              <input
                id="alias"
                type="text"
                value={form.alias}
                onChange={handleInputChange("alias")}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={errors.alias ? true : undefined}
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="upload-key"
              />
            </FieldShell>

            <FieldShell
              label="Keystore Password"
              htmlFor="password"
              error={errors.password}
              hint={`Minimum ${MIN_PASSWORD_LENGTH} characters.`}
            >
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={form.password}
                  onChange={handleInputChange("password")}
                  autoComplete="new-password"
                  aria-invalid={errors.password ? true : undefined}
                  className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 pr-11 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={toggleShowPassword}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-slate-500 hover:text-slate-300 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </FieldShell>

            <div className="sm:col-span-2">
              <FieldShell
                label="Validity (years)"
                htmlFor="validity"
                error={errors.validityYears}
                hint={`Android requires signing certificates valid until at least October 2033. ${MIN_VALIDITY_YEARS}–${MAX_VALIDITY_YEARS} years is recommended.`}
              >
                <div className="flex items-center gap-4">
                  <input
                    id="validity"
                    type="range"
                    min={MIN_VALIDITY_YEARS}
                    max={MAX_VALIDITY_YEARS}
                    step={1}
                    value={form.validityYears}
                    onChange={handleValidityChange}
                    aria-describedby="validity-display"
                    className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-slate-700 accent-blue-500"
                  />
                  <span
                    id="validity-display"
                    aria-hidden="true"
                    className="w-12 shrink-0 rounded-md border border-border bg-slate-800/50 py-1 text-center font-mono text-sm text-blue-400"
                  >
                    {form.validityYears}
                  </span>
                </div>
              </FieldShell>
            </div>

            <FieldShell
              label="Common Name (CN)"
              htmlFor="commonName"
              error={errors.commonName}
              hint="Usually your name or company."
            >
              <input
                id="commonName"
                type="text"
                value={form.commonName}
                onChange={handleInputChange("commonName")}
                autoComplete="off"
                aria-invalid={errors.commonName ? true : undefined}
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="John Doe"
              />
            </FieldShell>

            <FieldShell
              label="Organizational Unit (OU)"
              htmlFor="organizationalUnit"
              hint="Optional — e.g. Engineering."
            >
              <input
                id="organizationalUnit"
                type="text"
                value={form.organizationalUnit}
                onChange={handleInputChange("organizationalUnit")}
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="Engineering"
              />
            </FieldShell>

            <FieldShell
              label="Organization (O)"
              htmlFor="organization"
              hint="Optional — company name."
            >
              <input
                id="organization"
                type="text"
                value={form.organization}
                onChange={handleInputChange("organization")}
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="Acme Corp"
              />
            </FieldShell>

            <FieldShell label="City / Locality (L)" htmlFor="locality" hint="Optional.">
              <input
                id="locality"
                type="text"
                value={form.locality}
                onChange={handleInputChange("locality")}
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="San Francisco"
              />
            </FieldShell>

            <FieldShell
              label="State / Province (ST)"
              htmlFor="state"
              hint="Optional."
            >
              <input
                id="state"
                type="text"
                value={form.state}
                onChange={handleInputChange("state")}
                autoComplete="off"
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="California"
              />
            </FieldShell>

            <FieldShell
              label="Country (C)"
              htmlFor="country"
              error={errors.country}
              hint="Two-letter ISO code."
            >
              <input
                id="country"
                type="text"
                value={form.country}
                onChange={handleCountryChange}
                autoComplete="country"
                maxLength={2}
                aria-invalid={errors.country ? true : undefined}
                className="w-full rounded-lg border border-border bg-slate-800/50 px-3 py-2.5 font-mono text-sm tracking-widest text-white uppercase placeholder-slate-500 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                placeholder="US"
              />
            </FieldShell>
          </div>
        </section>

        {/* ---------------- Sidebar ---------------- */}
        <div className="flex flex-col gap-6 lg:col-span-2">
          {/* Generate section */}
          <section aria-labelledby="generate-heading" className="rounded-2xl border border-border bg-card p-6">
            <h2 id="generate-heading" className="sr-only">
              Generate keystore
            </h2>

            {error && (
              <div
                role="alert"
                className="mb-4 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
                <p className="text-sm text-red-300">{error}</p>
              </div>
            )}

            {isSuccess && !isGenerating && (
              <div
                role="status"
                className="mb-4 flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3"
              >
                <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
                <div className="text-sm text-emerald-300">
                  <p className="font-medium">✓ Keystore generated successfully</p>
                  <p className="mt-0.5 font-mono text-xs text-emerald-400/80">
                    {generatedFilename}
                  </p>
                </div>
              </div>
            )}

            <div className="flex flex-col gap-3">
              <button
                type="button"
                onClick={handleGenerate}
                disabled={isGenerating}
                className="inline-flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 text-sm font-semibold text-white transition-colors hover:bg-blue-500 focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-2 focus-visible:ring-offset-[#18181b] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isGenerating ? (
                  <>
                    <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />
                    Generating RSA-2048...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4" aria-hidden="true" />
                    Generate Keystore
                  </>
                )}
              </button>
              {(isSuccess || error) && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-xl border border-border bg-slate-800/50 px-6 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-700/50 focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:outline-none"
                >
                  <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  Reset form
                </button>
              )}
            </div>

            {output.filename && (
              <dl className="mt-5 space-y-2 border-t border-border pt-4 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-500">Format</dt>
                  <dd className="font-mono text-xs text-slate-300">PKCS#12</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-500">File</dt>
                  <dd className="truncate font-mono text-xs text-slate-300">{output.filename}</dd>
                </div>
              </dl>
            )}
          </section>

          {/* Integrity / output */}
          <section
            aria-labelledby="integrity-heading"
            className="rounded-2xl border border-border bg-card p-6"
          >
            <div className="mb-5 flex items-center gap-3">
              <Cpu className="h-5 w-5 text-blue-400" aria-hidden="true" />
              <h2 id="integrity-heading" className="text-lg font-semibold text-white">
                Integrity &amp; Output
              </h2>
            </div>

            {output.sha1Fingerprint ? (
              <div className="space-y-5">
                <div>
                  <p className="mb-1.5 text-xs font-medium tracking-wide text-slate-400 uppercase">
                    SHA-1 Fingerprint
                  </p>
                  <div className="flex items-start justify-between gap-2 rounded-lg border border-border bg-slate-800/50 p-3">
                    <code className="font-mono text-xs leading-relaxed break-all text-emerald-400 select-all">
                      {output.sha1Fingerprint}
                    </code>
                    <CopyButton
                      target="sha1"
                      copiedTarget={copiedTarget}
                      onCopy={handleCopy}
                      ariaLabel="Copy SHA-1 fingerprint to clipboard"
                    />
                  </div>
                </div>

                <div>
                  <p className="mb-1.5 text-xs font-medium tracking-wide text-slate-400 uppercase">
                    SHA-256 Fingerprint
                  </p>
                  <div className="flex items-start justify-between gap-2 rounded-lg border border-border bg-slate-800/50 p-3">
                    <code className="font-mono text-xs leading-relaxed break-all text-emerald-400 select-all">
                      {output.sha256Fingerprint}
                    </code>
                    <CopyButton
                      target="sha256"
                      copiedTarget={copiedTarget}
                      onCopy={handleCopy}
                      ariaLabel="Copy SHA-256 fingerprint to clipboard"
                    />
                  </div>
                </div>

                <dl className="space-y-2 border-t border-border pt-4 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-slate-500">Algorithm</dt>
                    <dd className="font-mono text-xs text-slate-300">RSA 2048</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-slate-500">Signature</dt>
                    <dd className="font-mono text-xs text-slate-300">SHA-256</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-slate-500">Format</dt>
                    <dd className="font-mono text-xs text-slate-300">PKCS#12</dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-slate-500">Validity</dt>
                    <dd className="font-mono text-xs text-slate-300">
                      {output.validityYears} years
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <dt className="text-slate-500">Alias</dt>
                    <dd className="truncate font-mono text-xs text-slate-300">{output.alias}</dd>
                  </div>
                </dl>
              </div>
            ) : (
              <p className="rounded-lg border border-dashed border-border bg-slate-800/30 px-4 py-6 text-center text-sm text-slate-500">
                Fingerprints and certificate details will appear here after generation.
              </p>
            )}

            <div className="mt-5 flex items-start gap-2.5 rounded-lg border border-blue-500/20 bg-blue-500/5 px-3.5 py-3">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-blue-400" aria-hidden="true" />
              <p className="text-xs leading-relaxed text-blue-300/80">
                The <code className="font-mono">.keystore</code> file is a{" "}
                <strong>PKCS#12</strong> container. Modern Java tooling (including Android
                Studio and Gradle) uses PKCS#12 as the default keystore format, so it works
                directly with <code className="font-mono">signingConfigs</code>.
              </p>
            </div>
          </section>

          {/* Gradle preview */}
          <section
            aria-labelledby="gradle-heading"
            className="rounded-2xl border border-border bg-card p-6"
          >
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 id="gradle-heading" className="text-lg font-semibold text-white">
                Android Gradle Preview
              </h2>
              <CopyButton
                target="gradle"
                copiedTarget={copiedTarget}
                onCopy={handleCopy}
                ariaLabel="Copy Gradle signing configuration to clipboard"
              />
            </div>
            <pre className="overflow-x-auto rounded-lg border border-border bg-slate-950/70 p-4 font-mono text-xs leading-relaxed text-slate-300">
              <code>
                {`android {
    signingConfigs {
        release {
            storeFile file("${generatedFilename || "upload-key.keystore"}")
            storePassword "••••••••"
            keyAlias "${output.alias || form.alias.trim() || "upload-key"}"
            keyPassword "••••••••"
        }
    }
}`}
              </code>
            </pre>
            <p className="mt-3 flex items-start gap-2 text-xs text-slate-500">
              <FileDown className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              Passwords are masked for safety — replace the dots with your real passwords in
              gradle.properties or your CI secrets, never in this file.
            </p>
          </section>
        </div>
      </div>

      {/* Screen-reader-friendly status region */}
      <div aria-live="polite" role="status" className="sr-only">
        {isGenerating
          ? "Generating RSA-2048 key pair, this may take a few seconds."
          : status
            ? status.text
            : ""}
      </div>

      {/* Acknowledged error banner lives in the generate card; keep a
          persistent footer note for privacy. */}
      <footer className="mt-10 border-t border-border pt-6 pb-4 text-center text-xs text-slate-600">
        All cryptographic operations run locally in your browser. No uploads, no servers, no
        telemetry.
      </footer>
    </div>
  );
}
