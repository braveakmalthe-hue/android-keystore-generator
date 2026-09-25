/**
 * Writer for the Sun/Java "JKS" (Java KeyStore) binary format, version 2.
 *
 * Only what Android signing needs is implemented: a single private-key entry
 * (key + its certificate chain) protected with the store password. This is the
 * equivalent of `keytool -genkeypair -storetype JKS`.
 *
 * Format references:
 *  - OpenJDK sun/security/provider/JavaKeyStore.java (engineStore / engineLoad)
 *  - OpenJDK sun/security/provider/KeyProtector.java (private-key protection)
 *  - pyjks (https://github.com/kurtbrose/pyjks) — the reference independent
 *    implementation; both are cross-checked below.
 *
 * On-disk layout (all integers big-endian):
 *   magic: u32 = 0xFEEDFEED
 *   version: u32 = 2
 *   entry count: u32 = 1
 *   per entry:
 *     tag: u32 = 1 (private key entry)
 *     alias: u16 length + UTF-8 bytes
 *     timestamp: u64 (milliseconds since epoch)
 *     encrypted key: u32 length + DER EncryptedPrivateKeyInfo (Sun JKS OID)
 *     cert chain: u32 count, then per cert: type (u16 len + UTF-8) + u32 len + DER
 *   integrity digest: 20 bytes =
 *     SHA-1(UTF-16BE(password) ++ "Mighty Aphrodite" ++ all preceding bytes)
 */

import { pki, asn1, md } from "node-forge";
import type { pki as ForgePki } from "node-forge";

/** Length of the random salt/IV used by Sun's private-key protection (KeyProtector.java: SALT_LEN = 20). */
const JKS_SALT_LENGTH = 20;
/** ASCII whitening string prepended to the keystore body before hashing (JavaKeyStore.java). */
const SIGNATURE_WHITENING = "Mighty Aphrodite";
/** OID for Sun's proprietary JKS key-protection algorithm (JavaSoft). */
const SUN_JKS_ALGO_OID = "1.3.6.1.4.1.42.2.17.1.1";

/* ------------------------------------------------------------------ */
/* Byte helpers (all big-endian, per the format)                       */
/* ------------------------------------------------------------------ */

class ByteWriter {
  private parts: number[] = [];

  u16(value: number): this {
    this.parts.push((value >>> 8) & 0xff, value & 0xff);
    return this;
  }

  u32(value: number): this {
    this.parts.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
    return this;
  }

  /** u64 as two u32 halves (values here are ms timestamps, well within range). */
  u64(value: number): this {
    this.u32(Math.floor(value / 0x100000000));
    this.u32(value >>> 0);
    return this;
  }

  /** Java writeUTF-style: u16 length prefix + UTF-8 bytes. */
  utf(text: string): this {
    const encoded = new TextEncoder().encode(text);
    this.u16(encoded.length);
    this.parts.push(...encoded);
    return this;
  }

  /** u32 length prefix + raw bytes. */
  blob(data: Uint8Array): this {
    this.u32(data.length);
    this.parts.push(...data);
    return this;
  }

  raw(data: Uint8Array): this {
    this.parts.push(...data);
    return this;
  }

  toUint8Array(): Uint8Array {
    return new Uint8Array(this.parts);
  }
}

function bytesToBinaryString(bytes: ArrayLike<number>): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return out;
}

function binaryStringToBytes(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function sha1(bytes: Uint8Array): Uint8Array {
  const hex = md.sha1.create().update(bytesToBinaryString(bytes)).digest().toHex();
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Java chars are UTF-16BE code units; JKS hashes/derives keys from this encoding. */
function utf16be(text: string): Uint8Array {
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out[i * 2] = (code >>> 8) & 0xff;
    out[i * 2 + 1] = code & 0xff;
  }
  return out;
}

/**
 * Sun's proprietary SHA-1 keystream used to protect the private key
 * (KeyProtector.java): repeatedly SHA-1(password ++ previous-block), starting
 * from the salt. Bytes of the stream are XORed into the key.
 */
function* jksKeystream(salt: Uint8Array, passwordBytes: Uint8Array): Generator<number> {
  let current = salt;
  for (;;) {
    const digest = sha1(concat(passwordBytes, current));
    current = digest;
    yield* digest;
  }
}

function xorWithKeystream(target: Uint8Array, keystream: Generator<number>): void {
  let i = 0;
  for (const k of keystream) {
    if (i >= target.length) break;
    target[i] ^= k;
    i++;
  }
}

/* ------------------------------------------------------------------ */
/* Private-key protection (Sun JKS OID 1.3.6.1.4.1.42.2.17.1.1)        */
/* ------------------------------------------------------------------ */

/**
 * Encrypt PKCS#8 key bytes with Sun's JKS key-protection scheme and wrap the
 * result in a DER EncryptedPrivateKeyInfo, exactly as KeyProtector.java does.
 *
 * Encrypted data layout: salt(20) ++ ciphertext ++ SHA-1(password ++ plaintext)(20),
 * where the digest is computed over the *unencrypted* PKCS#8 bytes.
 */
function protectPrivateKey(pkcs8Bytes: Uint8Array, password: string): Uint8Array {
  const passwordBytes = utf16be(password);

  const salt = new Uint8Array(JKS_SALT_LENGTH);
  crypto.getRandomValues(salt);

  // Authenticator over the plaintext, per KeyProtector.recover / pyjks.
  const check = sha1(concat(passwordBytes, pkcs8Bytes));

  // In-place XOR with the keystream turns the plaintext into the ciphertext.
  const ciphertext = pkcs8Bytes.slice();
  xorWithKeystream(ciphertext, jksKeystream(salt, passwordBytes));

  // EncryptedPrivateKeyInfo ::= SEQUENCE { algorithm OID (NULL params), OCTET STRING }
  const epki = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(SUN_JKS_ALGO_OID).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ""),
    ]),
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      bytesToBinaryString(concat(salt, ciphertext, check)),
    ),
  ]);

  return binaryStringToBytes(asn1.toDer(epki).getBytes());
}

/* ------------------------------------------------------------------ */
/* Container                                                           */
/* ------------------------------------------------------------------ */

export type JksOptions = {
  /** Forge private key object (e.g. from pki.rsa.generateKeyPair). */
  privateKey: ForgePki.PrivateKey;
  /** DER-encoded X.509 certificate as a binary string (forge convention). */
  certificateDer: string;
  /** Entry alias (normalized to lower-case, as keytool does). */
  alias: string;
  /** Store/key password (used for both, matching keytool for new entries). */
  password: string;
  /** Optional entry creation timestamp in ms; defaults to now. */
  timestamp?: number;
};

/**
 * Build a complete JKS v2 keystore file containing one private-key entry.
 * Returns the raw bytes ready to be written as a `.jks` file.
 */
export function createJksKeystore(options: JksOptions): Uint8Array {
  const { privateKey, certificateDer, alias, password } = options;
  const timestamp = options.timestamp ?? Date.now();

  // Wrap the RSA key (PKCS#1) in a PKCS#8 PrivateKeyInfo, as Java expects.
  const rsaAsn1 = pki.privateKeyToAsn1(privateKey);
  const pkcs8Bytes = binaryStringToBytes(asn1.toDer(pki.wrapRsaPrivateKey(rsaAsn1)).getBytes());

  const body = new ByteWriter();
  body.u32(0xfeedfeed); // magic
  body.u32(2); // version

  // One private-key entry (tag 1).
  body.u32(1);
  body.u32(1);
  body.utf(alias.toLowerCase());
  body.u64(timestamp);
  body.blob(protectPrivateKey(pkcs8Bytes, password));
  body.u32(1); // cert chain length
  body.utf("X.509");
  body.blob(binaryStringToBytes(certificateDer));

  // Integrity digest over UTF-16BE(password) ++ whitening ++ body.
  const digest = sha1(
    concat(utf16be(password), new TextEncoder().encode(SIGNATURE_WHITENING), body.toUint8Array()),
  );
  body.raw(digest);

  return body.toUint8Array();
}
