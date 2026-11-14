// note.rima.su — client side.
//
// Protocol v1 (must match internal/server/api.go):
//   K       = 32 random bytes, lives only in the URL fragment (#...), never sent to the server
//   encKey  = HKDF-SHA256(K, salt = 32 zero bytes, info = "trebuchet-note v1 enc")  -> AES-256-GCM key
//   token   = HKDF-SHA256(K, salt = 32 zero bytes, info = "trebuchet-note v1 auth") -> 32 bytes
//   padded  = uint32be(len(text)) || utf8(text) || zeros, total size in PADDED_SIZES
//   blob    = nonce(12) || AES-GCM(encKey, nonce, padded, aad = "trebuchet-note v1")
//   create: server gets blob + SHA-256(token) + ttl, returns id
//   read:   server gets token, returns blob once and deletes it
//
// DOM rule: only textContent / value / hidden. No innerHTML (CSP enforces Trusted Types).
"use strict";

(() => {
  const VERSION = "trebuchet-note v1";
  const PADDED_SIZES = [512, 2048, 8192, 32768, 65536];
  const MAX_TEXT_BYTES = PADDED_SIZES[PADDED_SIZES.length - 1] - 4;
  const ID_RE = /^[A-Za-z0-9_-]{22}$/;
  const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

  const te = new TextEncoder();
  const td = new TextDecoder("utf-8", { fatal: true });

  // ---------- base64url ----------

  function b64urlEncode(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64urlDecode(str) {
    if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad base64url");
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- crypto ----------

  async function deriveKeys(raw) {
    const base = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey", "deriveBits"]);
    const salt = new Uint8Array(32);
    const encKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: te.encode(VERSION + " enc") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const token = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: te.encode(VERSION + " auth") },
        base,
        256,
      ),
    );
    return { encKey, token };
  }

  function pad(text) {
    const data = te.encode(text);
    if (data.length === 0) throw new Error("empty");
    if (data.length > MAX_TEXT_BYTES) throw new Error("too long");
    const size = PADDED_SIZES.find((s) => s >= data.length + 4);
    const out = new Uint8Array(size);
    new DataView(out.buffer).setUint32(0, data.length, false);
    out.set(data, 4);
    return out;
  }

  function unpad(buf) {
    if (!PADDED_SIZES.includes(buf.length)) throw new Error("bad size");
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);
    if (len === 0 || len > buf.length - 4) throw new Error("bad length");
    for (let i = 4 + len; i < buf.length; i++) {
      if (buf[i] !== 0) throw new Error("bad padding");
    }
    return td.decode(buf.subarray(4, 4 + len));
  }

  async function encrypt(encKey, plain) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: te.encode(VERSION), tagLength: 128 },
        encKey,
        plain,
      ),
    );
    const blob = new Uint8Array(nonce.length + ct.length);
    blob.set(nonce, 0);
    blob.set(ct, nonce.length);
    return blob;
  }

  async function decrypt(encKey, blob) {
    if (blob.length < 12 + 16) throw new Error("bad blob");
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: te.encode(VERSION), tagLength: 128 },
      encKey,
      blob.subarray(12),
    );
    return new Uint8Array(plain);
  }

  // ---------- network ----------

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* non-JSON error */
    }
    return { status: res.status, data };
  }

  // ---------- UI helpers ----------

  const $ = (id) => document.getElementById(id);

  // Errors whose text is safe and meant to be shown to the user.
  class UserError extends Error {}

  function showError(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }

  async function copyFrom(input, button) {
    try {
      await navigator.clipboard.writeText(input.value);
      const old = button.textContent;
      button.textContent = "Скопировано";
      setTimeout(() => (button.textContent = old), 1500);
    } catch {
      input.select();
    }
  }

  function utf8Length(s) {
    return te.encode(s).length;
  }

  // ---------- create page ----------

  function initCreate() {
    const form = $("create-form");
    const text = $("text");
    const ttl = $("ttl");
    const counter = $("counter");
    const submit = $("submit");
    const err = $("error");
    const result = $("result");
    const link = $("link");
    const copy = $("copy");
    const again = $("again");

    const updateCounter = () => {
      const n = utf8Length(text.value);
      counter.textContent = `${n} / ${MAX_TEXT_BYTES} байт`;
      counter.classList.toggle("over", n > MAX_TEXT_BYTES);
    };
    text.addEventListener("input", updateCounter);
    updateCounter();

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.hidden = true;

      const value = text.value;
      if (value.trim() === "") return showError(err, "Сообщение пустое.");
      if (utf8Length(value) > MAX_TEXT_BYTES) return showError(err, "Сообщение слишком длинное.");

      submit.disabled = true;
      try {
        const raw = crypto.getRandomValues(new Uint8Array(32));
        const { encKey, token } = await deriveKeys(raw);
        const padded = pad(value);
        const blob = await encrypt(encKey, padded);
        padded.fill(0);
        const tokenHash = new Uint8Array(await crypto.subtle.digest("SHA-256", token));
        token.fill(0);

        const { status, data } = await postJSON("/api/v1/notes", {
          ciphertext: b64urlEncode(blob),
          token_hash: b64urlEncode(tokenHash),
          ttl: Number(ttl.value),
        });

        if (status === 429) throw new UserError("Слишком много запросов. Подождите минуту.");
        if (status === 503) throw new UserError("Сервис перегружен. Попробуйте позже.");
        if (status !== 201 || !data || typeof data.id !== "string" || !ID_RE.test(data.id)) {
          throw new UserError("Не удалось создать сообщение. Попробуйте ещё раз.");
        }

        link.value = `${location.origin}/n/${data.id}#${b64urlEncode(raw)}`;
        raw.fill(0);
        text.value = "";
        updateCounter();
        form.hidden = true;
        result.hidden = false;
        link.focus();
        link.select();
      } catch (ex) {
        showError(err, ex instanceof UserError ? ex.message : "Что-то пошло не так. Попробуйте ещё раз.");
      } finally {
        submit.disabled = false;
      }
    });

    copy.addEventListener("click", () => copyFrom(link, copy));
    again.addEventListener("click", () => {
      link.value = "";
      result.hidden = true;
      form.hidden = false;
      text.focus();
    });
  }

  // ---------- read page ----------

  function initRead() {
    const intro = $("intro");
    const reveal = $("reveal");
    const err = $("error");
    const result = $("result");
    const message = $("message");
    const copy = $("copy");

    const id = location.pathname.split("/")[2] || "";
    const keyStr = location.hash.slice(1);
    // Remove the key from the address bar and browser history right away.
    history.replaceState(null, "", location.pathname);

    if (!ID_RE.test(id) || !KEY_RE.test(keyStr)) {
      intro.hidden = true;
      return showError(err, "Ссылка повреждена: в ней нет ключа или он неполный. Попросите отправителя прислать ссылку целиком.");
    }

    reveal.addEventListener("click", async () => {
      reveal.disabled = true;
      err.hidden = true;
      try {
        const raw = b64urlDecode(keyStr);
        if (raw.length !== 32) throw new Error("bad key");
        const { encKey, token } = await deriveKeys(raw);
        raw.fill(0);

        const { status, data } = await postJSON(`/api/v1/notes/${id}/take`, { token: b64urlEncode(token) });
        token.fill(0);

        if (status === 404) {
          intro.hidden = true;
          return showError(err, "Сообщение не найдено. Его уже прочитали, у него истёк срок или ссылка неверна.");
        }
        if (status === 429) throw new UserError("Слишком много запросов. Подождите минуту.");
        if (status !== 200 || !data || typeof data.ciphertext !== "string") {
          throw new UserError("Не удалось открыть сообщение.");
        }

        const plain = await decrypt(encKey, b64urlDecode(data.ciphertext));
        message.value = unpad(plain);
        plain.fill(0);

        intro.hidden = true;
        result.hidden = false;
      } catch (ex) {
        reveal.disabled = false;
        showError(err, ex instanceof UserError ? ex.message : "Не удалось открыть сообщение: ссылка повреждена или данные изменены.");
      }
    });

    copy.addEventListener("click", () => copyFrom(message, copy));
  }

  // ---------- boot ----------

  if (!window.isSecureContext || !crypto || !crypto.subtle) {
    document.addEventListener("DOMContentLoaded", () => {
      showError($("error"), "Браузер не поддерживает безопасное шифрование (нужен HTTPS и современный браузер).");
    });
    return;
  }

  const start = () => {
    const page = document.body.dataset.page;
    if (page === "create") initCreate();
    else if (page === "read") initRead();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
