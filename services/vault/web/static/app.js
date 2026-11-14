// app.rima.su — accounts, client side.
//
// The password never leaves this page:
//   masterKey = PBKDF2-HMAC-SHA-512(NFKC(password), salt, iterations >= 600000)
//   authKey   = HKDF-SHA-256(masterKey, "trebuchet auth v1")  -> server, proves the password
//   metaKey   = HKDF-SHA-256(masterKey, "trebuchet meta v1")  -> server, opens metadata in a session
//   wrapKey   = HKDF-SHA-256(masterKey, "trebuchet wrap v1")  -> never leaves the browser
// The recovery code (32 random bytes) derives the same three keys with
// "trebuchet recovery ... v1" labels.
// keyset = AES-256-GCM(wrapKey, {identity Ed25519, exchange X25519 private keys})
//
// DOM rule: only textContent / value / hidden. No innerHTML (CSP enforces Trusted Types).
"use strict";

(() => {
  const ITER_DEFAULT = 600000;
  const ITER_MIN = 600000;
  const ITER_MAX = 10000000;
  const PW_MIN = 15;
  const PW_MAX = 256;
  const PHRASE_BITS = 90;
  const LOGIN_RE = /^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$/;
  const B64_32_RE = /^[A-Za-z0-9_-]{43}$/;
  const FORBIDDEN_PARTS = ["trebuchet", "rima"];
  const KEYSET_AAD = "trebuchet keyset v1";

  const te = new TextEncoder();
  const td = new TextDecoder("utf-8", { fatal: true });
  const subtle = crypto.subtle;

  // ---------- encoding ----------

  function b64e(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64d(str) {
    if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad base64url");
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Recovery code: 64 hex digits shown in groups of 4; separators are ignored on input.
  function formatCode(bytes) {
    return hex(bytes).match(/.{4}/g).join("-");
  }

  function parseCode(str) {
    const h = str.toLowerCase().replace(/[\s-]/g, "");
    if (!/^[0-9a-f]{64}$/.test(h)) return null;
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }

  // Must match seal.AAD in Go: label || 0 || (uint16be(len) || part)...
  function aad(label, ...parts) {
    const chunks = [te.encode(label), new Uint8Array([0])];
    for (const p of parts) chunks.push(new Uint8Array([p.length >> 8, p.length & 255]), p);
    return concat(...chunks);
  }

  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  // ---------- key derivation ----------

  const ZERO_SALT = new Uint8Array(32);

  async function hkdfBits(base, info) {
    return new Uint8Array(
      await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: te.encode(info) }, base, 256),
    );
  }

  async function hkdfAes(base, info) {
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: te.encode(info) },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function passwordKeys(password, salt, iterations) {
    if (!Number.isInteger(iterations) || iterations < ITER_MIN || iterations > ITER_MAX) {
      // A compromised server could try to make passwords cheap to guess.
      throw new UserError("Сервер прислал небезопасные параметры входа. Вход отменён.");
    }
    if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new UserError("Сервер прислал неверные параметры входа.");
    const pw = te.encode(password.normalize("NFKC"));
    const pbkdf = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
    pw.fill(0);
    const master = new Uint8Array(
      await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations }, pbkdf, 256),
    );
    const base = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
    master.fill(0);
    return {
      authKey: await hkdfBits(base, "trebuchet auth v1"),
      metaKey: await hkdfBits(base, "trebuchet meta v1"),
      wrapKey: await hkdfAes(base, "trebuchet wrap v1"),
    };
  }

  async function recoveryKeys(code) {
    const base = await subtle.importKey("raw", code, "HKDF", false, ["deriveBits", "deriveKey"]);
    return {
      authKey: await hkdfBits(base, "trebuchet recovery auth v1"),
      metaKey: await hkdfBits(base, "trebuchet recovery meta v1"),
      wrapKey: await hkdfAes(base, "trebuchet recovery wrap v1"),
    };
  }

  async function encrypt(key, plain, label) {
    const iv = random(12);
    const ct = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(label), tagLength: 128 }, key, plain),
    );
    return concat(iv, ct);
  }

  async function decrypt(key, blob, label) {
    if (blob.length < 12 + 16) throw new Error("short blob");
    return new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: te.encode(label), tagLength: 128 },
        key,
        blob.subarray(12),
      ),
    );
  }

  // ---------- identity keys ----------

  async function newIdentity() {
    let id, ex;
    try {
      id = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      ex = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    } catch {
      throw new UserError("Браузер не поддерживает Ed25519/X25519. Обновите его (Chrome 137+, Firefox, Safari 17+).");
    }
    const identityPub = new Uint8Array(await subtle.exportKey("raw", id.publicKey));
    const exchangePub = new Uint8Array(await subtle.exportKey("raw", ex.publicKey));
    const sig = new Uint8Array(
      await subtle.sign("Ed25519", id.privateKey, aad("trebuchet register v1", identityPub, exchangePub)),
    );
    const keysetPlain = te.encode(
      JSON.stringify({
        v: 1,
        identity: b64e(new Uint8Array(await subtle.exportKey("pkcs8", id.privateKey))),
        exchange: b64e(new Uint8Array(await subtle.exportKey("pkcs8", ex.privateKey))),
      }),
    );
    return { identityPub, exchangePub, sig, keysetPlain };
  }

  // Opens the keyset and imports the private keys as non-extractable.
  async function unlockKeyset(wrapKey, keysetB64, identityPubB64) {
    const plain = await decrypt(wrapKey, b64d(keysetB64), KEYSET_AAD);
    let ks;
    try {
      ks = JSON.parse(td.decode(plain));
    } finally {
      plain.fill(0);
    }
    if (!ks || ks.v !== 1 || typeof ks.identity !== "string" || typeof ks.exchange !== "string") {
      throw new Error("bad keyset");
    }
    const identity = await subtle.importKey("pkcs8", b64d(ks.identity), { name: "Ed25519" }, false, ["sign"]);
    const exchange = await subtle.importKey("pkcs8", b64d(ks.exchange), { name: "X25519" }, false, ["deriveBits"]);
    // The private key must match the public key the server published for us.
    const pub = await subtle.importKey("raw", b64d(identityPubB64), { name: "Ed25519" }, false, ["verify"]);
    const probe = random(32);
    const sig = await subtle.sign("Ed25519", identity, probe);
    if (!(await subtle.verify("Ed25519", pub, sig, probe))) throw new Error("keyset does not match");
    return { identity, exchange };
  }

  async function readKeysetPlain(wrapKey, keysetB64) {
    return decrypt(wrapKey, b64d(keysetB64), KEYSET_AAD);
  }

  async function fingerprint(identityPubB64, exchangePubB64) {
    const d = new Uint8Array(
      await subtle.digest("SHA-256", concat(te.encode("trebuchet fingerprint v1"), b64d(identityPubB64), b64d(exchangePubB64))),
    );
    const dv = new DataView(d.buffer);
    const groups = [];
    for (let i = 0; i < 6; i++) groups.push(String(dv.getUint32(i * 4) % 100000).padStart(5, "0"));
    return groups.join(" ");
  }

  // ---------- password policy (the server never sees the password) ----------

  let wordsPromise = null;
  let blockPromise = null;

  async function fetchList(name, integrity) {
    const res = await fetch(`/static/${name}`, {
      integrity,
      credentials: "omit",
      cache: "no-cache",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) throw new Error("list unavailable");
    return (await res.text())
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s !== "" && !s.startsWith("#"));
  }

  const words = () => (wordsPromise ||= fetchList("words.txt", document.body.dataset.wordsIntegrity).then((l) => [...new Set(l)]));
  const blocklist = () =>
    (blockPromise ||= fetchList("blocklist.txt", document.body.dataset.blocklistIntegrity).then(
      (l) => new Set(l.map((s) => s.normalize("NFKC").toLowerCase())),
    ));

  // Uniform integer in [0, n) without modulo bias.
  function randomBelow(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % n;
    }
  }

  async function generatePhrase() {
    const list = await words();
    if (list.length < 1024) throw new Error("word list too short");
    const count = Math.ceil(PHRASE_BITS / Math.log2(list.length));
    const out = [];
    for (let i = 0; i < count; i++) out.push(list[randomBelow(list.length)]);
    return out.join("-");
  }

  async function passwordProblem(password, login) {
    const pw = password.normalize("NFKC");
    const len = [...pw].length;
    if (len < PW_MIN) return `Пароль слишком короткий: нужно не меньше ${PW_MIN} символов.`;
    if (len > PW_MAX) return `Пароль слишком длинный: не больше ${PW_MAX} символов.`;
    const lower = pw.toLowerCase();
    if (login && lower.includes(login)) return "Пароль не должен содержать логин.";
    if (FORBIDDEN_PARTS.some((p) => lower.includes(p))) return "Пароль не должен содержать название сервиса.";
    if (new Set(lower).size < 5) return "Пароль слишком однообразный.";
    if (/^(.{1,8}?)\1+$/su.test(lower)) return "Пароль — это повторение одного куска.";
    if ((await blocklist()).has(lower)) return "Этот пароль есть в списках утёкших. Выберите другой.";
    return null;
  }

  // ---------- network ----------

  async function api(method, url, body) {
    const opts = {
      method,
      headers: {},
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    let data = null;
    if (res.status !== 204) {
      try {
        data = await res.json();
      } catch {
        /* non-JSON error */
      }
    }
    if (res.status === 429) throw new UserError("Слишком много попыток. Подождите несколько минут.");
    return { status: res.status, data };
  }

  async function prelogin(login) {
    const { status, data } = await api("POST", "/api/v1/auth/prelogin", { login });
    if (status !== 200 || !data || typeof data.salt !== "string") throw new UserError("Не удалось начать вход.");
    return { salt: b64d(data.salt), iterations: data.iterations };
  }

  function validAccount(a) {
    return (
      a && typeof a.login === "string" && typeof a.keyset === "string" &&
      B64_32_RE.test(a.identity_pub) && B64_32_RE.test(a.exchange_pub)
    );
  }

  // ---------- UI ----------

  class UserError extends Error {}

  const $ = (id) => document.getElementById(id);
  const views = ["login", "register", "code", "recover", "account"];
  const state = { account: null, keys: null, afterCode: null, codeText: "", phraseBits: 0 };

  // Messages go to the signed-out card or to the settings page.
  const msgEls = () =>
    document.body.classList.contains("authed")
      ? { status: $("acc-status"), error: $("acc-error") }
      : { status: $("status"), error: $("error") };

  function clearMessages() {
    for (const id of ["status", "error", "acc-status", "acc-error"]) $(id).hidden = true;
  }

  function show(view) {
    for (const v of views) $(`view-${v}`).hidden = v !== view;
    document.body.classList.toggle("authed", view === "account");
    clearMessages();
    window.scrollTo(0, 0);
  }

  function showError(ex) {
    const el = msgEls().error;
    el.textContent = ex instanceof UserError ? ex.message : "Что-то пошло не так. Попробуйте ещё раз.";
    el.hidden = false;
  }

  function status(msg) {
    const el = msgEls().status;
    el.textContent = msg || "";
    el.hidden = !msg;
  }

  // Runs an async form action: buttons disabled, the submit button names what
  // is happening ("Проверяем пароль…"), errors shown, everything restored after.
  function action(form, fn) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const buttons = form.querySelectorAll("button");
      const submit = form.querySelector('button[type="submit"]');
      const label = submit.textContent;
      const cap = form.querySelector("[data-busy-cap]");
      buttons.forEach((b) => (b.disabled = true));
      if (submit.dataset.busy) submit.textContent = submit.dataset.busy;
      if (cap) cap.hidden = false;
      clearMessages();
      try {
        await fn();
      } catch (ex) {
        status("");
        showError(ex);
      } finally {
        buttons.forEach((b) => (b.disabled = false));
        submit.textContent = label;
        if (cap) cap.hidden = true;
      }
    });
  }

  // ---------- password fields: counter, meter, inline error ----------

  function plural(n) {
    const m = n % 10;
    const h = n % 100;
    if (m === 1 && h !== 11) return "символ";
    if (m >= 2 && m <= 4 && (h < 12 || h > 14)) return "символа";
    return "символов";
  }

  function updateMeter(input) {
    const field = input.closest(".field");
    const n = [...input.value.normalize("NFKC")].length;
    const count = field.querySelector("[data-count]");
    if (count) count.textContent = `${n} ${plural(n)} · от ${PW_MIN}`;
    // Length only: the blocklist and other checks run on submit.
    const lvl = n === 0 ? 0 : n < PW_MIN ? 1 : n < 20 ? 2 : n < 28 ? 3 : 4;
    field.querySelectorAll(".meter i").forEach((i, k) => i.classList.toggle("on", k < lvl));
    field.classList.remove("err");
    const hint = field.querySelector("[data-hint]");
    if (hint) hint.hidden = true;
  }

  function fieldError(input, msg) {
    const field = input.closest(".field");
    field.classList.add("err");
    const hint = field.querySelector("[data-hint]");
    if (hint) {
      hint.textContent = msg;
      hint.hidden = false;
    }
    input.focus();
  }

  function initMeters() {
    for (const input of document.querySelectorAll("input[data-meter]")) {
      input.addEventListener("input", () => updateMeter(input));
      updateMeter(input);
    }
  }

  // ---------- small helpers ----------

  function readLogin(input) {
    const login = input.value.trim().toLowerCase();
    if (!LOGIN_RE.test(login)) {
      throw new UserError("Логин: 3–32 символа, латиница в нижнем регистре, цифры, точка, дефис, подчёркивание.");
    }
    return login;
  }

  async function readNewPassword(a, b, login) {
    if (a.value !== b.value) throw new UserError("Пароли не совпадают.");
    const problem = await passwordProblem(a.value, login);
    if (problem) throw new UserError(problem);
    return a.value;
  }

  async function fillGenerated(...inputs) {
    try {
      const phrase = await generatePhrase();
      for (const i of inputs) {
        i.value = phrase;
        i.type = "text";
        if (i.hasAttribute("data-meter")) updateMeter(i);
      }
    } catch (ex) {
      showError(ex);
    }
  }

  // Copies text; if the Clipboard API is unavailable, selects it instead.
  async function copyText(text, button, selectEl) {
    const label = button.querySelector("span") || button;
    const old = label.textContent;
    const done = (msg) => {
      label.textContent = msg;
      setTimeout(() => (label.textContent = old), 1600);
    };
    try {
      await navigator.clipboard.writeText(text);
      done("Скопировано");
    } catch {
      if (selectEl instanceof HTMLInputElement || selectEl instanceof HTMLTextAreaElement) {
        selectEl.select();
      } else {
        const range = document.createRange();
        range.selectNodeContents(selectEl);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
      done("Выделено, нажмите Ctrl+C");
    }
  }

  function clearAll(...arrays) {
    for (const a of arrays) if (a instanceof Uint8Array) a.fill(0);
  }

  // ---------- recovery code ----------

  function showCode(code, then, isRegistration) {
    const text = formatCode(code);
    code.fill(0);
    state.codeText = text;
    const grid = $("code-value");
    grid.replaceChildren();
    for (const g of text.split("-")) {
      const s = document.createElement("span");
      s.textContent = g;
      grid.append(s);
    }
    $("code-step").hidden = !isRegistration;
    $("code-saved").checked = false;
    $("code-done").disabled = true;
    state.afterCode = then;
    show("code");
  }

  // Saves the code as a text file. It is the user's explicit choice; the file
  // never touches the server.
  function saveCode() {
    const login = state.account ? state.account.login : "";
    const body =
      "Trebuchet — код восстановления\n\n" +
      `Логин: ${login}\n` +
      `Код:   ${state.codeText}\n` +
      `Выдан: ${new Date().toLocaleString("ru-RU")}\n\n` +
      "Код заменяет пароль. Храните офлайн, никому не пересылайте.\n" +
      "Старый код перестаёт действовать, когда выдаётся новый.\n";
    const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `trebuchet-recovery-${login || "code"}.txt`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- account page ----------

  async function showAccount() {
    const a = state.account;
    const fp = await fingerprint(a.identity_pub, a.exchange_pub);
    $("acc-login").textContent = a.login;
    $("pw-username").value = a.login;
    $("acc-fp").textContent = fp;
    // After a page reload the session is alive but the keys are not: they
    // exist only in memory of the tab where the password was entered.
    $("acc-keys").textContent = state.keys ? "разблокированы" : "заблокированы";
    $("acc-invite-box").hidden = !a.admin;
    $("acc-invite-out").hidden = true;
    $("who-av").textContent = a.login.slice(0, 1).toUpperCase();
    $("who-login").textContent = a.login;
    $("who-fp").textContent = fp.split(" ").slice(0, 2).join(" ");
    show("account");
  }

  async function signedIn(account, wrapKey) {
    if (!validAccount(account)) throw new UserError("Сервер прислал неверный ответ.");
    state.account = account;
    state.keys = null;
    if (wrapKey) {
      try {
        state.keys = await unlockKeyset(wrapKey, account.keyset, account.identity_pub);
      } catch {
        throw new UserError("Не удалось расшифровать ключи аккаунта. Возможно, данные на сервере повреждены.");
      }
    }
  }

  function signedOut() {
    state.account = null;
    state.keys = null;
    for (const f of document.querySelectorAll("form")) f.reset();
    for (const d of document.querySelectorAll("details")) d.open = false;
    document.querySelectorAll("input[data-meter]").forEach(updateMeter);
    show("login");
  }

  // ---------- flows ----------

  function initLogin() {
    action($("login-form"), async () => {
      const login = readLogin($("login-name"));
      const pwInput = $("login-password");
      const password = pwInput.value;
      const n = [...password.normalize("NFKC")].length;
      // Every account has a password of at least PW_MIN characters.
      if (n < PW_MIN) return fieldError(pwInput, `Минимум ${PW_MIN} символов. Сейчас ${n}.`);
      const { salt, iterations } = await prelogin(login);
      const k = await passwordKeys(password, salt, iterations);
      const { status: st, data } = await api("POST", "/api/v1/auth/login", {
        login,
        auth_key: b64e(k.authKey),
        meta_key: b64e(k.metaKey),
      });
      clearAll(k.authKey, k.metaKey);
      if (st === 401) throw new UserError("Неверный логин или пароль.");
      if (st !== 200) throw new UserError("Не удалось войти.");
      await signedIn(data, k.wrapKey);
      pwInput.value = "";
      updateMeter(pwInput);
      await showAccount();
    });
  }

  // Registration offers a generated passphrase by default; a custom password
  // is one click away. Inactive inputs are disabled so the browser neither
  // validates nor autofills them.
  function setRegisterMode(mode) {
    const own = mode === "own";
    $("reg-phrase-box").hidden = own;
    $("reg-own-box").hidden = !own;
    $("reg-phrase").disabled = own;
    $("reg-password").disabled = !own;
    $("reg-password2").disabled = !own;
    $("register-form").dataset.mode = mode;
    if (own) $("reg-password").focus();
  }

  async function newPhrase() {
    try {
      const phrase = await generatePhrase();
      const list = await words();
      const count = phrase.split("-").length;
      $("reg-phrase").value = phrase;
      $("reg-phrase-meta").textContent = `${count} слов · ≈ ${Math.floor(count * Math.log2(list.length))} бит`;
    } catch (ex) {
      showError(ex);
    }
  }

  function enterRegister() {
    show("register");
    setRegisterMode("phrase");
    if (!$("reg-phrase").value) newPhrase();
  }

  function initRegister() {
    $("reg-regen").addEventListener("click", newPhrase);
    $("reg-copy").addEventListener("click", () => copyText($("reg-phrase").value, $("reg-copy"), $("reg-phrase")));
    $("reg-own").addEventListener("click", () => setRegisterMode("own"));
    $("reg-use-phrase").addEventListener("click", () => setRegisterMode("phrase"));
    $("reg-show").addEventListener("change", (e) => {
      const t = e.target.checked ? "text" : "password";
      $("reg-password").type = t;
      $("reg-password2").type = t;
    });

    action($("register-form"), async () => {
      const invite = $("reg-invite").value.trim();
      if (!B64_32_RE.test(invite)) throw new UserError("Код приглашения неполный. Скопируйте его целиком.");
      const login = readLogin($("reg-name"));
      let password;
      if ($("register-form").dataset.mode === "own") {
        password = await readNewPassword($("reg-password"), $("reg-password2"), login);
      } else {
        password = $("reg-phrase").value;
        const problem = await passwordProblem(password, login);
        if (problem) throw new UserError(problem);
      }

      const salt = random(32);
      const k = await passwordKeys(password, salt, ITER_DEFAULT);
      const id = await newIdentity();
      const keyset = await encrypt(k.wrapKey, id.keysetPlain, KEYSET_AAD);
      const code = random(32);
      const r = await recoveryKeys(code);
      const recKeyset = await encrypt(r.wrapKey, id.keysetPlain, KEYSET_AAD);
      id.keysetPlain.fill(0);

      const { status: st, data } = await api("POST", "/api/v1/auth/register", {
        login,
        invite,
        credentials: {
          salt: b64e(salt),
          iterations: ITER_DEFAULT,
          auth_key: b64e(k.authKey),
          meta_key: b64e(k.metaKey),
          keyset: b64e(keyset),
        },
        recovery: { auth_key: b64e(r.authKey), meta_key: b64e(r.metaKey), keyset: b64e(recKeyset) },
        identity_pub: b64e(id.identityPub),
        exchange_pub: b64e(id.exchangePub),
        identity_sig: b64e(id.sig),
      });
      clearAll(k.authKey, k.metaKey, r.authKey, r.metaKey);
      if (st === 403) throw new UserError("Приглашение недействительно: неверное, уже использовано или истекло.");
      if (st === 409) throw new UserError("Этот логин занят.");
      if (st !== 201) throw new UserError("Не удалось создать аккаунт.");
      await signedIn(data, k.wrapKey);
      for (const f of ["reg-invite", "reg-phrase", "reg-password", "reg-password2"]) $(f).value = "";
      showCode(code, showAccount, true);
    });
  }

  function initRecover() {
    $("rec-generate").addEventListener("click", () => fillGenerated($("rec-password"), $("rec-password2")));

    action($("recover-form"), async () => {
      const login = readLogin($("rec-name"));
      const code = parseCode($("rec-code").value);
      if (!code) throw new UserError("Код восстановления: 64 шестнадцатеричных символа.");
      const password = await readNewPassword($("rec-password"), $("rec-password2"), login);

      const r = await recoveryKeys(code);
      code.fill(0);
      const first = await api("POST", "/api/v1/auth/recovery/keyset", { login, recovery_auth: b64e(r.authKey) });
      if (first.status === 401) throw new UserError("Неверный логин или код восстановления.");
      if (first.status !== 200 || !first.data) throw new UserError("Не удалось восстановить доступ.");
      let plain;
      try {
        plain = await readKeysetPlain(r.wrapKey, first.data.keyset);
      } catch {
        throw new UserError("Не удалось расшифровать ключи кодом восстановления.");
      }

      const salt = random(32);
      const k = await passwordKeys(password, salt, ITER_DEFAULT);
      const nextCode = random(32);
      const nr = await recoveryKeys(nextCode);
      const keyset = await encrypt(k.wrapKey, plain, KEYSET_AAD);
      const recKeyset = await encrypt(nr.wrapKey, plain, KEYSET_AAD);
      plain.fill(0);

      const { status: st } = await api("POST", "/api/v1/auth/recovery/reset", {
        login,
        recovery: { auth_key: b64e(r.authKey), meta_key: b64e(r.metaKey) },
        credentials: {
          salt: b64e(salt),
          iterations: ITER_DEFAULT,
          auth_key: b64e(k.authKey),
          meta_key: b64e(k.metaKey),
          keyset: b64e(keyset),
        },
        new_recovery: { auth_key: b64e(nr.authKey), meta_key: b64e(nr.metaKey), keyset: b64e(recKeyset) },
      });
      clearAll(r.authKey, r.metaKey, k.authKey, k.metaKey, nr.authKey, nr.metaKey);
      if (st === 401) throw new UserError("Неверный логин или код восстановления.");
      if (st !== 204) throw new UserError("Не удалось сменить пароль.");
      const acc = await api("GET", "/api/v1/account");
      if (acc.status !== 200) throw new UserError("Пароль изменён, но войти не удалось. Войдите заново.");
      await signedIn(acc.data, k.wrapKey);
      for (const f of ["rec-code", "rec-password", "rec-password2"]) $(f).value = "";
      showCode(nextCode, showAccount, false);
    });
  }

  function initCode() {
    $("code-saved").addEventListener("change", (e) => ($("code-done").disabled = !e.target.checked));
    $("code-copy").addEventListener("click", () => copyText(state.codeText, $("code-copy"), $("code-value")));
    $("code-save").addEventListener("click", saveCode);
    $("code-done").addEventListener("click", async () => {
      $("code-value").replaceChildren();
      state.codeText = "";
      const then = state.afterCode;
      state.afterCode = null;
      try {
        if (then) await then();
      } catch (ex) {
        showError(ex);
      }
    });
  }

  function initAccount() {
    $("acc-logout").addEventListener("click", async () => {
      try {
        await api("POST", "/api/v1/auth/logout");
      } finally {
        signedOut();
      }
    });

    $("acc-invite").addEventListener("click", async () => {
      try {
        const { status: st, data } = await api("POST", "/api/v1/invites");
        if (st !== 201 || !data || !B64_32_RE.test(data.code)) throw new UserError("Не удалось создать приглашение.");
        // The code goes in the fragment: it is never sent to the server in a URL.
        $("acc-invite-link").value = `${location.origin}/#invite=${data.code}`;
        $("acc-invite-exp").textContent =
          `Одноразовое. Действует до ${new Date(data.expires_at * 1000).toLocaleString("ru-RU")}. Отправьте по надёжному каналу.`;
        $("acc-invite-out").hidden = false;
        $("acc-invite-link").select();
      } catch (ex) {
        showError(ex);
      }
    });
    $("acc-invite-copy").addEventListener("click", () =>
      copyText($("acc-invite-link").value, $("acc-invite-copy"), $("acc-invite-link")),
    );

    $("pw-generate").addEventListener("click", () => fillGenerated($("pw-new"), $("pw-new2")));

    action($("password-form"), async () => {
      const a = state.account;
      const password = await readNewPassword($("pw-new"), $("pw-new2"), a.login);
      const { salt, iterations } = await prelogin(a.login);
      const cur = await passwordKeys($("pw-current").value, salt, iterations);
      let plain;
      try {
        plain = await readKeysetPlain(cur.wrapKey, a.keyset);
      } catch {
        throw new UserError("Неверный текущий пароль.");
      }
      const newSalt = random(32);
      const k = await passwordKeys(password, newSalt, ITER_DEFAULT);
      const keyset = await encrypt(k.wrapKey, plain, KEYSET_AAD);
      plain.fill(0);
      const { status: st } = await api("POST", "/api/v1/account/password", {
        current_auth_key: b64e(cur.authKey),
        credentials: {
          salt: b64e(newSalt),
          iterations: ITER_DEFAULT,
          auth_key: b64e(k.authKey),
          meta_key: b64e(k.metaKey),
          keyset: b64e(keyset),
        },
      });
      clearAll(cur.authKey, cur.metaKey, k.authKey, k.metaKey);
      if (st === 401) throw new UserError("Неверный текущий пароль.");
      if (st !== 204) throw new UserError("Не удалось сменить пароль.");
      const acc = await api("GET", "/api/v1/account");
      if (acc.status !== 200) return signedOut();
      await signedIn(acc.data, k.wrapKey);
      $("password-form").reset();
      $("password-form").closest("details").open = false;
      updateMeter($("pw-new"));
      await showAccount();
      status("Пароль изменён. Остальные сессии завершены.");
    });

    action($("delete-form"), async () => {
      const a = state.account;
      const { salt, iterations } = await prelogin(a.login);
      const k = await passwordKeys($("del-password").value, salt, iterations);
      const { status: st } = await api("POST", "/api/v1/account/delete", { auth_key: b64e(k.authKey) });
      clearAll(k.authKey, k.metaKey);
      if (st === 401) throw new UserError("Неверный пароль.");
      if (st !== 204) throw new UserError("Не удалось удалить аккаунт.");
      signedOut();
      status("Аккаунт удалён.");
    });
  }

  async function boot() {
    for (const b of document.querySelectorAll("[data-go]")) {
      b.addEventListener("click", () => (b.dataset.go === "register" ? enterRegister() : show(b.dataset.go)));
    }
    initMeters();
    initLogin();
    initRegister();
    initRecover();
    initCode();
    initAccount();

    // An invite link carries the code in the fragment; take it and wipe the URL.
    const m = /^#invite=([A-Za-z0-9_-]{43})$/.exec(location.hash);
    history.replaceState(null, "", location.pathname);
    if (m) {
      $("reg-invite").value = m[1];
      $("reg-invite-field").hidden = true;
      $("reg-invite-note").hidden = false;
      enterRegister();
      return;
    }

    try {
      const { status: st, data } = await api("GET", "/api/v1/account");
      if (st === 200) {
        await signedIn(data, null);
        await showAccount();
        return;
      }
    } catch {
      /* fall through to login */
    }
    show("login");
  }

  if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
    document.addEventListener("DOMContentLoaded", () => {
      const el = $("error");
      el.textContent = "Браузер не поддерживает безопасное шифрование (нужен HTTPS и современный браузер).";
      el.hidden = false;
    });
    return;
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
