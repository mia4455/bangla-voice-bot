// এই ফাইলের প্রথম অংশ: Edge TTS-এর Sec-MS-GEC v2 টোকেন অ্যালগরিদম (Microsoft-এর সুরক্ষা টোকেন তৈরির জন্য)
const M = 0xFFFFFFFFn;
const SHA256_INITIAL = [0x6A09E667n, 0xBB67AE85n, 0x3C6EF372n, 0xA54FF53An, 0x510E527Fn, 0x9B05688Cn, 0x1F83D9ABn, 0x5BE0CD19n];
const SHA256_STATE = [0xFD9FBEA2n, 0x91243CE7n, 0xBE499094n, 0xCD2E1E0An, 0x6C006F49n, 0x4BD35ABn, 0xFEB0A7E4n, 0x3EFFBD2n];
const SHA256_SCHEDULE = [0xEB24BF9En, 0x1558691Fn, 0xA0C09EE2n, 0xCFA32BAn, 0xA622EE8Cn, 0xD1DD9491n, 0xC0DD25A0n, 0xF9E70AB6n, 0xF0C31573n, 0x7058CE4En, 0x7188E606n, 0xE5AB33n, 0xD258B060n, 0x72766564n];
const ROUND = [0x428A2F98n, 0x71374491n, 0xB5C0FBCFn, 0xE9B5DBA5n, 0x3956C25Bn, 0x59F111F1n, 0x923F82A4n, 0xAB1C5ED5n, 0xD807AA98n, 0x12835B01n, 0x243185BEn, 0x550C7DC3n, 0x72BE5D74n, 0x80DEB1FEn, 0x9BDC06A7n, 0xC19BF174n, 0xE49B69C1n, 0xEFBE4786n, 0xFC19DC6n, 0x240CA1CCn, 0x2DE92C6Fn, 0x4A7484AAn, 0x5CB0A9DCn, 0x76F988DAn, 0x983E5152n, 0xA831C66Dn, 0xB00327C8n, 0xBF597FC7n, 0xC6E00BF3n, 0xD5A79147n, 0x6CA6351n, 0x14292967n, 0x27B70A85n, 0x2E1B2138n, 0x4D2C6DFCn, 0x53380D13n, 0x650A7354n, 0x766A0ABBn, 0x81C2C92En, 0x92722C85n, 0xA2BFE8A1n, 0xA81A664Bn, 0xC24B8B70n, 0xC76C51A3n, 0xD192E819n, 0xD6990624n, 0xF40E3585n, 0x106AA070n, 0x19A4C116n, 0x1E376C08n, 0x2748774Cn, 0x34B0BCB5n, 0x391C0CB3n, 0x4ED8AA4An, 0x5B9CCA4Fn, 0x682E6FF3n, 0x748F82EEn, 0x78A5636Fn, 0x84C87814n, 0x8CC70208n, 0x90BEFFFAn, 0xA4506CEBn, 0xBEF9A3F7n, 0xC67178F2n];
const BLOCK_CONSTANTS = [...ROUND.slice(0,14), 0xC9DC06A7n, ...ROUND.slice(15)];
const CS64_COEF = [[0xE82E91B1n, 0xB32700D0n], [0x44DE24C6n, 0x88DFF51Dn], [0x3BEB65BCn, 0x29514038n], [0xC89C5933n, 0xB328CBDFn], [0x8D1EC211n, 0xD405B4D5n], [0x314EF5D5n, 0x26E55F3Cn], [0xE92491B1n, 0x607801C6n], [0xF0A5B9D5n, 0x82B2C1FBn], [0x6064CF3n, 0xFA51A3DAn], [0xDA79FA60n, 0x207CC464n], [0xBED20560n, 0x3C3C74F3n], [0x89F9C9F8n, 0xD2D14B61n], [0x35FA38C6n, 0xBB04A2C1n], [0xCB49E3C6n, 0xC5626167n]];

const rol16 = v => { v &= M; return ((v << 16n) | (v >> 16n)) & M; };
const sigma0 = v => ((v >> 7n) ^ (v << 25n) ^ (v >> 18n) ^ (v << 14n) ^ (v >> 3n)) & M;
const sigma1 = v => ((v >> 17n) ^ (v << 15n) ^ (v >> 19n) ^ (v << 13n) ^ (v >> 10n)) & M;

function rounds(state, words, firstRound = 0) {
  let [a,b,c,d,e,f,g,h] = state;
  const constants = firstRound === 14 ? BLOCK_CONSTANTS : ROUND;
  const aligned = Math.min(64, Math.floor((firstRound + 7) / 8) * 8);
  for (let i = firstRound; i < aligned; i++) {
    const rotE = e * 0x100000001n, rotA = a * 0x100000001n;
    const t1 = h + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (g ^ (e & (f ^ g))) + constants[i] + words[i];
    const t2 = ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((a & b) | (c & (a | b)));
    [a,b,c,d,e,f,g,h] = [(t1+t2)&M, a, b, c, (d+t1)&M, e, f, g];
  }
  for (let i = aligned; i < 64; i += 8) {
    let rotE, rotA, t1;
    rotE = e * 0x100000001n; rotA = a * 0x100000001n;
    t1 = h + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (g ^ (e & (f ^ g))) + constants[i] + words[i];
    d = (d + t1) & M;
    h = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((a & b) | (c & (a | b)))) & M;
    rotE = d * 0x100000001n; rotA = h * 0x100000001n;
    t1 = g + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (f ^ (d & (e ^ f))) + constants[i+1] + words[i+1];
    c = (c + t1) & M;
    g = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((h & a) | (b & (h | a)))) & M;
    rotE = c * 0x100000001n; rotA = g * 0x100000001n;
    t1 = f + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (e ^ (c & (d ^ e))) + constants[i+2] + words[i+2];
    b = (b + t1) & M;
    f = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((g & h) | (a & (g | h)))) & M;
    rotE = b * 0x100000001n; rotA = f * 0x100000001n;
    t1 = e + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (d ^ (b & (c ^ d))) + constants[i+3] + words[i+3];
    a = (a + t1) & M;
    e = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((f & g) | (h & (f | g)))) & M;
    rotE = a * 0x100000001n; rotA = e * 0x100000001n;
    t1 = d + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (c ^ (a & (b ^ c))) + constants[i+4] + words[i+4];
    h = (h + t1) & M;
    d = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((e & f) | (g & (e | f)))) & M;
    rotE = h * 0x100000001n; rotA = d * 0x100000001n;
    t1 = c + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (b ^ (h & (a ^ b))) + constants[i+5] + words[i+5];
    g = (g + t1) & M;
    c = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((d & e) | (f & (d | e)))) & M;
    rotE = g * 0x100000001n; rotA = c * 0x100000001n;
    t1 = b + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (a ^ (g & (h ^ a))) + constants[i+6] + words[i+6];
    f = (f + t1) & M;
    b = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((c & d) | (e & (c | d)))) & M;
    rotE = f * 0x100000001n; rotA = b * 0x100000001n;
    t1 = a + ((rotE >> 6n) ^ (rotE >> 11n) ^ (rotE >> 25n)) + (h ^ (f & (g ^ h))) + constants[i+7] + words[i+7];
    e = (e + t1) & M;
    a = (t1 + ((rotA >> 2n) ^ (rotA >> 13n) ^ (rotA >> 22n)) + ((b & c) | (d & (b | c)))) & M;
  }
  return [a,b,c,d,e,f,g,h];
}
function expand(words, firstWord = 16) {
  for (let i = firstWord; i < 64; i++) {
    const x = words[i-2], y = words[i-15];
    words.push((sigma1(x) + words[i-7] + sigma0(y) + words[i-16]) & M);
  }
}
const be32 = (bytes, off) => (BigInt(bytes[off])<<24n)|(BigInt(bytes[off+1])<<16n)|(BigInt(bytes[off+2])<<8n)|BigInt(bytes[off+3]);
const le32 = (bytes, off) => BigInt(bytes[off])|(BigInt(bytes[off+1])<<8n)|(BigInt(bytes[off+2])<<16n)|(BigInt(bytes[off+3])<<24n);

function sha256Init(data) {
  const words = new Array(14).fill(0n);
  words.push(be32(data,0) & 0xFFFFFFn << 8n | 0n); // placeholder replaced below
  words.pop();
  words.push(BigInt((data[0]<<16)|(data[1]<<8)|data[2]));
  words.push(be32(data,3));
  for (let i = 16; i < 30; i++) {
    let value = SHA256_SCHEDULE[i-16];
    if (i-2 >= 14) value += (i === 16) ? (sigma1(words[i-2]) ^ 0x000B92C0n) : sigma1(words[i-2]);
    if (i-7 >= 14) value += words[i-7];
    if (i-15 >= 14) value += (i === 29) ? (sigma0(words[i-15]) ^ 0x059C0B80n) : sigma0(words[i-15]);
    words.push(value & M);
  }
  words.push((sigma1(words[28]) + words[23] + sigma0(words[15]) + words[14] + 0xC9DC06A7n - ROUND[14]) & M);
  expand(words, 31);
  const working = rounds(SHA256_STATE, words, 14);
  return SHA256_INITIAL.map((x,i) => (x + working[i]) & M);
}
function sha256Digest(data) {
  const length = 57 + data.length;
  let padded = [...data.subarray(7), 0x80];
  const zeros = ((55 - length) % 64 + 64) % 64;
  padded.push(...new Array(zeros).fill(0));
  const bits = BigInt(length * 8);
  for (let s = 56n; s >= 0n; s -= 8n) padded.push(Number((bits >> s) & 0xFFn));
  padded = new Uint8Array(padded);
  let state = sha256Init(data.subarray(0,7));
  for (let off = 0; off < padded.length; off += 64) {
    const words = [];
    for (let i = 0; i < 16; i++) words.push(be32(padded, off + i*4));
    expand(words);
    const working = rounds(state, words);
    state = state.map((x,i) => (x + working[i]) & M);
  }
  const out = new Uint8Array(32);
  state.forEach((w,i) => { out[i*4]=Number((w>>24n)&0xFFn); out[i*4+1]=Number((w>>16n)&0xFFn); out[i*4+2]=Number((w>>8n)&0xFFn); out[i*4+3]=Number(w&0xFFn); });
  return out;
}
function cs64Digest(data, digest) {
  let keyA = le32(digest,0) | 1n, keyB = le32(digest,4) | 1n;
  const factors = [(keyA * 0x82893933n) & M, (keyB * 0x82893933n) & M];
  const terms = CS64_COEF.map(([coef], i) => (coef * factors[i % 2]) & M);
  const offsets = CS64_COEF.map(([,off]) => off);
  const withZero = new Uint8Array(data.length + 1); withZero.set(data, 1);
  const padLen = withZero.length + ((4 - (withZero.length % 4)) % 4);
  const words = [];
  for (let off = 0; off < padLen; off += 4) words.push(le32(new Uint8Array([...withZero,0,0,0]), off));
  if (words.length % 2) words.push(0n);
  words.forEach((word, index) => {
    let term = word * (index % 2 === 0 ? keyA : keyB);
    let offset = rol16(word) * (index % 2 === 0 ? 0xEF0569FBn : 0xC31713DBn);
    if (index === 0) { term += 0xF2F90B1An * factors[0]; offset += 0x0B1A0000n; }
    terms.push(term & M); offsets.push(offset & M);
  });
  let swapAcc = 0n, swapLast = 0n, state = 0n, acc = 0n;
  for (let i = 0; i < terms.length; i += 2) {
    const x = terms[i], y = terms[i+1];
    let t = rol16((offsets[i] + x) & M);
    let q = (t * 0x76F50F34n) & M;
    swapAcc += (rol16(q) * 0xC3EFEA97n + q) & M;
    t = rol16((offsets[i+1] + y) & M);
    q = (t * 0x1881CE3Cn) & M;
    swapLast = (rol16(q) * 0x35BD1EC9n + q) & M;
    swapAcc = (swapAcc + swapLast) & M;
    state = (state * keyA + x) & M;
    state = (rol16(state) * 0xCF98B111n) & M;
    state = (rol16(state) * 0x87085B9Fn) & M;
    state = (rol16(state) * 0x12CEB96Dn) & M;
    state = (rol16(state) * 0x257E1D83n) & M;
    acc += state;
    t = (state * keyB + y) & M;
    t = (rol16(t) * 0xA27416F5n) & M;
    t = (rol16(t) * 0xD38396FFn) & M;
    state = (rol16((rol16(t) * 0x7C932B89n) & M) * 0xBFA49F69n) & M;
    acc = (acc + state) & M;
  }
  return [swapLast ^ state, swapAcc ^ acc];
}
function generateSecMsGecV2(unixSeconds) {
  let ticks = BigInt(Math.floor(unixSeconds)) + 11644473600n;
  ticks -= ticks % 300n;
  ticks *= 10000000n;
  const data = new TextEncoder().encode(`${ticks.toString()}6A5AA1D4EAFF4E9FB37E23D68491D6F4`);
  const digest = sha256Digest(data);
  const [a,b] = cs64Digest(data, digest);
  const csBytes = new Uint8Array(8);
  [a,b].forEach((w,i)=>{ csBytes[i*4]=Number(w&0xFFn); csBytes[i*4+1]=Number((w>>8n)&0xFFn); csBytes[i*4+2]=Number((w>>16n)&0xFFn); csBytes[i*4+3]=Number((w>>24n)&0xFFn); });
  const hex = arr => [...arr].map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
  return `${hex(csBytes)}-${hex(digest)}`;
}

// =====================================================================
// 🎙️ Telegram বাংলা ভয়েস বট — Cloudflare Workers সংস্করণ
// ---------------------------------------------------------------------
// Secrets (কোডে নয়!): Dashboard → Settings → Variables and Secrets
//   BOT_TOKEN       (Secret) — @BotFather থেকে
//   WEBHOOK_SECRET  (Secret) — যেকোনো এলোমেলো লেখা (নিজে বানান)
// Bindings:
//   PREFS (KV Namespace) — ইউজারের ভয়েস-পছন্দ মনে রাখতে
// =====================================================================

const VOICES = {
  female: { label: "👩 Female (Shabana)", bn: "bn-BD-NabanitaNeural", en: "en-US-AriaNeural" },
  male:   { label: "👨 Male (Arif)",      bn: "bn-BD-PradeepNeural",  en: "en-US-GuyNeural" },
};
const VOICE_RATE = "+0%";   // 🔊 স্বাভাবিক গতি (ফিক্সড)
const VOICE_PITCH = "+0Hz"; // স্বাভাবিক পিচ (ফিক্সড)
const MAX_TEXT = 1000;

const tg = (env, method) => `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`;

async function tgCall(env, method, payload) {
  const r = await fetch(tg(env, method), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return r.json();
}

function detectLang(text) {
  for (const ch of text) if (ch >= "\u0980" && ch <= "\u09FF") return "bn";
  return "en";
}

function voiceKeyboard(current) {
  const rows = Object.entries(VOICES).map(([key, v]) => [{
    text: (key === current ? "✅ " : "") + v.label,
    callback_data: "voice:" + key,
  }]);
  rows.push([{ text: "🎙️ আমার নিজের ভয়েস (এই হোস্টিংয়ে নেই)", callback_data: "voice:my" }]);
  return { inline_keyboard: rows };
}

async function getVoice(env, userId) {
  try { return (await env.PREFS.get("voice:" + userId)) || "female"; } catch { return "female"; }
}
async function setVoice(env, userId, key) {
  try { await env.PREFS.put("voice:" + userId, key); } catch {}
}

// ---------------- Edge TTS (Microsoft-এর বাংলা ভয়েস) ----------------
const EDGE_TOKEN = "6A5AA1D4EAFF4E9FB37E23D68491D6F4";
const xmlEscape = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&apos;");

async function edgeTTS(text, voiceName, lang) {
  const gec = generateSecMsGecV2(Date.now() / 1000);
  const connId = crypto.randomUUID().replaceAll("-", "");
  const url = `https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=${EDGE_TOKEN}&Sec-MS-GEC=${gec}&Sec-MS-GEC-Version=2-143.0.3650.75&ConnectionId=${connId}`;
  const resp = await fetch(url, {
    headers: {
      "Upgrade": "websocket",
      "Pragma": "no-cache", "Cache-Control": "no-cache",
      "Origin": "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold",
      "Accept-Language": "en-US,en;q=0.9",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
      "Cookie": `muid=${crypto.randomUUID().replaceAll("-","").toUpperCase()};`,
    },
  });
  const ws = resp.webSocket;
  if (!ws) throw new Error("Edge TTS WebSocket খোলা যায়নি (status " + resp.status + ")");
  ws.accept();

  const audioChunks = [];
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Edge TTS timeout")), 30000);
    ws.addEventListener("message", async (event) => {
      let data = event.data;
      if (data instanceof Blob) data = await data.arrayBuffer();
      if (typeof data === "string") {
        if (data.includes("Path:turn.end")) { clearTimeout(timer); try{ws.close();}catch{} resolve(); }
        return;
      }
      const buf = new Uint8Array(data);
      const headerLen = new DataView(buf.buffer, buf.byteOffset).getUint16(0);
      const header = new TextDecoder().decode(buf.subarray(2, 2 + headerLen));
      if (header.includes("Path:audio")) audioChunks.push(buf.subarray(2 + headerLen));
    });
    ws.addEventListener("error", () => { clearTimeout(timer); reject(new Error("Edge TTS সংযোগে সমস্যা")); });
  });

  const ts = () => new Date().toISOString();
  ws.send(`X-Timestamp:${ts()}\r\nContent-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n{"context":{"synthesis":{"audio":{"metadataoptions":{"sentenceBoundaryEnabled":"false","wordBoundaryEnabled":"false"},"outputFormat":"audio-24khz-48kbitrate-mono-mp3"}}}}`);
  const reqId = crypto.randomUUID().replaceAll("-", "");
  const ssml = `<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='${lang === "bn" ? "bn-BD" : "en-US"}'><voice name='${voiceName}'><prosody pitch='${VOICE_PITCH}' rate='${VOICE_RATE}'>${xmlEscape(text)}</prosody></voice></speak>`;
  ws.send(`X-RequestId:${reqId}\r\nContent-Type:application/ssml+xml\r\nX-Timestamp:${ts()}\r\nPath:ssml\r\n\r\n${ssml}`);

  await done;
  const total = audioChunks.reduce((n, c) => n + c.length, 0);
  if (!total) throw new Error("Edge TTS কোনো অডিও পাঠায়নি");
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of audioChunks) { out.set(c, off); off += c.length; }
  return out;
}

// ব্যাকআপ: Edge ব্যর্থ হলে Google বাংলা TTS (কোয়ালিটি কম, কিন্তু বট থামবে না)
async function googleTTS(text) {
  const parts = [];
  const chunks = text.match(/[^।.!?]+[।.!?]?/g) || [text];
  let buf = "";
  const queue = [];
  for (const c of chunks) { if ((buf + c).length > 180) { queue.push(buf); buf = c; } else buf += c; }
  if (buf) queue.push(buf);
  for (const q of queue.slice(0, 6)) {
    const r = await fetch(`https://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob&tl=bn&q=${encodeURIComponent(q)}`,
      { headers: { "User-Agent": "Mozilla/5.0" } });
    if (r.ok) parts.push(new Uint8Array(await r.arrayBuffer()));
  }
  const total = parts.reduce((n, c) => n + c.length, 0);
  if (!total) throw new Error("কোনো TTS-ই কাজ করেনি");
  const out = new Uint8Array(total); let off = 0;
  for (const c of parts) { out.set(c, off); off += c.length; }
  return out;
}

async function speak(text, voiceKey) {
  const lang = detectLang(text);
  const voice = VOICES[voiceKey][lang];
  try { return await edgeTTS(text, voice, lang); }
  catch (e) { return await googleTTS(text); }
}

// ---------------- Telegram আপডেট প্রসেসিং ----------------
async function processUpdate(env, update) {
  // বাটনে ক্লিক
  if (update.callback_query) {
    const q = update.callback_query;
    const key = (q.data || "").split(":")[1];
    if (key === "my") {
      await tgCall(env, "answerCallbackQuery", {
        callback_query_id: q.id,
        text: "🎙️ নিজের ভয়েস অপশনটা এই ফ্রি হোস্টিংয়ে চলবে না (ভারী AI মডেল লাগে)। Female/Male ভয়েস ব্যবহার করুন।",
        show_alert: true,
      });
      return;
    }
    if (VOICES[key]) {
      await setVoice(env, q.from.id, key);
      await tgCall(env, "answerCallbackQuery", { callback_query_id: q.id, text: "✅ " + VOICES[key].label });
      await tgCall(env, "editMessageText", {
        chat_id: q.message.chat.id, message_id: q.message.message_id,
        text: `✅ ভয়েস সিলেক্ট হয়েছে: *${VOICES[key].label}*\n\nএবার যেকোনো টেক্সট লিখে পাঠান — এই গলায় অডিও আসবে! 🎧`,
        parse_mode: "Markdown", reply_markup: voiceKeyboard(key),
      });
    }
    return;
  }

  const msg = update.message;
  if (!msg) return;
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const text = (msg.text || "").trim();

  if (text === "/start" || text === "/help" || text === "/voice") {
    const current = await getVoice(env, userId);
    await tgCall(env, "sendMessage", {
      chat_id: chatId, parse_mode: "Markdown",
      text: "🎙️ *বাংলা ভয়েস বটে স্বাগতম!*\n\nআমাকে যেকোনো *বাংলা (বা English) টেক্সট* লিখে পাঠান — আমি পরিষ্কার উচ্চারণে পড়ে শোনাবো। 🔊\n\nপ্রথমে নিচের বাটনে ভয়েস বেছে নিন:",
      reply_markup: voiceKeyboard(current),
    });
    return;
  }
  if (text === "/myid") {
    await tgCall(env, "sendMessage", { chat_id: chatId, text: `🆔 আপনার Telegram ID: ${userId}` });
    return;
  }
  if (!text || text.startsWith("/")) return;
  if (text.length > MAX_TEXT) {
    await tgCall(env, "sendMessage", { chat_id: chatId, text: `⚠️ একবারে সর্বোচ্চ ${MAX_TEXT} অক্ষর পাঠান। লেখাটা ভাগ করে পাঠান।` });
    return;
  }

  const voiceKey = await getVoice(env, userId);
  await tgCall(env, "sendChatAction", { chat_id: chatId, action: "record_voice" });
  try {
    const audio = await speak(text, voiceKey);
    const form = new FormData();
    form.append("chat_id", String(chatId));
    form.append("caption", `${VOICES[voiceKey].label} • ${detectLang(text) === "bn" ? "বাংলা" : "English"}`);
    form.append("voice", new Blob([audio], { type: "audio/mpeg" }), "voice.mp3");
    const r = await fetch(tg(env, "sendVoice"), { method: "POST", body: form });
    if (!r.ok) throw new Error("Telegram sendVoice ব্যর্থ: " + (await r.text()));
  } catch (e) {
    await tgCall(env, "sendMessage", { chat_id: chatId, text: "❌ অডিও বানাতে সমস্যা হয়েছে। একটু পরে আবার চেষ্টা করুন।" });
  }
}

// ---------------- Worker এন্ট্রি ----------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response("✅ বাংলা ভয়েস বট চলছে! Telegram-এ গিয়ে বটকে মেসেজ দিন।");
    }

    // একবার ভিজিট করলেই Telegram-এর সাথে Webhook যুক্ত হয়ে যাবে
    if (url.pathname === "/registerWebhook") {
      const payload = { url: url.origin + "/webhook", allowed_updates: ["message", "callback_query"] };
      if (env.WEBHOOK_SECRET) payload.secret_token = env.WEBHOOK_SECRET;
      const result = await tgCall(env, "setWebhook", payload);
      return Response.json(result);
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      if (env.WEBHOOK_SECRET) {
        if (request.headers.get("x-telegram-bot-api-secret-token") !== env.WEBHOOK_SECRET)
          return new Response("Unauthorized", { status: 401 });
      }
      const update = await request.json();
      ctx.waitUntil(processUpdate(env, update));
      return new Response("OK");
    }

    return new Response("Not found", { status: 404 });
  },
};
