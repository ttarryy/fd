import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { setImmediate } from "node:timers/promises";
import { bridgePage } from "../src/bridge.js";
import { FRAME, MAX_WS_MESSAGE, encodeFrame } from "../src/protocol.js";

function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
async function flush() { for (let i = 0; i < 5; i++) await setImmediate(); }
async function fixture(t, { native = true, nonce = "n".repeat(43) } = {}) {
  const response = bridgePage("proxy.example.com", "synthetic-bootstrap");
  const html = await response.text(), code = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
  const outbound = [], calls = [], sockets = [], listeners = new Map(), timers = new Map(), bootstrap = deferred();
  let timerId = 0;
  class Socket {
    static OPEN = 1;
    constructor(url, protocol) { this.url = url; this.protocol = protocol; this.readyState = 0; this.bufferedAmount = 0; this.sent = []; this.closed = false; sockets.push(this); }
    send(data) { this.sent.push(data); this.bufferedAmount += data.byteLength; }
    close() { this.closed = true; this.readyState = 3; }
    open() { this.readyState = 1; this.onopen(); }
  }
  const android = { onmessage: null, postMessage(value) { outbound.push(value); } }, history = [];
  const parent = {}, context = { ArrayBuffer, Uint8Array, DataView, URL, URLSearchParams, AbortController,
    location: { hash: "#android=" + nonce }, history: { replaceState(...args) { history.push(args); } },
    parent, WebSocket: Socket,
    addEventListener(type, fn) { listeners.set(type, fn); },
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) { calls.push({ url, options }); return options.method === "DELETE" ? Promise.resolve({}) : bootstrap.promise; },
  };
  if (native) context.TelegramWebProxy = android;
  vm.runInNewContext(code, context);
  t.after(() => listeners.get("pagehide")());
  const handler = android.onmessage;
  return { response, html, context, outbound, calls, sockets, timers, bootstrap, android, listeners, history,
    send(bytes) { handler({ data: bytes instanceof Uint8Array ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) : bytes }); },
    respond(welcome = encodeFrame(FRAME.WELCOME, 0)) { bootstrap.resolve({ ok: true, headers: new Headers({ "X-Carrier-Mode": "websocket", "X-Session-Token": "A".repeat(43) }), async arrayBuffer() { return welcome.buffer; } }); },
  };
}
const hello = () => encodeFrame(FRAME.HELLO, 0, new Uint8Array([1]));
function statuses(f) { return f.outbound.filter(v => typeof v === "string").map(v => JSON.parse(v)).filter(v => v.t === "status").map(v => v.state); }

test("bridge uses a fresh CSP nonce and exact-origin HTTPS/WSS", async t => {
  const f = await fixture(t), csp = f.response.headers.get("Content-Security-Policy");
  const nonce = f.html.match(/<script nonce="([^"]+)">/)[1];
  assert.ok(csp.includes("script-src 'nonce-" + nonce + "'"));
  assert.ok(csp.includes("connect-src https://proxy.example.com wss://proxy.example.com"));
  assert.ok(csp.includes("sandbox allow-same-origin allow-scripts"));
  assert.ok(!csp.includes("unsafe-inline"));
  assert.notEqual(nonce, (await bridgePage("proxy.example.com", "test").text()).match(/<script nonce="([^"]+)">/)[1]);
  assert.deepEqual(f.history[0], [null, "", "/"]);
  assert.equal(JSON.parse(f.outbound.at(-1)).nonce, "n".repeat(43));
});
test("Android HELLO creates a hardened session and flushes queued frames in order", async t => {
  const f = await fixture(t); f.send(hello());
  const a = encodeFrame(FRAME.OPEN, 1), b = encodeFrame(FRAME.OPEN, 2); f.send(a); f.send(b);
  const options = f.calls[0].options;
  assert.equal(options.mode, "same-origin"); assert.equal(options.redirect, "error");
  assert.equal(options.credentials, "omit"); assert.equal(options.cache, "no-store"); assert.equal(options.referrerPolicy, "no-referrer");
  f.respond(); await flush(); assert.equal(f.sockets.length, 1);
  const socket = f.sockets[0]; assert.equal(socket.url, "wss://proxy.example.com/api/v1/ws");
  socket.open(); assert.deepEqual(socket.sent.map(v => [...new Uint8Array(v)]), [[...a], [...b]]);
  assert.equal(f.timers.size, 0); assert.ok(statuses(f).includes("connected"));
});
test("close during bootstrap cannot resurrect a WebSocket", async t => {
  const f = await fixture(t); f.send(hello()); f.send({ t: "close" });
  assert.equal(f.calls[0].options.signal.aborted, true);
  f.respond(); await flush(); assert.equal(f.sockets.length, 0); assert.equal(f.timers.size, 0);
});
test("bridge bootstrap/WebSocket deadline closes a stalled carrier", async t => {
  const f = await fixture(t); f.send(hello());
  const timer = [...f.timers.values()][0]; assert.equal(timer.ms, 15000); timer.fn();
  assert.ok(statuses(f).includes("failed")); assert.equal(f.calls[0].options.signal.aborted, true);
  f.respond(); await flush(); assert.equal(f.sockets.length, 0);
});
test("bridge pending queue enforces both byte and item limits", async t => {
  for (const size of [1, 1024 * 1024]) {
    const f = await fixture(t); f.send(hello());
    const frame = encodeFrame(FRAME.DATA, 1, new Uint8Array(size));
    for (let i = 0; i < (size === 1 ? 1025 : 2); i++) f.send(frame);
    assert.ok(statuses(f).includes("failed")); assert.equal(f.calls[0].options.signal.aborted, true);
  }
});
test("bridge rejects oversize messages and invalid WELCOME", async t => {
  const large = await fixture(t); large.send(new ArrayBuffer(MAX_WS_MESSAGE + 1));
  assert.ok(statuses(large).includes("failed")); assert.equal(large.calls.length, 0);
  const bad = await fixture(t); bad.send(hello()); bad.respond(encodeFrame(FRAME.CLOSE, 1)); await flush();
  assert.ok(statuses(bad).includes("failed")); assert.equal(bad.sockets.length, 0);
});
test("bridge counts the next write against WebSocket bufferedAmount", async t => {
  const f = await fixture(t); f.send(hello()); f.respond(); await flush(); const socket = f.sockets[0]; socket.open();
  socket.bufferedAmount = MAX_WS_MESSAGE - 7; f.send(encodeFrame(FRAME.OPEN, 1));
  assert.equal(socket.sent.length, 0); assert.equal(socket.closed, true); assert.ok(statuses(f).includes("failed"));
});
test("downlink batches are delivered to Android as complete individual frames", async t => {
  const f = await fixture(t); f.send(hello()); f.respond(); await flush(); const socket = f.sockets[0]; socket.open();
  const a = encodeFrame(FRAME.DATA, 1, new Uint8Array([1])), b = encodeFrame(FRAME.DATA, 2, new Uint8Array([2]));
  const joined = new Uint8Array(a.length + b.length); joined.set(a); joined.set(b, a.length);
  socket.onmessage({ data: joined.buffer });
  assert.deepEqual(f.outbound.filter(v => v instanceof ArrayBuffer).slice(-2).map(v => [...new Uint8Array(v)]), [[...a], [...b]]);
});
test("Android binding rejects invalid nonce and loopback binding accepts only its parent", async t => {
  const invalid = await fixture(t, { nonce: "bad" }); assert.equal(invalid.android.onmessage, null);
  const f = await fixture(t, { native: false }); const port = { postMessage() {}, close() {}, start() {} };
  const listener = f.listeners.get("message"), init = { data: { t: "tproxy-init", v: 1 }, ports: [port] };
  listener({ ...init, source: f.context.parent, origin: "https://evil.example" }); assert.equal(port.onmessage, undefined);
  listener({ ...init, source: {}, origin: "http://127.0.0.1:1234" }); assert.equal(port.onmessage, undefined);
  listener({ ...init, source: f.context.parent, origin: "http://127.0.0.1:1234" }); assert.equal(typeof port.onmessage, "function");
});
