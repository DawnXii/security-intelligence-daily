#!/usr/bin/env bash
# overflow-check.sh <url> — 通过 Moli CDP 检查页面元素横向越界（scrollWidth > clientWidth）
set -e
URL="$1"
PAGE_ID=$(curl -s http://127.0.0.1:9222/json/new | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
WS="ws://127.0.0.1:9222/devtools/page/$PAGE_ID"
python3 - "$URL" "$WS" <<'PY'
import json, sys, threading, time
try:
    from websocket import create_connection
except ImportError:
    sys.exit("NEED_WEBSOCKET_LIB")
url, ws_url = sys.argv[1], sys.argv[2]
ws = create_connection(ws_url, timeout=15)
idc = [0]
def send(method, params=None):
    idc[0] += 1
    ws.send(json.dumps({"id": idc[0], "method": method, "params": params or {}}))
    while True:
        msg = json.loads(ws.recv())
        if msg.get("id") == idc[0]:
            return msg.get("result", {})
send("Page.enable")
send("Page.navigate", {"url": url})
time.sleep(3)
send("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
time.sleep(1)
expr = """(() => {
  const docW = document.documentElement.clientWidth;
  const out = [];
  document.querySelectorAll('*').forEach(el => {
    const r = el.getBoundingClientRect();
    if (r.width === 0) return;
    if (r.right > docW + 1 || r.left < -1) {
      out.push(el.tagName + '.' + (el.className.toString().slice(0,40)) + ' L' + Math.round(r.left) + ' R' + Math.round(r.right));
    }
  });
  const wide = document.documentElement.scrollWidth;
  return JSON.stringify({docW, scrollWidth: wide, over: out.slice(0, 15), n: out.length});
})()"""
r = send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
print(r.get("result", {}).get("value", "EVAL_FAIL"))
ws.close()
PY
