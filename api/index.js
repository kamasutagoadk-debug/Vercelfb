// api/index.js

// No need to import fetch in modern Vercel environment — it's built-in
// import fetch from "node-fetch"; ❌ Not needed

export default async function handler(req, res) {
  try {
    const ip = getRealIp(req) || "8.8.8.8"; // Fallback IP to prevent crashes

    console.log("Resolved IP:", ip);

    const isBad = await isBot(ip);
    console.log(ip, " - ", "timestamp:", new Date(), ":: isBot: ", isBad);

    // Get ISP & Country Info
    const ipInfo = await fetch(`https://ipinfo.io/${ip}/json`)
      .then(r => r.json())
      .catch(() => ({}));
    const isp = ipInfo.org || "Unknown";
    const country = ipInfo.country || "Unknown";

    console.log(ip, " - isp:", isp, "- country:", country, "-- timestamp:", new Date(), ":: isBot: ", isBad);

    // Redirect
    return res.redirect(302, isBad ? "https://www.facebook.com" : "https://google.com");
  } catch (error) {
    console.error("Serverless Function Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

/* ------------------------------
   IP Utility Functions
------------------------------ */

function getRealIp(req) {
  const headerCandidates = [
    "x-client-ip",
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "true-client-ip",
    "x-forwarded",
    "x-cluster-client-ip",
    "forwarded-for",
    "forwarded",
  ];

  for (const h of headerCandidates) {
    const raw = req.headers[h];
    if (!raw) continue;
    const ip = extractIpFromHeader(raw);
    if (ip && !isPrivateIp(ip)) return ip;
  }

  const socketAddr = req.socket?.remoteAddress || req.connection?.remoteAddress || null;
  return normalizeSocketIp(socketAddr);
}

function extractIpFromHeader(raw) {
  if (!raw) return null;
  const first = raw.split(",").map(s => s.trim()).find(Boolean);
  if (!first) return null;
  let ip = first;

  ip = ip.replace(/^\[|\]$/g, "");

  const ipv4WithPort = ip.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/);
  if (ipv4WithPort) return ipv4WithPort[1];

  const maybePort = ip.match(/^(.+):(\d+)$/);
  if (maybePort) {
    const candidate = maybePort[1];
    if (candidate.includes(":")) ip = candidate;
  }

  if (/^::ffff:/i.test(ip)) ip = ip.replace(/^::ffff:/i, "");
  ip = ip.split("%")[0];

  return ip;
}

function normalizeSocketIp(addr) {
  if (!addr) return null;
  let ip = addr;
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  ip = ip.split("%")[0];
  return ip;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === "127.0.0.1" || ip === "::1") return true;

  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    if (/^10\./.test(ip)) return true;
    if (/^192\.168\./.test(ip)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
    if (/^169\.254\./.test(ip)) return true;
    return false;
  }

  if (/^(?:fc|fd)/i.test(ip)) return true;
  if (/^fe80:/i.test(ip)) return true;
  if (ip === "::") return true;

  return false;
}

/* ------------------------------
   Bot Detection Functions
------------------------------ */

async function isBot(ip) {
  const results = await Promise.all([
    proxy1(ip),
    proxy2(ip),
    proxy3(ip),
    proxy4(ip),
    proxy5(ip),
  ]);
  return results.includes("BLOCK");
}

async function proxy1(ip) {
  try {
    const res = await fetch(`https://blackbox.ipinfo.app/lookup/${ip}`);
    const text = await res.text();
    return text === "Y" ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}

async function proxy2(ip) {
  try {
    const res = await fetch(
      `http://check.getipintel.net/check.php?ip=${ip}&contact=test${Math.floor(
        Math.random() * 1000000
      )}@domain.com`
    );
    const text = await res.text();
    const num = parseFloat(text);
    return !isNaN(num) && num >= 0.99 ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}

async function proxy3(ip) {
  try {
    const res = await fetch(`https://ip.teoh.io/api/vpn/${ip}`);
    const json = await res.json();
    return json.risk === "high" ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}

async function proxy4(ip) {
  try {
    const res = await fetch(`http://proxycheck.io/v2/${ip}?risk=1&vpn=1`);
    const json = await res.json();
    return json.status === "ok" && json[ip]?.proxy === "yes" ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}

async function proxy5(ip) {
  try {
    const res = await fetch(`https://v2.api.iphub.info/guest/ip/${ip}?c=${Math.random()}`);
    const json = await res.json();
    return json.block === 1 ? "BLOCK" : "ALLOW";
  } catch {
    return "ALLOW";
  }
}
