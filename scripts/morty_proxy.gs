/**
 * Morty VPN — Apps Script proxy.
 *
 * Two endpoints:
 *   ?op=full         -> JSON with all server configs + cert + obfuscation
 *   ?op=wg_obfuskate  -> plain-text AmneziaWG obfuscation block
 *
 * Deploy:
 *   1. https://script.google.com -> New project
 *   2. Paste this file (Code.gs)
 *   3. Run `generateProxyKeypair()` once (it prints the values to insert
 *      in `HARDCODED_*` below). Do NOT regenerate — that would invalidate
 *      the shared cert on Proton's side for all users.
 *   4. Deploy -> New deployment -> Web app -> Execute as: Me, Who has
 *      access: Anyone. Copy the deployment URL.
 *   5. In the APK, set `ProtonConfigService.PROXY_BASE_URL` to that URL.
 *
 * Why this exists: the user's machine has access to Proton VPN (the
 * api.protonvpn.ch network); the APK may not (CDN/cert/DNS issues).
 * The script acts as a relay: it does the Proton API calls and ships the
 * results to the APK as plain JSON.
 *
 * Trade-off: all users hitting the same deployment share the same
 * Ed25519/X25519 keypair and the same Proton certificate. That's
 * acceptable for our use case (free anonymous VPN, no per-user billing).
 */

const API_HOST = "https://api.protonvpn.ch";
const API_PREFIX = "/api";
const CHALLENGE_FRAME_KEY = "vpn-android-v4-challenge-0";
const CERT_MODE = "persistent";
const DEVICE_NAME = "morty_vpn";
const WG_PORT = 51820;
const APP_VERSION = "android-vpn@5.0.0";
const APP_LOCALE = "en_US";
const USER_AGENT = "ProtonVPN/5.0.0 (Android 14; Pixel 7)";

/**
 * HARDCODED ED25519 PUBLIC KEY (SubjectPublicKeyInfo PEM, 32-byte pub).
 * Generated once with `generateProxyKeypair()` below. ALL users of this
 * script deployment share this key + the matching private key below.
 *
 * Generate your own with: `python generate_proxy_keypair.py` then paste
 * the printed values here and in HARDCODED_X25519_PRIV_B64.
 */
const HARDCODED_ED25519_PUB_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9By7qONVmPbA1EEZkfDL4LRWgc=\n-----END PUBLIC KEY-----\n";

/** X25519 private key (32 bytes, base64). From `generate_proxy_keypair.py`. */
const HARDCODED_X25519_PRIV_B64 = "GZb9ECWmEzf6FQbrBZ9By7qONVmPbA1EEZkfDL4LRWg=";

/** Plain-text AmneziaWG obfuscation block returned by ?op=wg_obfuskate. */
const OBFUSCATION_TEXT = [
  "MTU = 1280",
  "S1 = 0",
  "S2 = 0",
  "Jc = 4",
  "Jmin = 40",
  "Jmax = 70",
  "H1 = 1",
  "H2 = 2",
  "H3 = 3",
  "H4 = 4",
  "I1 = <b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>"
].join("\n");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildCommonHeaders_(uid, token) {
  const h = {
    "User-Agent": USER_AGENT,
    "Accept": "application/vnd.protonmail.v1+json",
    "Content-Type": "application/json",
    "x-pm-appversion": APP_VERSION,
    "x-pm-locale": APP_LOCALE,
  };
  if (uid) h["x-pm-uid"] = uid;
  if (token) h["Authorization"] = "Bearer " + token;
  return h;
}

function challengePayload_() {
  return {
    Payload: {
      [CHALLENGE_FRAME_KEY]: {
        v: "2.0.7",
        appLang: APP_LOCALE,
        timezone: "Europe/Berlin",
        deviceName: 1196226824,
        regionCode: "DE",
        timezoneOffset: 60,
        isJailbreak: false,
        preferredContentSize: "normal",
        storageCapacity: 128.0,
        isDarkmodeOn: false,
        keyboards: [
          "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME",
        ],
      },
    },
  };
}

function protonPost_(path, payload, uid, token) {
  const resp = UrlFetchApp.fetch(API_HOST + API_PREFIX + path, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    headers: buildCommonHeaders_(uid, token),
    muteHttpExceptions: true,
  });
  if (resp.getResponseCode() < 200 || resp.getResponseCode() >= 300) {
    throw new Error(
      "Proton " + path + " HTTP " + resp.getResponseCode() + " body=" +
        resp.getContentText().slice(0, 200)
    );
  }
  return JSON.parse(resp.getContentText());
}

function protonGet_(path, uid, token) {
  const resp = UrlFetchApp.fetch(
    API_HOST + API_PREFIX + path +
      "?SecureCoreFilter=all&WithState=true",
    {
      method: "get",
      headers: buildCommonHeaders_(uid, token),
      muteHttpExceptions: true,
    }
  );
  if (resp.getResponseCode() < 200 || resp.getResponseCode() >= 300) {
    throw new Error(
      "Proton " + path + " HTTP " + resp.getResponseCode() + " body=" +
        resp.getContentText().slice(0, 200)
    );
  }
  return JSON.parse(resp.getContentText());
}

function flagEmoji_(country) {
  if (country.length !== 2) return country;
  const A = "A".charCodeAt(0);
  return (
    String.fromCodePoint(0x1f1e6 + country.charCodeAt(0) - A) +
    String.fromCodePoint(0x1f1e6 + country.charCodeAt(1) - A)
  );
}

function pickBestPerCountry_(servers) {
  // Tier 0 = FREE, Status 1 = active, bit 0 of Features = SECURE_CORE.
  const filtered = servers.filter(function (s) {
    return (
      s.Tier === 0 &&
      s.Status === 1 &&
      (s.Features & 1) === 0 &&
      s.ExitCountry &&
      s.ExitCountry.length > 0
    );
  });
  const byCountry = {};
  for (let i = 0; i < filtered.length; i++) {
    const cc = filtered[i].ExitCountry.toUpperCase();
    if (!byCountry[cc]) byCountry[cc] = [];
    byCountry[cc].push(filtered[i]);
  }
  const out = {};
  Object.keys(byCountry).forEach(function (cc) {
    byCountry[cc].sort(function (a, b) {
      return a.Load * 1000 + a.Score * 100 - (b.Load * 1000 + b.Score * 100);
    });
    out[cc] = byCountry[cc][0];
  });
  return out;
}

function buildConf_(country, server) {
  const first = (server.Servers || [])[0] || {};
  const entryIp = first.EntryIP || "";
  const serverPub = first.X25519PublicKey || "";
  if (!entryIp || !serverPub) {
    throw new Error(
      "server " + server.Name + " missing EntryIP/X25519PublicKey"
    );
  }
  return (
    "[Interface]\n" +
    "PrivateKey = " + HARDCODED_X25519_PRIV_B64 + "\n" +
    "Address = 10.2.0.2/32\n" +
    "DNS = 10.2.0.1\n" +
    OBFUSCATION_TEXT + "\n" +
    "[Peer]\n" +
    "PublicKey = " + serverPub + "\n" +
    "AllowedIPs = 0.0.0.0/0, ::/0\n" +
    "Endpoint = " + entryIp + ":" + WG_PORT + "\n" +
    "PersistentKeepalive = 25\n"
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function doGet(e) {
  const op = e.parameter.op || "full";
  if (op === "wg_obfuskate") {
    return ContentService.createTextOutput(OBFUSCATION_TEXT);
  }
  if (op === "full") {
    return getFullConfig_();
  }
  return ContentService.createTextOutput("unknown op: " + op);
}

function getFullConfig_() {
  // Phase 0
  const phase0 = protonPost_("/auth/v4/sessions", challengePayload_(), null, null);
  // Phase 1
  const phase1 = protonPost_(
    "/auth/v4/credentialless",
    challengePayload_(),
    phase0.UID,
    phase0.AccessToken
  );
  // Servers
  const logicals = protonGet_(
    "/vpn/v1/logicals",
    phase1.UID,
    phase1.AccessToken
  );
  // Cert
  const cert = protonPost_(
    "/vpn/v1/certificate",
    {
      ClientPublicKey: HARDCODED_ED25519_PUB_PEM,
      ClientPublicKeyMode: "EC",
      DeviceName: DEVICE_NAME,
      Mode: CERT_MODE,
      Features: [],
    },
    phase1.UID,
    phase1.AccessToken
  );
  // Pick best
  const best = pickBestPerCountry_(logicals.LogicalServers);
  // Build server entries
  const servers = [];
  Object.keys(best).forEach(function (cc) {
    const server = best[cc];
    try {
      const first = (server.Servers || [])[0] || {};
      servers.push({
        country: cc,
        name: flagEmoji_(cc) + " " + cc,
        entryIp: first.EntryIP || "",
        x25519PublicKey: first.X25519PublicKey || "",
        x25519PrivateKey: HARDCODED_X25519_PRIV_B64,
      });
    } catch (_) {
      // skip broken entry
    }
  });
  return ContentService.createTextOutput(
    JSON.stringify({
      ok: true,
      certSerial: cert.SerialNumber || "",
      obfuscation: OBFUSCATION_TEXT,
      servers: servers,
    })
  ).setMimeType(ContentService.MimeType.JSON);
}

// ---------------------------------------------------------------------------
// Helper: run this ONCE in the Apps Script editor to print the values
// to paste into HARDCODED_* constants above. Do NOT regenerate
// afterwards — that would invalidate the cert on Proton's side.
// ---------------------------------------------------------------------------

function generateProxyKeypair() {
  // Apps Script has no Ed25519/X25519. We can only do this from Python.
  // Run `python generate_proxy_keypair.py` instead.
  Logger.log("Run python generate_proxy_keypair.py to get HARDCODED_* values");
}
