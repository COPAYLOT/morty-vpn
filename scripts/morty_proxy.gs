/**
 * Morty VPN — Apps Script HTTP proxy.
 *
 * Generic forwarder. The APK builds the Proton API request locally
 * (URL + method + headers + body) and asks the script to perform it.
 * The script returns the response status + body to the APK.
 *
 * Why this exists: the user's network (where the script lives) has
 * access to api.protonvpn.ch; the APK's network may not. The script
 * acts as a relay: it does the Proton API calls and ships the results
 * back to the APK.
 *
 * Endpoint:
 *   GET <URL>?op=proxy
 *       &url=<URL-encoded Proton URL>
 *       &method=<GET|POST>
 *       &headers=<URL-encoded JSON object>
 *       &body=<URL-encoded request body, optional>
 *
 * Response (success):
 *   { "ok": true, "status": <int>, "body": "<string>" }
 *
 * Response (failure):
 *   { "ok": false, "error": "<string>" }
 *
 * Other ops:
 *   ?op=ping -> "pong" (for connectivity test)
 *
 * Deploy:
 *   1. https://script.google.com -> New project
 *   2. Paste this file (Code.gs)
 *   3. Deploy -> New deployment -> Web app
 *      - Execute as: Me
 *      - Who has access: Anyone
 *   4. Copy the deployment URL.
 *   5. In the APK, set `ProtonProxyClient.PROXY_BASE_URL` to that URL.
 *
 * Notes:
 *   - All logic (login, fetch, cert, config build) lives in the APK.
 *   - This script is a pure forwarder — no Proton knowledge here.
 *   - Obfuscation (`?op=wg_obfuskate`) is a SEPARATE script that the
 *     APK fetches directly without going through this proxy.
 */

function json_(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet(e) {
  try {
    const op = e.parameter.op;

    // Health check — for testing connectivity from the APK
    if (op === 'ping') {
      return json_({ok: true, status: 200, body: 'pong'});
    }

    if (op !== 'proxy') {
      return json_({ok: false, error: 'unknown op: ' + op});
    }

    const url = e.parameter.url;
    if (!url) {
      return json_({ok: false, error: 'url required'});
    }

    const method = (e.parameter.method || 'GET').toUpperCase();
    const headers = e.parameter.headers
      ? JSON.parse(e.parameter.headers)
      : {};
    const body = e.parameter.body || null;

    const fetchOpts = {
      method: method,
      headers: headers,
      muteHttpExceptions: true,
    };
    if (body !== null) {
      fetchOpts.contentType = 'application/json';
      fetchOpts.payload = body;
    }

    const resp = UrlFetchApp.fetch(url, fetchOpts);
    return json_({
      ok: true,
      status: resp.getResponseCode(),
      body: resp.getContentText(),
    });
  } catch (err) {
    return json_({
      ok: false,
      error: String((err && err.message) || err),
    });
  }
}
