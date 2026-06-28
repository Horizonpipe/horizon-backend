'use strict';

function parseHostFromUrl(value) {
  if (!value) return '';
  try {
    return new URL(String(value).trim()).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** Hostnames treated as the public SaaS sign-up front door (pipeshare.net). */
function saasSignupHosts() {
  const hosts = new Set(['pipeshare.net', 'www.pipeshare.net']);
  const base = String(process.env.SAAS_CPANEL_BASE_URL || '')
    .trim()
    .replace(/\/$/, '');
  if (base) {
    const h = parseHostFromUrl(base);
    if (h) {
      hosts.add(h);
      if (h.startsWith('www.')) hosts.add(h.slice(4));
      else hosts.add(`www.${h}`);
    }
  }
  return hosts;
}

/**
 * SaaS sign-up (pipeshare.net) must verify by email only — no dev PIN bypass.
 * Non-SaaS (pipeshare.live) may use SIGNUP_DEV_RETURN_PIN when SMTP is absent.
 */
function isSaasSignupRequest(req) {
  const explicit = String(req.body?.signupContext ?? req.body?.signup_context ?? '')
    .trim()
    .toLowerCase();
  if (explicit === 'saas') return true;
  if (explicit === 'non-saas' || explicit === 'dev') return false;

  const hosts = saasSignupHosts();
  for (const header of [req.get('origin'), req.get('referer')]) {
    const h = parseHostFromUrl(header);
    if (h && hosts.has(h)) return true;
  }
  return false;
}

module.exports = {
  isSaasSignupRequest,
  saasSignupHosts,
  parseHostFromUrl
};
