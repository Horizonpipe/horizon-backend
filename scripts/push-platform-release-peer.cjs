require('dotenv').config({ path: '/opt/horizon/horizon-backend/.env' });
const { pushPlatformReleaseToPeers } = require('/opt/horizon/horizon-backend/lib/platform-release-peers');

const version = process.argv[2] || '0.0.5';
pushPlatformReleaseToPeers(version, { actor: 'BASE-verify' })
  .then((r) => {
    console.log(JSON.stringify({ ok: true, peers: r }, null, 2));
  })
  .catch((e) => {
    console.error(JSON.stringify({ ok: false, error: e.message || String(e) }));
    process.exit(1);
  });
