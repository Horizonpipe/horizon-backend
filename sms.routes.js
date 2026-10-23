'use strict';

const { handleInboundSms, inboundRequestAllowed, twimlMessage } = require('./lib/operational-sms');

function registerSmsRoutes(app, { pool }) {
  async function inbound(req, res) {
    try {
      const allowed = await inboundRequestAllowed(req, pool);
      if (!allowed) return res.status(403).type('text/plain').send('Forbidden');
      const result = await handleInboundSms(pool, req.body || {});
      return res.type('text/xml').send(twimlMessage(result.text));
    } catch (err) {
      console.error('[sms] inbound', err?.message || err);
      return res.status(500).type('text/plain').send('Inbound text could not be handled.');
    }
  }

  app.post('/api/sms/twilio/inbound', inbound);
  app.post('/api/sms/twilio/inbound/:hookKey', inbound);
}

module.exports = { registerSmsRoutes };
