import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  HELP_REPLY,
  STOP_REPLY,
  YES_NO_KEYWORD_REPLY,
  buildCrewText,
  classifyKeyword,
  employeeMayReceiveSms,
  handleInboundSms,
  phoneKey,
  replyFor,
  sendOperationalSms,
  twilioReady,
  validTwilioSignature
} from './operational-sms.js';

const TWILIO_KEYS = [
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_API_KEY',
  'TWILIO_API_SECRET',
  'TWILIO_PHONE_NUMBER',
  'TWILIO_MESSAGING_SERVICE_SID',
  'TWILIO_WEBHOOK_SECRET'
];

test('US phone keys stay on the last 10 digits', () => {
  assert.equal(phoneKey('+1 (904) 925-1267'), '9049251267');
  assert.equal(phoneKey('9049251267'), '9049251267');
  assert.equal(phoneKey('555'), '');
});

test('keywords are operational replies, not a signup campaign', () => {
  assert.equal(classifyKeyword('stop'), 'stop');
  assert.equal(classifyKeyword('STOPALL'), 'stop');
  assert.equal(classifyKeyword('  start please'), 'start');
  assert.equal(classifyKeyword('UNSTOP'), 'start');
  assert.equal(classifyKeyword('Help'), 'help');
  assert.equal(classifyKeyword('YES'), 'yes');
  assert.equal(classifyKeyword('schedule me'), 'other');
  assert.equal(replyFor('stop'), STOP_REPLY);
  assert.equal(STOP_REPLY.includes('PipeShare:'), true);
  assert.equal(STOP_REPLY.includes('Reply START to opt back in.'), true);
  assert.equal(HELP_REPLY.includes('Reply STOP to opt out.'), true);
  assert.equal(YES_NO_KEYWORD_REPLY.includes('does not opt you in'), true);
});

test('crew texts name PipeShare and include STOP', () => {
  for (const kind of ['schedule', 'reminder', 'change', 'cancel']) {
    const text = buildCrewText(kind, {
      project: 'Phase 1B',
      when: '2026-10-24 7:00 AM',
      place: 'Jacksonville, FL',
      map: 'https://maps.example/job'
    });
    assert.equal(text.startsWith('PipeShare:'), true, kind);
    assert.equal(text.includes('Reply STOP to opt out.'), true, kind);
  }
});

test('customers and missing consent cannot be texted', () => {
  const optOut = { opted_out_at: '2026-10-23T12:00:00Z', started_at: null };
  assert.equal(
    employeeMayReceiveSms(
      { account_type: 'customer', phone: '9045550100', sms_consent: true },
      null
    ),
    false
  );
  assert.equal(
    employeeMayReceiveSms(
      { account_type: 'employee', phone: '9045550100', sms_consent: false },
      null
    ),
    false
  );
  assert.equal(
    employeeMayReceiveSms(
      { account_type: 'employee', phone: '9045550100', sms_consent: true, sms_opted_out_at: '2026-10-23' },
      null
    ),
    false
  );
  assert.equal(
    employeeMayReceiveSms(
      { account_type: 'employee', phone: '9045550100', sms_consent: true },
      optOut
    ),
    false
  );
  assert.equal(
    employeeMayReceiveSms({ account_type: 'employee', phone: '9045550100', sms_consent: true }, null),
    true
  );
});

test('Twilio signatures reject a tampered body', () => {
  const token = 'unit-test-token';
  const url = 'https://pipeshare.live/api/sms/twilio/inbound';
  const params = { Body: 'STOP', From: '+19045550100' };
  const data = `${url}BodySTOPFrom+19045550100`;
  const signature = crypto.createHmac('sha1', token).update(data, 'utf8').digest('base64');
  assert.equal(validTwilioSignature(token, signature, url, params), true);
  assert.equal(validTwilioSignature(token, signature, url, { Body: 'HELP', From: '+19045550100' }), false);
  assert.equal(validTwilioSignature('', signature, url, params), false);
});

test('send does not call Twilio when credentials are absent', async () => {
  const saved = new Map(TWILIO_KEYS.map((key) => [key, process.env[key]]));
  for (const key of TWILIO_KEYS) delete process.env[key];
  let called = false;
  const original = global.fetch;
  global.fetch = async () => {
    called = true;
    throw new Error('fetch should not run');
  };
  try {
    assert.equal(twilioReady(), false);
    const result = await sendOperationalSms({ to: '+19045550100', body: 'PipeShare: Schedule. Reply STOP to opt out.' });
    assert.equal(result.ok, false);
    assert.equal(result.code, 'not_configured');
    assert.equal(called, false);
  } finally {
    global.fetch = original;
    for (const [key, value] of saved) {
      if (value == null) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('STOP stores an opt-out and YES does not create consent', async () => {
  const queries = [];
  const users = [
    {
      id: 'emp',
      account_type: 'employee',
      phone: '9045550100',
      sms_consent: false,
      sms_opted_out_at: null
    }
  ];
  const pool = {
    async query(sql, params) {
      queries.push(String(sql));
      if (sql.includes('INSERT INTO sms_inbound_messages')) return { rows: [{ message_sid: params[0] }] };
      if (sql.includes('FROM users')) return { rows: users };
      if (sql.includes('FROM sms_opt_outs')) return { rows: [] };
      return { rows: [] };
    }
  };
  const stopped = await handleInboundSms(pool, { Body: 'STOP', From: '+19045550100', MessageSid: 'SM1' });
  assert.equal(stopped.text, STOP_REPLY);
  assert.equal(queries.some((sql) => sql.includes('INSERT INTO sms_opt_outs')), true);
  assert.equal(queries.some((sql) => sql.includes('sms_consent = true') || sql.includes('sms_consent=true')), false);

  queries.length = 0;
  const yes = await handleInboundSms(pool, { Body: 'YES', From: '+19045550100', MessageSid: 'SM2' });
  assert.equal(yes.text, YES_NO_KEYWORD_REPLY);
  assert.equal(queries.some((sql) => /UPDATE users[\s\S]*sms_consent/i.test(sql)), false);
  assert.equal(queries.some((sql) => sql.includes('INSERT INTO sms_opt_outs')), false);
});
