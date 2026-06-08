// ============================================================
// Lea Rossek — Admin API Route (Vercel Serverless Function)
//
// ALL admin operations go through here. The service_role key
// and admin password NEVER touch the browser.
//
// Required environment variables in Vercel dashboard:
//   SUPABASE_URL          — your Supabase project URL
//   SUPABASE_SERVICE_KEY  — service_role secret key (NOT the anon key)
//   ADMIN_PASSWORD        — the admin panel password Lea uses
// ============================================================

const { createClient } = require('@supabase/supabase-js');

// ── Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://learossek.com',
  'https://www.learossek.com',
  'https://learossek-app.vercel.app',
];

// ── Simple in-memory rate limiter (resets when function cold-starts)
//    For production scale, replace with Vercel KV or Upstash Redis.
const rateMap = new Map();
const RATE_LIMIT = 20;          // max requests
const RATE_WINDOW = 60 * 1000; // per 60 seconds

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) {
    rateMap.set(ip, { count: 1, start: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  rateMap.set(ip, entry);
  return true;
}

module.exports = async (req, res) => {
  // ── CORS
  const origin = req.headers.origin || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  // ── Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  }

  // ── Parse body
  let body;
  try {
    body = typeof req.body === 'object' ? req.body : JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const { action, payload = {}, password } = body;

  // ── Validate environment variables
  const SUPABASE_URL      = process.env.SUPABASE_URL;
  const SUPABASE_SVC_KEY  = process.env.SUPABASE_SERVICE_KEY;
  const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD;

  if (!SUPABASE_URL || !SUPABASE_SVC_KEY || !ADMIN_PASSWORD) {
    console.error('Missing environment variables');
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  // ── Authenticate — password checked server-side, never exposed to client
  if (!password || password !== ADMIN_PASSWORD) {
    // Small delay to slow brute-force attempts
    await new Promise(r => setTimeout(r, 300));
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ── Supabase client with service_role (bypasses RLS — safe server-side only)
  const sb = createClient(SUPABASE_URL, SUPABASE_SVC_KEY, {
    auth: { persistSession: false }
  });

  try {
    switch (action) {

      // ── Health check / login validation
      case 'ping':
        return res.json({ ok: true });

      // ── Bookings
      case 'getAllBookings': {
        const { data, error } = await sb
          .from('bookings')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(500);
        return res.json({ data: data || [], error: error?.message || null });
      }

      case 'confirmBooking': {
        if (!payload.id) return res.status(400).json({ error: 'Missing booking id' });
        const { error } = await sb
          .from('bookings')
          .update({ status: 'confirmed' })
          .eq('id', payload.id);
        return res.json({ error: error?.message || null });
      }

      case 'cancelBooking': {
        if (!payload.id) return res.status(400).json({ error: 'Missing booking id' });
        const { error } = await sb
          .from('bookings')
          .update({ status: 'cancelled' })
          .eq('id', payload.id);
        return res.json({ error: error?.message || null });
      }

      // ── Sessions
      case 'getAllSessions': {
        const { data, error } = await sb
          .from('sessions')
          .select('*')
          .order('date')
          .order('time')
          .limit(200);
        return res.json({ data: data || [], error: error?.message || null });
      }

      case 'addSession': {
        const s = sanitizeSession(payload);
        if (!s) return res.status(400).json({ error: 'Invalid session data' });
        const { data, error } = await sb.from('sessions').insert([s]).select();
        return res.json({ data: data || [], error: error?.message || null });
      }

      case 'updateSession': {
        if (!payload.id) return res.status(400).json({ error: 'Missing session id' });
        const s = sanitizeSession(payload.data);
        if (!s) return res.status(400).json({ error: 'Invalid session data' });
        const { error } = await sb.from('sessions').update(s).eq('id', payload.id);
        return res.json({ error: error?.message || null });
      }

      case 'deleteSession': {
        if (!payload.id) return res.status(400).json({ error: 'Missing session id' });
        const { error } = await sb.from('sessions').update({ active: false }).eq('id', payload.id);
        return res.json({ error: error?.message || null });
      }

      // ── Prices
      case 'updatePrice': {
        const { key, amount } = payload;
        if (!['studio', 'private'].includes(key)) return res.status(400).json({ error: 'Invalid price key' });
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt < 0 || amt > 10000) return res.status(400).json({ error: 'Invalid price amount' });
        const { error } = await sb
          .from('prices')
          .update({ amount: amt, updated_at: new Date().toISOString() })
          .eq('key', key);
        return res.json({ error: error?.message || null });
      }

      // ── Clients
      case 'getAllClients': {
        const { data, error } = await sb
          .from('clients')
          .select('*')
          .order('sessions_count', { ascending: false })
          .limit(1000);
        return res.json({ data: data || [], error: error?.message || null });
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (e) {
    console.error('Admin API error:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// ── Server-side input sanitization for sessions
function sanitizeSession(raw) {
  if (!raw) return null;
  const type = ['studio', 'guest'].includes(raw.type) ? raw.type : null;
  const title = String(raw.title || '').trim().slice(0, 120);
  const date  = /^\d{4}-\d{2}-\d{2}$/.test(raw.date) ? raw.date : null;
  const time  = /^\d{2}:\d{2}$/.test(raw.time) ? raw.time : null;
  const price = parseFloat(raw.price);

  if (!type || !title || !date || !time || isNaN(price)) return null;

  return {
    type,
    title,
    date,
    time,
    duration: Math.min(Math.max(parseInt(raw.duration) || 50, 10), 300),
    location: String(raw.location || '').trim().slice(0, 120),
    address:  raw.address ? String(raw.address).trim().slice(0, 200) : null,
    capacity: type === 'studio' ? (parseInt(raw.capacity) || 2) : null,
    price:    Math.min(Math.max(price, 0), 10000),
    external_link: type === 'guest' && raw.external_link
      ? String(raw.external_link).trim().slice(0, 500) : null,
    coupon: type === 'guest' && raw.coupon
      ? String(raw.coupon).trim().slice(0, 50) : null,
    lat: raw.lat ? parseFloat(raw.lat) : null,
    lng: raw.lng ? parseFloat(raw.lng) : null,
    active: true,
  };
}
