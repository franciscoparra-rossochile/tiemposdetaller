/* ═══════════════════════════════════════════════════════════════════════════
   AUTENTICACIÓN DEL LADO DEL SERVIDOR

   El problema que resuelve, medido hoy: la app hacía
     select * from users where username = ...
   con la llave anónima, y comparaba la contraseña en el navegador. Esa llave
   está embebida en el HTML de un sitio público. Cualquiera que abriera el
   código fuente podía leer la tabla completa de usuarios con las contraseñas
   EN TEXTO PLANO. Y la gente reutiliza contraseñas: el daño no se queda en
   esta app.

   Cómo queda: las contraseñas se guardan como hash scrypt en `user_secrets`,
   una tabla con RLS activo y sin políticas — o sea, invisible para la llave
   anónima. Esta función es la única que puede leerla, usando la llave de
   servicio que vive solo en las variables de entorno de Netlify. El navegador
   nunca ve un hash ni una contraseña.

   Período de transición: si un usuario todavía no tiene hash, se valida contra
   la contraseña antigua y se le crea el hash en ese mismo login. Así la app de
   producción sigue funcionando mientras se migra, sin dejar a nadie afuera.
   El último paso —borrar la columna `password`— se hace cuando producción
   también apunte acá.
   ═══════════════════════════════════════════════════════════════════════════ */
const crypto = require('crypto');

const SURL = 'https://jczmupcmeixpwjedfgtk.supabase.co';
const ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Impjem11cGNtZWl4cHdqZWRmZ3RrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY5NzMxOTMsImV4cCI6MjA5MjU0OTE5M30.DuICC_pCQGv27lZivieXRRvGz9A1GNkgmhvTvyKo25o';

const J = (code, obj) => ({
  statusCode: code,
  headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type' },
  body: JSON.stringify(obj)
});

function llave() {
  /* la de servicio si está configurada; si no, la anónima (modo transición) */
  return process.env.SUPABASE_SERVICE_ROLE_KEY || ANON;
}
async function sb(path, method, body) {
  const k = llave();
  const r = await fetch(SURL + '/rest/v1/' + path, {
    method: method || 'GET',
    headers: { apikey: k, Authorization: 'Bearer ' + k, 'content-type': 'application/json',
               Prefer: method === 'POST' ? 'resolution=merge-duplicates,return=representation' : 'return=minimal' },
    body: body ? JSON.stringify(body) : undefined
  });
  const t = await r.text();
  if (!r.ok) throw new Error(path + ' → ' + r.status + ' ' + t.slice(0, 200));
  return t ? JSON.parse(t) : [];
}

/* scrypt viene en Node, sin dependencias que instalar ni mantener */
function hashear(clave, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(clave), s, 32, { N: 16384, r: 8, p: 1 }).toString('hex');
  return 'scrypt$' + s + '$' + h;
}
function verificar(clave, guardado) {
  try {
    const [alg, salt, h] = String(guardado || '').split('$');
    if (alg !== 'scrypt' || !salt || !h) return false;
    const calc = crypto.scryptSync(String(clave), salt, 32, { N: 16384, r: 8, p: 1 }).toString('hex');
    /* comparación de tiempo constante: no filtrar por cuánto demora */
    const a = Buffer.from(calc, 'hex'), b = Buffer.from(h, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) { return false; }
}

/* Nunca devolver al navegador nada que se parezca a una credencial. */
function limpiar(u) {
  const out = { ...u };
  delete out.password; delete out.password_hash; delete out.pass; delete out.clave;
  return out;
}

/* Convierte a hash lo que quede en texto plano. Se dispara sin await para no
   demorar el login: si falla, el próximo login lo vuelve a intentar. */
let _barriendo = false;
async function barrido(limite) {
  if (_barriendo) return 0;
  _barriendo = true;
  try {
    let users = [];
    try { users = await sb('users?select=id,password'); }
    catch (_) { return 0; }  /* la columna ya no existe: no queda nada que migrar */
    const secretos = await sb('user_secrets?select=user_id');
    const ya = new Set((secretos || []).map(x => x.user_id));
    let faltan = (users || []).filter(u => u.password && !ya.has(u.id));
    if (limite) faltan = faltan.slice(0, limite);
    let n = 0;
    for (const u of faltan) {
      try { await sb('user_secrets', 'POST', { user_id: u.id, password_hash: hashear(u.password) }); n++; } catch (_) {}
    }
    if (n) console.log('barrido: ' + n + ' contrasena(s) convertidas a hash');
    return n;
  } catch (e) {
    console.warn('barrido no pudo correr:', String(e.message).slice(0, 90));
    return 0;
  } finally { _barriendo = false; }
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return J(204, {});
  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (_) {}
  const accion = body.accion || 'login';

  try {
    /* ── Migración: hashea todo lo que quede en texto plano. Una sola vez. ── */
    if (accion === 'migrar') {
      if (body.k !== process.env.MIGRACION_TOKEN) return J(401, { error: 'no autorizado' });
      const users = await sb('users?select=id,username,password');
      const secretos = await sb('user_secrets?select=user_id');
      const ya = new Set((secretos || []).map(s => s.user_id));
      let n = 0;
      for (const u of users) {
        if (ya.has(u.id) || !u.password) continue;
        await sb('user_secrets', 'POST', { user_id: u.id, password_hash: hashear(u.password) });
        n++;
      }
      return J(200, { ok: true, migrados: n, total: users.length, con_hash: ya.size + n });
    }

    /* ── Login ── */
    if (accion === 'login') {
      const uname = String(body.username || '').trim().toLowerCase();
      const clave = String(body.password || '');
      if (!uname || !clave) return J(400, { error: 'Faltan usuario o contraseña' });

      const rows = await sb('users?select=*&username=eq.' + encodeURIComponent(uname) + '&limit=1');
      const u = (rows || [])[0];
      /* mismo mensaje y mismo costo si el usuario no existe: no revelar cuáles sí */
      if (!u) { hashear(clave); return J(401, { error: 'Usuario o contraseña incorrectos' }); }

      /* Si todavía no está cargada la llave de servicio, la tabla de secretos
         es inaccesible (RLS). Eso NO puede dejar a nadie afuera: se cae al
         camino antiguo y se avisa por log. El login jamás debe romperse. */
      let guardado = null, secretosDisponibles = true;
      try {
        const sec = await sb('user_secrets?select=password_hash&user_id=eq.' + u.id + '&limit=1');
        guardado = ((sec || [])[0] || {}).password_hash || null;
      } catch (e) {
        secretosDisponibles = false;
        console.warn('user_secrets inaccesible (falta SUPABASE_SERVICE_ROLE_KEY):', String(e.message).slice(0, 90));
      }

      if (guardado) {
        if (!verificar(clave, guardado)) return J(401, { error: 'Usuario o contraseña incorrectos' });
      } else {
        /* transición: todavía sin hash. Se valida contra el valor antiguo y se
           crea el hash en el acto, para que el próximo login ya sea seguro. */
        /* sin hash y sin columna antigua no hay con qué comparar */
        if (!('password' in u) || !u.password || String(u.password) !== clave) return J(401, { error: 'Usuario o contraseña incorrectos' });
        if (secretosDisponibles) {
          try { await sb('user_secrets', 'POST', { user_id: u.id, password_hash: hashear(clave) }); } catch (_) {}
        }
      }
      /* ── Barrido automático ──
         En cuanto la llave de servicio está cargada, el primer login convierte
         a hash TODAS las contraseñas que queden en texto plano. Es idempotente
         y elimina el paso manual: nadie tiene que acordarse de dispararlo ni
         manejar un token para hacerlo. */
      /* Esperado y acotado: en una función serverless el proceso se congela
         apenas se responde, así que un barrido "en segundo plano" nunca
         alcanza a correr. Dos por login agregan ~200 ms y convergen en pocos
         ingresos; el barrido completo va en la acción `estado`. */
      if (secretosDisponibles) { try { await barrido(2); } catch (_) {} }
      return J(200, { ok: true, user: limpiar(u), seguro: !!guardado });
    }

    /* ── Cambio de contraseña ── */
    if (accion === 'cambiar') {
      const uid = String(body.user_id || '');
      const actual = String(body.actual || ''), nueva = String(body.nueva || '');
      if (!uid || !nueva) return J(400, { error: 'Faltan datos' });
      if (nueva.length < 6) return J(400, { error: 'La contraseña nueva debe tener al menos 6 caracteres' });
      const rows = await sb('users?select=id,password,must_change_password&id=eq.' + uid + '&limit=1');
      const u = (rows || [])[0];
      if (!u) return J(404, { error: 'Usuario no encontrado' });
      const sec = await sb('user_secrets?select=password_hash&user_id=eq.' + uid + '&limit=1');
      const guardado = ((sec || [])[0] || {}).password_hash;
      /* si viene de un reseteo obligatorio no se pide la actual */
      if (!u.must_change_password) {
        const okActual = guardado ? verificar(actual, guardado) : (u.password && String(u.password) === actual);
        if (!okActual) return J(401, { error: 'La contraseña actual no coincide' });
      }
      await sb('user_secrets', 'POST', { user_id: uid, password_hash: hashear(nueva) });
      /* Solo se toca la columna antigua si todavía existe: cuando se borre,
         este PATCH falla y no debe tumbar el cambio de contraseña. */
      try { await sb('users?id=eq.' + uid, 'PATCH', { password: nueva, must_change_password: false }); }
      catch (_) { await sb('users?id=eq.' + uid, 'PATCH', { must_change_password: false }); }
      return J(200, { ok: true });
    }

    /* ── Fijar contraseña (alta o reseteo por administrador) ──
       La app ya no puede escribir en `users.password` porque esa columna deja
       de existir: acá se crea el hash. No pide la actual porque es un reseteo
       administrativo, y por eso marca must_change_password. */
    if (accion === 'set') {
      const uid = String(body.user_id || '');
      const nueva = String(body.nueva || '');
      if (!uid || !nueva) return J(400, { error: 'Faltan datos' });
      if (nueva.length < 4) return J(400, { error: 'La contraseña debe tener al menos 4 caracteres' });
      const rows = await sb('users?select=id&id=eq.' + uid + '&limit=1');
      if (!(rows || [])[0]) return J(404, { error: 'Usuario no encontrado' });
      await sb('user_secrets', 'POST', { user_id: uid, password_hash: hashear(nueva) });
      if (body.forzar_cambio !== false) {
        try { await sb('users?id=eq.' + uid, 'PATCH', { must_change_password: true }); } catch (_) {}
      }
      return J(200, { ok: true });
    }

    /* ── Diagnóstico: cuánto falta por migrar (sin exponer nada) ── */
    if (accion === 'estado') {
      /* Diagnóstico y también el empujón: acá sí conviene esperar el barrido
         completo, porque nadie está esperando una pantalla. */
      if (process.env.SUPABASE_SERVICE_ROLE_KEY) { try { await barrido(0); } catch (_) {} }
      const users = await sb('users?select=id');
      let secretos = [];
      try { secretos = await sb('user_secrets?select=user_id'); }
      catch (_) { return J(200, { ok: true, usuarios: (users || []).length, con_hash: null,
        llave_de_servicio: false, aviso: 'Falta SUPABASE_SERVICE_ROLE_KEY en Netlify: sin ella no se puede leer la tabla de secretos.' }); }
      const n = (users || []).length, c = (secretos || []).length;
      return J(200, {
        ok: true, usuarios: n, con_hash: c, faltan: Math.max(0, n - c),
        llave_de_servicio: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
        listo: n > 0 && c >= n,
        siguiente: (n > 0 && c >= n)
          ? 'Todas las contraseñas están en hash. Ya se puede borrar la columna `password` (coordinar con producción).'
          : 'El primer login después de cargar la llave convierte todo solo.'
      });
    }

    return J(400, { error: 'acción desconocida' });
  } catch (e) {
    return J(500, { error: String(e.message || e).slice(0, 300) });
  }
};
