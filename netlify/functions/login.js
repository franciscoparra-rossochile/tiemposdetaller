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

/* ── Prueba de identidad entre llamadas ────────────────────────────────────
   Sin esto, `set` y el cambio forzado de contraseña quedaban abiertos: la
   tabla `users` es legible con la llave anónima, así que cualquiera obtenía
   el uuid del admin y le fijaba una contraseña nueva. Verificado en vivo.

   El token es HMAC sobre {uid, rol, exp}. La llave de firma es la de servicio,
   que ya vive en las variables de entorno: no hay nada nuevo que configurar.
   Si esa llave falta, `abrirToken` devuelve null y las acciones sensibles se
   niegan — falla cerrado, que es como debe fallar. */
const TOKEN_MS = 12 * 3600 * 1000;   /* igual que la sesión de la app */

function secretoFirma() { return process.env.SUPABASE_SERVICE_ROLE_KEY || ''; }

function firmar(uid, rol) {
  const s = secretoFirma();
  if (!s) return null;
  const cuerpo = Buffer.from(JSON.stringify({ uid, rol, exp: Date.now() + TOKEN_MS })).toString('base64url');
  const firma = crypto.createHmac('sha256', s).update(cuerpo).digest('base64url');
  return cuerpo + '.' + firma;
}

function abrirToken(t) {
  const s = secretoFirma();
  if (!s || !t || typeof t !== 'string') return null;
  const i = t.indexOf('.');
  if (i < 1) return null;
  const cuerpo = t.slice(0, i), firma = t.slice(i + 1);
  const esperada = crypto.createHmac('sha256', s).update(cuerpo).digest('base64url');
  const a = Buffer.from(firma), b = Buffer.from(esperada);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p = null;
  try { p = JSON.parse(Buffer.from(cuerpo, 'base64url').toString('utf8')); } catch (_) { return null; }
  if (!p || !p.uid || !p.exp || Date.now() > p.exp) return null;
  return p;
}

/* Nunca devolver al navegador nada que se parezca a una credencial. */
function limpiar(u) {
  const out = { ...u };
  delete out.password; delete out.password_hash; delete out.pass; delete out.clave;
  return out;
}

/* El barrido de migración se eliminó junto con la columna `password`: ya no
   queda nada en texto plano que convertir. */

/* ── Largo mínimo de contraseña ────────────────────────────────────────────
   Seis, acompañado del freno de abajo. Sin freno, seis caracteres se prueban
   por fuerza bruta; con freno, un atacante tiene ocho tiros cada cuarto de
   hora y el problema deja de ser el largo. */
const CLAVE_MIN = 6;

/* ── Freno a intentos ──────────────────────────────────────────────────────
   Los fallidos viven en `login_attempts`, tabla con RLS y sin políticas:
   invisible para la llave pública. Si la tabla no existe, `frenado` devuelve
   false y el login sigue igual: un freno que se cae no puede dejar al taller
   afuera.

   ⚠ El contador por IP solo cuenta intentos contra usuarios QUE NO EXISTEN.
   Los 15 del taller salen a internet por la misma IP: si contara todos los
   fallos, quince personas equivocándose dos veces cada una el lunes en la
   mañana —justo cuando todos cambian su contraseña— sumarían treinta y
   dejarían al taller entero bloqueado. Eso no es un ataque, es un lunes.
   Probar nombres de usuario que no existen sí es la firma de alguien
   barriendo la lista, y para eso queda el contador. La cuenta concreta la
   protege el contador por usuario, que sí cuenta todo. */
const FRENO_VENTANA_MIN = 15;
const FRENO_POR_USUARIO = 8;
const FRENO_POR_IP      = 30;

function ipDe(event) {
  const h = (event && event.headers) || {};
  const x = h['x-nf-client-connection-ip'] || h['client-ip'] || h['x-forwarded-for'] || '';
  return String(x).split(',')[0].trim() || 'desconocida';
}

async function contar(clave, desde) {
  const q = 'login_attempts?select=id&clave=eq.' + encodeURIComponent(clave) +
            '&cuando=gte.' + encodeURIComponent(desde);
  const filas = await sb(q);
  return (filas || []).length;
}

async function frenado(uname, ip) {
  const desde = new Date(Date.now() - FRENO_VENTANA_MIN * 60000).toISOString();
  try {
    const [porUsuario, porIp] = await Promise.all([
      contar('u:' + uname, desde),
      contar('ip:' + ip, desde)
    ]);
    if (porUsuario >= FRENO_POR_USUARIO) return 'usuario';
    if (porIp >= FRENO_POR_IP) return 'ip';
    return false;
  } catch (_) {
    return false;   /* la tabla no existe todavía: no frenar a nadie */
  }
}

async function anotarFallo(uname, ip, usuarioExiste) {
  try {
    const filas = [{ clave: 'u:' + uname }];
    /* solo se le cuenta a la IP cuando el usuario no existe: ver el comentario
       del bloque de arriba sobre los 15 detrás de la misma salida a internet */
    if (!usuarioExiste) filas.push({ clave: 'ip:' + ip });
    await sb('login_attempts', 'POST', filas);
    /* barrido barato: lo viejo ya no sirve para nada y la tabla no debe crecer */
    const viejo = new Date(Date.now() - 6 * 3600000).toISOString();
    await sb('login_attempts?cuando=lt.' + encodeURIComponent(viejo), 'DELETE');
  } catch (_) {}
}

/* ── Recuperación de contraseña por correo ─────────────────────────────────
   El enlace lleva un token firmado que incluye una HUELLA del hash de la
   contraseña vigente. Cuando la contraseña cambia, el hash cambia, la huella
   deja de coincidir y el enlace muere solo.

   Eso lo hace de un solo uso sin guardar nada en la base: no hay tabla de
   tokens que limpiar, no se acumulan tokens viejos, y no hay forma de reusar
   un enlace ya usado. Media hora de vigencia. */
const RECUP_MS = 30 * 60 * 1000;

/* De dónde sale el enlace del correo.
   ⚠ NO se usa el header Host tal cual: cualquiera puede falsificarlo y
   conseguir que el correo legítimo apunte a un dominio suyo. Se acepta solo
   uno de los dos sitios conocidos, y ante la duda, producción. */
const SITIOS = ['operacionrosso.netlify.app', 'beta-operacionrosso.netlify.app'];
function baseDe(event) {
  const h = ((event && event.headers) || {})['host'] || '';
  return 'https://' + (SITIOS.indexOf(String(h).toLowerCase()) >= 0 ? h : SITIOS[0]);
}

function huellaDe(hash) {
  return crypto.createHash('sha256').update(String(hash || '')).digest('base64url').slice(0, 12);
}

function firmarRecup(uid, hashActual) {
  const s = secretoFirma();
  if (!s) return null;
  const cuerpo = Buffer.from(JSON.stringify({
    uid, exp: Date.now() + RECUP_MS, h: huellaDe(hashActual)
  })).toString('base64url');
  return cuerpo + '.' + crypto.createHmac('sha256', s).update(cuerpo).digest('base64url');
}

/* Devuelve el uid solo si la firma es válida, no venció, y la contraseña
   sigue siendo la misma de cuando se emitió el enlace. */
async function abrirRecup(t) {
  const s = secretoFirma();
  if (!s || !t || typeof t !== 'string') return null;
  const i = t.indexOf('.');
  if (i < 1) return null;
  const cuerpo = t.slice(0, i);
  const esperada = crypto.createHmac('sha256', s).update(cuerpo).digest('base64url');
  const a = Buffer.from(t.slice(i + 1)), b = Buffer.from(esperada);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p = null;
  try { p = JSON.parse(Buffer.from(cuerpo, 'base64url').toString('utf8')); } catch (_) { return null; }
  if (!p || !p.uid || !p.exp || Date.now() > p.exp) return null;
  try {
    const sec = await sb('user_secrets?select=password_hash&user_id=eq.' + p.uid + '&limit=1');
    const guardado = ((sec || [])[0] || {}).password_hash;
    if (!guardado || huellaDe(guardado) !== p.h) return null;   /* ya se usó */
  } catch (_) { return null; }
  return p.uid;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* Envío por API HTTP, no SMTP: cero dependencias que empaquetar. */
async function enviarCorreo(para, asunto, html, texto) {
  const k = process.env.RESEND_API_KEY;
  if (!k) { console.warn('sin RESEND_API_KEY: no se envió el correo'); return false; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + k, 'content-type': 'application/json' },
      body: JSON.stringify({
        from: 'Rosso Chile <servicios@rossochile.cl>',
        to: [para], subject: asunto, html, text: texto
      })
    });
    if (!r.ok) { console.warn('Resend ' + r.status + ': ' + (await r.text()).slice(0, 200)); return false; }
    return true;
  } catch (e) { console.warn('no se pudo enviar el correo:', e.message); return false; }
}

function correoRecuperacion(nombre, enlace) {
  const html = '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a;">' +
    '<div style="font-weight:700;font-size:18px;letter-spacing:.04em;color:#c8102e;">ROSSO CHILE</div>' +
    '<h1 style="font-size:20px;margin:20px 0 8px;">Recuperar tu contraseña</h1>' +
    '<p style="line-height:1.55;margin:0 0 18px;">Hola ' + esc(nombre || '') + ', pediste recuperar el acceso a la aplicación del taller. ' +
    'Aprieta el botón y define una contraseña nueva.</p>' +
    '<p style="margin:0 0 20px;"><a href="' + esc(enlace) + '" style="display:inline-block;background:#c8102e;color:#fff;text-decoration:none;font-weight:700;padding:12px 22px;border-radius:8px;">Definir contraseña nueva</a></p>' +
    '<p style="line-height:1.55;color:#555;font-size:13px;margin:0 0 6px;">El enlace sirve por 30 minutos y una sola vez.</p>' +
    '<p style="line-height:1.55;color:#555;font-size:13px;margin:0;"><b>Si no pediste esto, ignora el correo.</b> Tu contraseña actual sigue funcionando y nadie puede cambiarla sin este enlace.</p>' +
    '<hr style="border:0;border-top:1px solid #e5e5e5;margin:22px 0;"/>' +
    '<p style="color:#888;font-size:12px;margin:0;">Si el botón no funciona, copia esta dirección en tu navegador:<br/>' + esc(enlace) + '</p>' +
    '</div>';
  const texto = 'Hola ' + (nombre || '') + ',\n\n' +
    'Pediste recuperar el acceso a la aplicación del taller. Abre esta dirección y define una contraseña nueva:\n\n' +
    enlace + '\n\nEl enlace sirve por 30 minutos y una sola vez.\n\n' +
    'Si no pediste esto, ignora el correo: tu contraseña actual sigue funcionando.\n\nRosso Chile';
  return { html, texto };
}

/* ── Portero compartido de acciones de administrador ───────────────────────
   `set` ya hacía esto en línea; las acciones de equipo necesitan lo mismo, y
   una regla de seguridad escrita en dos lugares se arregla en uno solo la
   próxima vez. El rol SIEMPRE se relee de la base: el que viaja en el token
   es una pista para pintar la pantalla, no una credencial. Si a alguien lo
   bajan de admin a las 10, su token de las 9 no le sirve a las 11. */
async function exigirAdmin(token) {
  const ses = abrirToken(token);
  if (!ses) return { error: 'Sesión no válida. Vuelve a entrar.', code: 401 };
  const filas = await sb('users?select=id,username,role,is_active&id=eq.' + ses.uid + '&limit=1');
  const u = (filas || [])[0];
  if (!u || u.role !== 'admin') return { error: 'Solo un administrador puede hacer esto', code: 403 };
  if (u.is_active === false) return { error: 'Cuenta desactivada', code: 403 };
  return u;
}

/* POST sin `merge-duplicates`: para crear una cuenta queremos que un choque
   falle, no que pise en silencio una fila existente. */
async function sbRep(path, method, body) {
  const k = llave();
  const r = await fetch(SURL + '/rest/v1/' + path, {
    method: method || 'POST',
    headers: { apikey: k, Authorization: 'Bearer ' + k, 'content-type': 'application/json',
               Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined
  });
  const t = await r.text();
  if (!r.ok) throw new Error(path + ' → ' + r.status + ' ' + t.slice(0, 200));
  return t ? JSON.parse(t) : [];
}

/* ── Lista blanca de campos ────────────────────────────────────────────────
   Se copia campo por campo lo que el panel puede tocar. Nada de reenviar el
   objeto que mandó el navegador: si mañana la tabla gana una columna
   sensible, un cliente modificado la escribiría sin que nadie lo note. Lo que
   no está en esta lista no se escribe, y punto.

   Fuera quedan a propósito: id, is_active, baja_el, baja_por (van por
   `equipo_baja`), recovery_email (lo pone su dueño, nadie más) y cualquier
   cosa que tenga que ver con la contraseña (va por `set`). */
const ROLES = ['admin', 'jefatura', 'tech'];
function camposEquipo(d) {
  d = d || {};
  const campos = {};
  if (d.name !== undefined)   campos.name   = String(d.name || '').trim().slice(0, 80);
  if (d.username !== undefined) campos.username = String(d.username || '').trim().toLowerCase().replace(/\s+/g, '').slice(0, 40);
  if (d.cargo !== undefined)  campos.cargo  = String(d.cargo || '').trim().slice(0, 80);
  if (d.avatar_url !== undefined) campos.avatar_url = d.avatar_url ? String(d.avatar_url).slice(0, 500) : null;
  if (d.role !== undefined) {
    const r = String(d.role || '');
    if (ROLES.indexOf(r) < 0) return { error: 'Rol no válido' };
    campos.role = r;
  }
  /* Un técnico es técnico: `can_tech` es el permiso de que jefatura o un
     admin además tomen servicios, y en un tech no significa nada. */
  if (d.can_tech !== undefined) campos.can_tech = (campos.role || '') !== 'tech' && d.can_tech === true;
  if (d.permissions !== undefined && d.permissions && typeof d.permissions === 'object') {
    const p = {};
    for (const k of Object.keys(d.permissions)) p[String(k).slice(0, 60)] = d.permissions[k] === true;
    campos.permissions = p;
  }
  if (d.must_change_password !== undefined) campos.must_change_password = d.must_change_password === true;
  if (!Object.keys(campos).length) return { error: 'No hay nada que guardar' };
  return { campos };
}

/* ¿Cuántos admins activos quedarían si sacamos a este? Una app de taller sin
   administrador es un taller sin llave del pañol: nadie puede crear cuentas,
   resetear contraseñas ni arreglar el desastre desde adentro. */
async function quedanAdmins(excepto) {
  const filas = await sb('users?select=id&role=eq.admin&is_active=is.true&id=neq.' + excepto);
  return (filas || []).length;
}

async function limpiarFallos(uname) {
  try { await sb('login_attempts?clave=eq.' + encodeURIComponent('u:' + uname), 'DELETE'); } catch (_) {}
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return J(204, {});
  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (_) {}
  const accion = body.accion || 'login';

  try {
    /* La acción `migrar` se eliminó. Tenía un fallo: comparaba
       `body.k !== process.env.MIGRACION_TOKEN` y, al no existir esa variable,
       una petición sin token daba `undefined !== undefined` = false y pasaba
       el control. Ya no hace falta: el barrido automático la reemplazó. */

    /* ── Login ── */
    if (accion === 'login') {
      const uname = String(body.username || '').trim().toLowerCase();
      const clave = String(body.password || '');
      if (!uname || !clave) return J(400, { error: 'Faltan usuario o contraseña' });

      const ip = ipDe(event);
      const freno = await frenado(uname, ip);
      if (freno) {
        return J(429, { error: 'Demasiados intentos fallidos. Espera ' + FRENO_VENTANA_MIN + ' minutos y vuelve a intentar.' });
      }

      const rows = await sb('users?select=*&username=eq.' + encodeURIComponent(uname) + '&limit=1');
      const u = (rows || [])[0];
      /* mismo mensaje y mismo costo si el usuario no existe: no revelar cuáles sí */
      if (!u) { hashear(clave); await anotarFallo(uname, ip, false); return J(401, { error: 'Usuario o contraseña incorrectos' }); }

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
        if (!verificar(clave, guardado)) {
          await anotarFallo(uname, ip, true);
          return J(401, { error: 'Usuario o contraseña incorrectos' });
        }
      } else {
        /* transición: todavía sin hash. Se valida contra el valor antiguo y se
           crea el hash en el acto, para que el próximo login ya sea seguro. */
        /* sin hash y sin columna antigua no hay con qué comparar */
        if (!('password' in u) || !u.password || String(u.password) !== clave) {
          await anotarFallo(uname, ip, true);
          return J(401, { error: 'Usuario o contraseña incorrectos' });
        }
        if (secretosDisponibles) {
          try { await sb('user_secrets', 'POST', { user_id: u.id, password_hash: hashear(clave) }); } catch (_) {}
        }
      }
      /* ── Cuenta dada de baja ────────────────────────────────────────────
         Se comprueba DESPUÉS de validar la contraseña, a propósito. Si se
         respondiera "cuenta desactivada" antes, cualquiera podría averiguar
         quién trabaja acá y quién ya no probando nombres. Así, para enterarse
         hay que saber la contraseña — o sea, ser la persona. Y a esa persona
         sí le sirve un mensaje claro en vez de "contraseña incorrecta", que la
         dejaría reintentando y llamando a jefatura. */
      if (u.is_active === false) {
        return J(403, { error: 'Tu cuenta está desactivada. Habla con jefatura si crees que es un error.' });
      }

      /* Entró bien: se borra su cuenta de fallidos para que un olvido de la
         mañana no lo deje frenado en la tarde. */
      await limpiarFallos(uname);
      /* El barrido de migración se retiró del login: la columna `password` ya
         no existe, así que solo agregaba una consulta fallida a cada ingreso. */
      return J(200, {
        ok: true,
        user: limpiar(u),
        seguro: !!guardado,
        /* prueba de identidad para las acciones que escriben contraseñas */
        token: firmar(u.id, u.role)
      });
    }

    /* ── Cambio de contraseña (el propio usuario) ──
       Dos caminos válidos, y ninguno más:
         a) sabe su contraseña actual y la manda en `actual`;
         b) trae el token que se le entregó en el login de hace un rato.
       El camino (b) cubre el cambio obligado del primer ingreso, donde el
       navegador ya no conserva la clave temporal con la que acaba de entrar.
       Antes bastaba con que el usuario tuviera `must_change_password` activo:
       eso dejaba que cualquiera, sin credencial alguna, le pisara la clave a
       una cuenta recién reseteada. */
    if (accion === 'cambiar') {
      const uid = String(body.user_id || '');
      const actual = String(body.actual || ''), nueva = String(body.nueva || '');
      if (!uid || !nueva) return J(400, { error: 'Faltan datos' });

      const rows = await sb('users?select=id,must_change_password,is_active&id=eq.' + uid + '&limit=1');
      const u = (rows || [])[0];
      if (!u) return J(404, { error: 'Usuario no encontrado' });
      if (u.is_active === false) return J(403, { error: 'Cuenta desactivada' });

      /* Primero quién eres, después si lo que traes sirve. Al revés, un
         desconocido podría distinguir por el mensaje de error entre una cuenta
         que existe y una que no, o entre reglas que cumple y que no. */
      const ses = abrirToken(body.token);
      const conToken = !!(ses && ses.uid === uid);

      if (!conToken) {
        const sec = await sb('user_secrets?select=password_hash&user_id=eq.' + uid + '&limit=1');
        const guardado = ((sec || [])[0] || {}).password_hash;
        if (!guardado || !actual || !verificar(actual, guardado)) {
          return J(401, { error: 'La contraseña actual no coincide' });
        }
      }

      if (nueva.length < CLAVE_MIN) return J(400, { error: 'La contraseña nueva debe tener al menos ' + CLAVE_MIN + ' caracteres' });

      await sb('user_secrets', 'POST', { user_id: uid, password_hash: hashear(nueva) });

      /* Correo personal de recuperación. Se acepta en el mismo paso que el
         cambio de contraseña porque ese es el momento en que la persona ya
         probó ser quien dice: pedirlo por separado sería otra pantalla que
         nadie completa. Solo se guarda si la columna existe. */
      const cambios = { must_change_password: false };
      const correo = String(body.recovery_email || '').trim().toLowerCase();
      if (correo && /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(correo)) cambios.recovery_email = correo;
      try {
        await sb('users?id=eq.' + uid, 'PATCH', cambios);
      } catch (e) {
        /* que el correo falle (columna ausente, o ya usado por otra cuenta) no
           puede impedir el cambio de contraseña, que es lo importante */
        await sb('users?id=eq.' + uid, 'PATCH', { must_change_password: false });
        return J(200, { ok: true, token: firmar(uid, null), aviso_correo: 'No se pudo guardar el correo de recuperación.' });
      }
      /* token nuevo: la sesión sigue viva con la contraseña recién puesta */
      return J(200, { ok: true, token: firmar(uid, null) });
    }

    /* ── Fijar contraseña (alta o reseteo por administrador) ──
       Exige token de admin. Sin esto quedaba completamente abierto: los uuid
       de `users` son legibles con la llave anónima, así que bastaba pedir el
       del admin y fijarle una contraseña conocida para entrar como él. */
    if (accion === 'set') {
      const ses = abrirToken(body.token);
      if (!ses) return J(401, { error: 'Sesión no válida. Vuelve a entrar.' });
      /* el rol se relee de la base: el del token es solo una pista */
      const quien = await sb('users?select=id,role,is_active&id=eq.' + ses.uid + '&limit=1');
      const admin = (quien || [])[0];
      if (!admin || admin.role !== 'admin') return J(403, { error: 'Solo un administrador puede fijar contraseñas' });
      /* Un admin dado de baja conserva su token hasta 12 h. No debe poder
         usarlo para nada. */
      if (admin.is_active === false) return J(403, { error: 'Cuenta desactivada' });

      const uid = String(body.user_id || '');
      const nueva = String(body.nueva || '');
      if (!uid || !nueva) return J(400, { error: 'Faltan datos' });
      if (nueva.length < CLAVE_MIN) return J(400, { error: 'La contraseña debe tener al menos ' + CLAVE_MIN + ' caracteres' });
      const rows = await sb('users?select=id,is_active&id=eq.' + uid + '&limit=1');
      const destino = (rows || [])[0];
      if (!destino) return J(404, { error: 'Usuario no encontrado' });
      if (destino.is_active === false) return J(409, { error: 'Esa cuenta está dada de baja. Reactívala antes de darle una contraseña.' });
      await sb('user_secrets', 'POST', { user_id: uid, password_hash: hashear(nueva) });
      if (body.forzar_cambio !== false) {
        try { await sb('users?id=eq.' + uid, 'PATCH', { must_change_password: true }); } catch (_) {}
      }
      console.log('set: ' + admin.id + ' fijó la contraseña de ' + uid);
      return J(200, { ok: true });
    }

    /* ── Pedir el enlace de recuperación ────────────────────────────────
       La respuesta es SIEMPRE la misma, exista o no la cuenta, esté activa o
       no, tenga correo registrado o no. Si dijera "ese usuario no existe",
       cualquiera podría averiguar quién trabaja acá probando nombres — y con
       la lista de nombres, atacar cuentas concretas. */
    if (accion === 'recuperar') {
      const id = String(body.identificador || '').trim().toLowerCase();
      const ip = ipDe(event);
      const MISMA = { ok: true, mensaje: 'Si esa cuenta existe y tiene un correo registrado, te va a llegar un enlace en unos minutos. Revisa también la carpeta de spam.' };
      if (!id) return J(400, { error: 'Escribe tu usuario o tu correo' });

      /* mismo freno que el login: que no sirva para sondear cuentas en masa */
      if (await frenado('rec:' + id, ip)) {
        return J(429, { error: 'Demasiados intentos. Espera ' + FRENO_VENTANA_MIN + ' minutos.' });
      }
      /* Acá SÍ se le cuenta a la IP, al revés que en el login. Un usuario
         real equivocándose de contraseña es cosa de todos los días; pedir
         recuperación es rarísimo. Sin contarlo por IP, alguien podría disparar
         correos de recuperación a los 15 en bucle y llenarles la bandeja. */
      await anotarFallo('rec:' + id, ip, false);

      let u = null;
      try {
        const campo = id.indexOf('@') >= 0 ? 'recovery_email' : 'username';
        const rows = await sb('users?select=id,name,username,role,recovery_email,is_active&' +
                              campo + '=eq.' + encodeURIComponent(id) + '&limit=1');
        u = (rows || [])[0] || null;
      } catch (_) {}

      if (!u || u.is_active === false || !u.recovery_email) return J(200, MISMA);

      const sec = await sb('user_secrets?select=password_hash&user_id=eq.' + u.id + '&limit=1');
      const guardado = ((sec || [])[0] || {}).password_hash;
      if (!guardado) return J(200, MISMA);

      const enlace = baseDe(event) + '/?r=' + encodeURIComponent(firmarRecup(u.id, guardado) || '');
      const { html, texto } = correoRecuperacion(u.name, enlace);
      await enviarCorreo(u.recovery_email, 'Recuperar tu contraseña · Rosso OPS', html, texto);
      console.log('recuperar: enlace enviado a la cuenta ' + u.id);
      return J(200, MISMA);
    }

    /* ── Comprobar el enlace antes de mostrar el formulario ──────────────
       Para no hacer que alguien escriba una contraseña nueva dos veces y
       recién ahí enterarse de que el enlace venció. */
    if (accion === 'revisar_enlace') {
      const uid = await abrirRecup(body.t);
      if (!uid) return J(200, { ok: false, motivo: 'El enlace venció o ya se usó. Pide uno nuevo.' });
      const rows = await sb('users?select=name,username&id=eq.' + uid + '&limit=1');
      const u = (rows || [])[0] || {};
      return J(200, { ok: true, nombre: u.name || null, usuario: u.username || null });
    }

    /* ── Restablecer con el enlace ── */
    if (accion === 'restablecer') {
      const nueva = String(body.nueva || '');
      const uid = await abrirRecup(body.t);
      /* la validez del enlace se comprueba ANTES que el largo: un desconocido
         con un token inventado no debe distinguir "enlace malo" de "clave
         corta" */
      if (!uid) return J(401, { error: 'El enlace venció o ya se usó. Pide uno nuevo.' });
      if (nueva.length < CLAVE_MIN) return J(400, { error: 'La contraseña nueva debe tener al menos ' + CLAVE_MIN + ' caracteres' });

      const rows = await sb('users?select=id,name,username,role,is_active&id=eq.' + uid + '&limit=1');
      const u = (rows || [])[0];
      if (!u || u.is_active === false) return J(403, { error: 'Cuenta desactivada' });

      await sb('user_secrets', 'POST', { user_id: uid, password_hash: hashear(nueva) });
      await sb('users?id=eq.' + uid, 'PATCH', { must_change_password: false });
      await limpiarFallos(u.username);

      /* Aviso cruzado entre administradores: son las dos cuentas que pueden
         todo, y enterarse de que la clave de la otra se recuperó cuesta un
         correo. Nunca puede tumbar el restablecimiento. */
      if (u.role === 'admin') {
        try {
          const otros = await sb('users?select=name,recovery_email&role=eq.admin&is_active=eq.true&id=neq.' + uid);
          for (const o of (otros || [])) {
            if (!o.recovery_email) continue;
            await enviarCorreo(o.recovery_email, 'Aviso: se recuperó la contraseña de un administrador',
              '<p>Se acaba de recuperar por correo la contraseña de <b>' + esc(u.name || u.username) + '</b>, que es cuenta de administrador en Rosso OPS.</p>' +
              '<p>Si fue esa persona, no hay nada que hacer. Si no, entra y cámbiala.</p>',
              'Se recuperó por correo la contraseña de ' + (u.name || u.username) + ' (administrador). Si no fue esa persona, entra y cámbiala.');
          }
        } catch (_) {}
      }
      console.log('restablecer: contraseña nueva para ' + uid);
      return J(200, { ok: true, usuario: u.username });
    }

    /* ── Gestión de equipo ─────────────────────────────────────────────────
       Antes esto lo hacía el navegador: `users.insert()`, `users.update()` con
       el rol adentro, y `users.delete()`, todo con la llave anónima que va
       incrustada en el HTML público. El panel se le mostraba solo a un admin,
       pero la pantalla que esconde un botón no es un candado: PostgREST le
       contesta igual a quien llame directo. Cualquiera con el código fuente a
       la vista podía ponerse `role: admin`, crear una cuenta nueva o borrar a
       los quince.

       Ahora la base ya no acepta esas escrituras desde el navegador (v2.9:
       revoke insert/update/delete, y update devuelto columna por columna solo
       para lo inofensivo). Estas tres acciones son la puerta de reemplazo, y
       tienen el mismo portero que `set`: token de sesión firmado, rol releído
       desde la base —no el del token— y cuenta vigente. */
    if (accion === 'equipo_crear' || accion === 'equipo_editar' || accion === 'equipo_baja') {
      const admin = await exigirAdmin(body.token);
      if (admin.error) return J(admin.code, { error: admin.error });

      if (accion === 'equipo_crear') {
        const d = camposEquipo(body.datos);
        if (d.error) return J(400, { error: d.error });
        if (!d.campos.username) return J(400, { error: 'Falta el usuario' });
        if (!d.campos.name) return J(400, { error: 'Falta el nombre' });
        const clave = String(body.clave || '');
        if (clave.length < CLAVE_MIN) return J(400, { error: 'La contraseña debe tener al menos ' + CLAVE_MIN + ' caracteres' });

        const repe = await sb('users?select=id,is_active&username=eq.' + encodeURIComponent(d.campos.username) + '&limit=1');
        if ((repe || [])[0]) {
          return J(409, { error: (repe[0].is_active === false)
            ? 'Ese usuario ya existe pero está dado de baja. Reactívalo en vez de crearlo de nuevo.'
            : 'Ese nombre de usuario ya está ocupado.' });
        }

        d.campos.must_change_password = true;   /* siempre, sin excepción */
        d.campos.is_active = true;
        const creado = await sbRep('users', 'POST', d.campos);
        const nuevo = (creado || [])[0];
        if (!nuevo || !nuevo.id) return J(500, { error: 'No se pudo crear la cuenta' });
        await sb('user_secrets', 'POST', { user_id: nuevo.id, password_hash: hashear(clave) });
        console.log('equipo_crear: ' + admin.id + ' creó ' + nuevo.username + ' (' + nuevo.role + ')');
        return J(200, { ok: true, user: limpiar(nuevo) });
      }

      const uid = String(body.user_id || '');
      if (!uid) return J(400, { error: 'Falta el usuario' });
      const rows = await sb('users?select=id,name,username,role,is_active&id=eq.' + uid + '&limit=1');
      const destino = (rows || [])[0];
      if (!destino) return J(404, { error: 'Usuario no encontrado' });

      if (accion === 'equipo_editar') {
        const d = camposEquipo(body.datos);
        if (d.error) return J(400, { error: d.error });
        /* Quitarse a uno mismo el rol de admin deja el panel sin dueño y no
           hay forma de volver desde la app. Se bloquea acá y no en el
           navegador, que es donde importa. */
        if (uid === admin.id && d.campos.role && d.campos.role !== 'admin') {
          return J(409, { error: 'No puedes quitarte a ti mismo el rol de administrador. Pídeselo al otro admin.' });
        }
        if (d.campos.role && d.campos.role !== 'admin' && destino.role === 'admin') {
          const q = await quedanAdmins(uid);
          if (q === 0) return J(409, { error: 'Es el último administrador activo. Nombra otro antes de bajarle el rol.' });
        }
        if (d.campos.username && d.campos.username !== destino.username) {
          const repe = await sb('users?select=id&username=eq.' + encodeURIComponent(d.campos.username) + '&id=neq.' + uid + '&limit=1');
          if ((repe || [])[0]) return J(409, { error: 'Ese nombre de usuario ya está ocupado.' });
        }
        await sb('users?id=eq.' + uid, 'PATCH', d.campos);
        console.log('equipo_editar: ' + admin.id + ' editó ' + destino.username + ' → ' + JSON.stringify(Object.keys(d.campos)));
        return J(200, { ok: true });
      }

      /* equipo_baja: reemplaza al borrado. Borrar la fila se lleva por delante
         el historial de servicios de la persona, que es justo lo que no hay
         que perder —es el registro de quién hizo cada trabajo—. Dar de baja
         cierra el acceso y deja los datos donde están. */
      const reactivar = body.reactivar === true;
      if (!reactivar) {
        if (uid === admin.id) return J(409, { error: 'No puedes darte de baja a ti mismo.' });
        if (destino.role === 'admin') {
          const q = await quedanAdmins(uid);
          if (q === 0) return J(409, { error: 'Es el último administrador activo. Nombra otro antes de darlo de baja.' });
        }
      }
      await sb('users?id=eq.' + uid, 'PATCH', reactivar
        ? { is_active: true,  baja_el: null, baja_por: null, must_change_password: true }
        : { is_active: false, baja_el: new Date().toISOString(), baja_por: admin.username || admin.id });
      console.log('equipo_baja: ' + admin.id + (reactivar ? ' reactivó ' : ' dio de baja a ') + destino.username);
      return J(200, { ok: true, is_active: reactivar });
    }

    /* Las acciones de diagnóstico `verificar` y `estado` se retiraron: la
       migración terminó, la columna de texto plano ya no existe, y mientras
       existieran cualquiera podía preguntarle al servidor cuántas cuentas hay
       y cuáles están sin hash. Una función pública responde lo mínimo. */

    return J(400, { error: 'acción desconocida' });
  } catch (e) {
    return J(500, { error: String(e.message || e).slice(0, 300) });
  }
};
