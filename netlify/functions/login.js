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

    /* Las acciones de diagnóstico `verificar` y `estado` se retiraron: la
       migración terminó, la columna de texto plano ya no existe, y mientras
       existieran cualquiera podía preguntarle al servidor cuántas cuentas hay
       y cuáles están sin hash. Una función pública responde lo mínimo. */

    return J(400, { error: 'acción desconocida' });
  } catch (e) {
    return J(500, { error: String(e.message || e).slice(0, 300) });
  }
};
