
/*
 * custom-dast-rules.js
 *
 * OWASP ZAP - Active Rule Script
 *
 * DAST-01: Inyeccion de comandos controlada
 * DAST-02: Reflexion de entrada candidata a XSS
 * DAST-03: Path Traversal
 *
 * Reglas embebidas. No requiere dast-rules.json.
 *
 * Pendiente: validar ejecucion en la version de ZAP
 * utilizada por GitHub Actions.
 */

var URI = Java.type('org.apache.commons.httpclient.URI');

var RULES = [
  {
    id: 'CUSTOM-DAST-01',
    ref: '100101-1',
    name: 'DAST-01 Command Injection - Negative Control',
    path: '/api/diagnostic',
    paramName: 'command',
    attack: 'whoami; id',
    severity: 'critical',
    vulnerable_if: {
      json_field: 'executed',
      json_equals: true
    },
    safe_if: {
      status: 400,
      json_field: 'executed',
      json_equals: false
    },
    description:
      'La ejecucion arbitraria requiere evidencia adicional.'
  },
  {
    id: 'CUSTOM-DAST-02',
    ref: '100101-2',
    name: 'DAST-02 Reflected Input - XSS Candidate',
    path: '/api/search',
    paramName: 'q',
    attack: '<script>alert(1)</script>',
    severity: 'high',
    vulnerable_if: {
      status: 200,
      body_contains: '<script>alert(1)</script>'
    },
    description:
      'Entrada reflejada literalmente. No confirma ejecucion JavaScript.'
  },
  {
    id: 'CUSTOM-DAST-03',
    ref: '100101-3',
    name: 'DAST-03 Path Traversal',
    path: '/api/file',
    paramName: 'name',
    attack: '../appsettings.json',
    severity: 'high',
    vulnerable_if: {
      status: 200,
      body_contains: 'Logging'
    },
    description:
      'Acceso a contenido de configuracion mediante ruta relativa.'
  }
];

var executedRefs = {};

function log(message) {
  print('[custom-dast-rules] ' + message);
}

function buildAttackUri(baseUri, rule) {
  var scheme = baseUri.getScheme();
  var authority = baseUri.getAuthority();

  var query =
    rule.paramName + '=' +
    encodeURIComponent(rule.attack);

  var url =
    scheme + '://' +
    authority +
    rule.path + '?' +
    query;

  return new URI(url, true);
}

function sendAttack(as, baseMsg, rule) {
  var request = baseMsg.cloneRequest();

  request.getRequestHeader().setMethod('GET');

  request.getRequestHeader().setURI(
    buildAttackUri(
      baseMsg.getRequestHeader().getURI(),
      rule
    )
  );

  request.setRequestBody('');
  request.getRequestHeader().setContentLength(0);

  as.sendAndReceive(request, false, false);

  return request;
}

function safeJson(body) {
  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

function matchesCondition(condition, status, body) {
  if (!condition) {
    return false;
  }

  if (
    condition.status !== undefined &&
    status !== condition.status
  ) {
    return false;
  }

  if (
    condition.body_contains !== undefined &&
    body.indexOf(condition.body_contains) === -1
  ) {
    return false;
  }

  if (condition.json_field !== undefined) {
    var parsed = safeJson(body);

    if (!parsed) {
      return false;
    }

    var value = parsed[condition.json_field];

    if (
      condition.json_equals !== undefined &&
      value !== condition.json_equals
    ) {
      return false;
    }
  }

  return true;
}


function raiseFinding(as, rule, attackMsg, body) {
  var alert = as.newAlert();

  alert
    .setParam(rule.paramName)
    .setAttack(rule.attack)
    .setEvidence(body.substring(0, 500))
    .setOtherInfo(
      rule.id + ' - ' +
      rule.name + '. ' +
      rule.description
    )
    .setMessage(attackMsg)
    .raise();

  log(
    rule.id +
    ' -> alerta solicitada a ZAP para ' +
    rule.path
  );
}


function evaluateRule(as, msg, rule) {
  if (executedRefs[rule.ref]) {
    return;
  }

  log('Evaluando ' + rule.id + ' en ' + rule.path);

  var attackMsg;

  try {
    attackMsg = sendAttack(as, msg, rule);
  } catch (e) {
    log(
      rule.id +
      ' -> error enviando solicitud: ' +
      e
    );
    return;
  }

  executedRefs[rule.ref] = true;

  var status =
    attackMsg.getResponseHeader().getStatusCode();

  var body =
    attackMsg.getResponseBody().toString();

  var vulnerable = matchesCondition(
    rule.vulnerable_if,
    status,
    body
  );

  var confirmedSafe = matchesCondition(
    rule.safe_if,
    status,
    body
  );

  if (vulnerable) {
    try {
      raiseFinding(as, rule, attackMsg, body);
    } catch (e) {
      log(
        rule.id +
        ' -> error generando alerta: ' +
        e
      );
    }

    return;
  }

  if (confirmedSafe) {
    log(
      rule.id +
      ' -> control aprobado, HTTP ' +
      status +
      ', sin alerta'
    );

    return;
  }

  log(
    rule.id +
    ' -> resultado no concluyente, HTTP ' +
    status
  );
}

function scanNode(as, msg) {
  var path =
    msg.getRequestHeader().getURI().getPath();

  for (var i = 0; i < RULES.length; i++) {
    var rule = RULES[i];

    if (path === rule.path) {
      evaluateRule(as, msg, rule);
    }
  }
}

function scan(as, msg, param, value) {
  // La evaluacion de estos casos se realiza en scanNode.
}
