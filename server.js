const http = require('http');

const SHA40 = /^[0-9a-f]{40}$/;

function evaluate(rawBody) {
  const violations = [];

  // Guard against null, arrays, primitives, or missing body
  const body = (rawBody && typeof rawBody === 'object' && !Array.isArray(rawBody)) ? rawBody : {};

  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const wf = (body.workflow && typeof body.workflow === 'object') ? body.workflow : {};
  const perms = (wf.permissions && typeof wf.permissions === 'object') ? wf.permissions : {};
  const actions = Array.isArray(wf.actions) ? wf.actions : [];
  const img = (body.image && typeof body.image === 'object') ? body.image : {};

  // Permissions: exactly contents:read, packages:write, id-token:none, no extras
  const requiredPerms = { contents: 'read', packages: 'write', 'id-token': 'none' };
  const permKeys = Object.keys(perms);
  const requiredKeys = Object.keys(requiredPerms);
  let permsOk = permKeys.length === requiredKeys.length;
  if (permsOk) {
    for (const k of requiredKeys) {
      if (perms[k] !== requiredPerms[k]) { permsOk = false; break; }
    }
  }
  if (!permsOk) violations.push('EXCESS_PERMISSION');

  // PR safety
  if (wf.trigger === 'pull_request_target') {
    violations.push('UNSAFE_PR_TRIGGER');
  }
  if (event === 'pull_request' && wf.trigger !== 'pull_request') {
    if (!violations.includes('UNSAFE_PR_TRIGGER')) violations.push('UNSAFE_PR_TRIGGER');
  }
  if (wf.testsPassed !== true || wf.matrixComplete !== true || wf.failFast !== false) {
    violations.push('TESTS_INCOMPLETE');
  }

  // Action pinning
  let mutable = false;
  for (const a of actions) {
    if (!a || typeof a !== 'object') { mutable = true; continue; }
    if (a.owner === 'actions') {
      continue; // version tag allowed
    }
    if (!SHA40.test(a.ref || '')) {
      mutable = true;
    }
  }
  if (mutable) violations.push('MUTABLE_ACTION');

  // Image checks
  if (img.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (img.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (!(img.secretMode === 'none' || img.secretMode === 'buildkit')) {
    violations.push('SECRET_IN_LAYER');
  }
  if (!(Number(img.criticalVulnerabilities) === 0)) violations.push('CRITICAL_CVE');
  if (img.digestPinned !== true) violations.push('UNPINNED_IMAGE');

  // Production additional requirements
  if (target === 'production') {
    if (event !== 'push' || ref !== 'refs/heads/main') {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (wf.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return violations;
}

function normalizePath(url) {
  if (!url) return url;
  const withoutQuery = url.split('?')[0];
  // strip trailing slash (except root)
  if (withoutQuery.length > 1 && withoutQuery.endsWith('/')) {
    return withoutQuery.slice(0, -1);
  }
  return withoutQuery;
}

const server = http.createServer((req, res) => {
  const path = normalizePath(req.url);

  if (req.method === 'POST' && path === '/release-gate') {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try {
        let body = {};
        if (data && data.trim().length > 0) {
          body = JSON.parse(data);
        }
        const violations = evaluate(body);
        const decision = violations.length === 0 ? 'promote' : 'block';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ decision, violations }));
      } catch (err) {
        // Never let an exception crash the process or hang the request
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ decision: 'block', violations: ['INVALID_REQUEST'] }));
      }
    });
    req.on('error', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ decision: 'block', violations: ['INVALID_REQUEST'] }));
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  }
});

// Catch any unexpected error so the whole process never dies
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Release gate listening on port ${PORT}`);
  });
}

module.exports = { evaluate, server };
