const http = require('http');

const SHA40 = /^[0-9a-f]{40}$/;

function evaluate(body) {
  const violations = [];

  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const wf = body.workflow || {};
  const perms = wf.permissions || {};
  const actions = wf.actions || [];
  const img = body.image || {};

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

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/release-gate') {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      let body;
      try {
        body = JSON.parse(data || '{}');
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ decision: 'block', violations: ['INVALID_REQUEST'] }));
        return;
      }
      const violations = evaluate(body);
      const decision = violations.length === 0 ? 'promote' : 'block';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ decision, violations }));
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  }
});

const PORT = process.env.PORT || 3000;

// Only start the server when this file is run directly (e.g. `node server.js`).
// When required by test.js, the server should NOT auto-start, otherwise the
// test process never exits.
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Release gate listening on port ${PORT}`);
  });
}

module.exports = { evaluate, server };
