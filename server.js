const express = require('express');
const app = express();
app.use(express.json());
const SHA_RE = /^[0-9a-f]{40}$/;

function evaluate(body) {
  const violations = [];
  const target = body?.target;
  const event = body?.event;
  const ref = body?.ref;
  const workflow = body?.workflow || {};
  const image = body?.image || {};
  const perms = workflow.permissions || {};
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
  const permKeys = Object.keys(perms);
  const idToken = perms['id-token'];
  const hasExtraKeys = permKeys.some(k => !['contents', 'packages', 'id-token'].includes(k));
  const permsOk =
    perms.contents === 'read' &&
    perms.packages === 'write' &&
    idToken === 'none' &&
    !hasExtraKeys &&
    permKeys.length === 3;
  if (!permsOk) violations.push('EXCESS_PERMISSION');

  if (event === 'pull_request') {
    const trigger = workflow.trigger;
    if (trigger !== 'pull_request') {
      violations.push('UNSAFE_PR_TRIGGER');
    }
    if (workflow.testsPassed !== true || workflow.matrixComplete !== true || workflow.failFast !== false) {
      violations.push('TESTS_INCOMPLETE');
    }
  } else {
    if (workflow.trigger === 'pull_request_target') {
      violations.push('UNSAFE_PR_TRIGGER');
    }
    if (workflow.testsPassed !== true || workflow.matrixComplete !== true || workflow.failFast !== false) {
      violations.push('TESTS_INCOMPLETE');
    }
  }

  let mutableActionFound = false;
  for (const a of actions) {
    const owner = a?.owner;
    const ref_ = a?.ref;
    if (owner === 'actions') continue;
    if (typeof ref_ !== 'string' || !SHA_RE.test(ref_)) {
      mutableActionFound = true;
    }
  }
  if (mutableActionFound) violations.push('MUTABLE_ACTION');

  if (image.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (image.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (!(image.secretMode === 'none' || image.secretMode === 'buildkit')) {
    violations.push('SECRET_IN_LAYER');
  }
  if (!(Number.isFinite(image.criticalVulnerabilities) && image.criticalVulnerabilities === 0)) {
    violations.push('CRITICAL_CVE');
  }
  if (image.digestPinned !== true) violations.push('UNPINNED_IMAGE');

  if (target === 'production') {
    if (!(event === 'push' && ref === 'refs/heads/main')) {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (workflow.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return violations;
}

app.post('/release-gate', (req, res) => {
  try {
    const violations = evaluate(req.body || {});
    const decision = violations.length === 0 ? 'promote' : 'block';
    res.status(200).json({ decision, violations });
  } catch (err) {
    res.status(200).json({ decision: 'block', violations: ['INVALID_REQUEST'] });
  }
});

app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'not found' });
});

process.on('uncaughtException', (err) => console.error('Uncaught exception:', err));
process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`release-gate listening on ${PORT}`));
}

module.exports = { evaluate, app };
