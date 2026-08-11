const assert = require('assert');
const { evaluate } = require('./server.js');

function safeBase() {
  return {
    target: 'preview',
    event: 'pull_request',
    ref: 'refs/heads/feature/x',
    workflow: {
      trigger: 'pull_request',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: 'actions', name: 'checkout', ref: 'v4' },
        { owner: 'docker', name: 'build-push-action', ref: 'a'.repeat(40) }
      ]
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'buildkit',
      criticalVulnerabilities: 0,
      digestPinned: true
    }
  };
}

{
  const v = evaluate(safeBase());
  assert.deepStrictEqual(v, [], 'safe preview should have no violations');
}

{
  const b = safeBase();
  b.workflow.permissions['id-token'] = 'write';
  const v = evaluate(b);
  assert(v.includes('EXCESS_PERMISSION'));
}

{
  const b = safeBase();
  b.workflow.permissions.actions = 'read';
  const v = evaluate(b);
  assert(v.includes('EXCESS_PERMISSION'));
}

{
  const b = safeBase();
  b.workflow.trigger = 'pull_request_target';
  const v = evaluate(b);
  assert(v.includes('UNSAFE_PR_TRIGGER'));
}

{
  const b = safeBase();
  b.workflow.matrixComplete = false;
  const v = evaluate(b);
  assert(v.includes('TESTS_INCOMPLETE'));
}

{
  const b = safeBase();
  b.workflow.failFast = true;
  const v = evaluate(b);
  assert(v.includes('TESTS_INCOMPLETE'));
}

{
  const b = safeBase();
  b.workflow.actions.push({ owner: 'someorg', name: 'foo', ref: 'v1.0.0' });
  const v = evaluate(b);
  assert(v.includes('MUTABLE_ACTION'));
}

{
  const b = safeBase();
  b.image.multiStage = false;
  const v = evaluate(b);
  assert(v.includes('SINGLE_STAGE_IMAGE'));
}

{
  const b = safeBase();
  b.image.runsAsRoot = true;
  const v = evaluate(b);
  assert(v.includes('ROOT_RUNTIME'));
}

{
  const b = safeBase();
  b.image.secretMode = 'copy';
  const v = evaluate(b);
  assert(v.includes('SECRET_IN_LAYER'));
}

{
  const b = safeBase();
  b.image.criticalVulnerabilities = 2;
  const v = evaluate(b);
  assert(v.includes('CRITICAL_CVE'));
}

{
  const b = safeBase();
  b.image.digestPinned = false;
  const v = evaluate(b);
  assert(v.includes('UNPINNED_IMAGE'));
}

{
  const b = safeBase();
  b.target = 'production';
  b.event = 'push';
  b.ref = 'refs/heads/main';
  b.workflow.trigger = 'push';
  b.workflow.environmentApproval = true;
  const v = evaluate(b);
  assert.deepStrictEqual(v, []);
}

{
  const b = safeBase();
  b.target = 'production';
  b.event = 'push';
  b.ref = 'refs/heads/develop';
  b.workflow.trigger = 'push';
  b.workflow.environmentApproval = true;
  const v = evaluate(b);
  assert(v.includes('INVALID_PRODUCTION_REF'));
}

{
  const b = safeBase();
  b.target = 'production';
  b.event = 'push';
  b.ref = 'refs/heads/main';
  b.workflow.trigger = 'push';
  b.workflow.environmentApproval = false;
  const v = evaluate(b);
  assert(v.includes('APPROVAL_REQUIRED'));
}

{
  const b = safeBase();
  b.workflow.permissions['id-token'] = 'write';
  b.image.runsAsRoot = true;
  b.image.digestPinned = false;
  const v = evaluate(b);
  assert(v.includes('EXCESS_PERMISSION'));
  assert(v.includes('ROOT_RUNTIME'));
  assert(v.includes('UNPINNED_IMAGE'));
}

console.log('All tests passed.');
