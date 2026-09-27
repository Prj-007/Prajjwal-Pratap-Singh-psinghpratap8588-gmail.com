// Console checks beyond ui.spec.js: the entries inside each card, per role.
// Same rule as ui.spec.js — present with data-state="unlocked", or absent.

import { test, expect } from '@playwright/test';

async function login(page, email) {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill('demo1234');
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

test.describe('people', () => {
  test('owner: rows, role pickers and suspend/remove on everyone but themself', async ({ page }) => {
    await login(page, 'dana@example.test');
    await page.getByTestId('nav-people').click();
    const rows = page.locator('[data-testid="user-row"]');
    await expect(rows).toHaveCount(5);
    await expect(page.locator('[data-testid="user-row"][data-user-id="usr_dana"] [data-testid="role-select"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="role-select"][data-state="unlocked"]')).toHaveCount(4);
    await expect(page.locator('[data-testid="suspend-user"]')).toHaveCount(4);
    await expect(page.getByTestId('invite-user')).toHaveCount(1);
  });

  test('viewer: rows only, no management entries', async ({ page }) => {
    await login(page, 'viewer@acme.test');
    await page.getByTestId('nav-people').click();
    await expect(page.locator('[data-testid="user-row"]')).toHaveCount(5);
    for (const id of ['invite-user', 'role-select', 'suspend-user', 'remove-user']) {
      await expect(page.getByTestId(id)).toHaveCount(0);
    }
  });

  test('admin: the role picker never offers owner or admin', async ({ page }) => {
    await login(page, 'admin@acme.test');
    await page.getByTestId('nav-people').click();
    const picker = page.locator('[data-testid="user-row"][data-user-id="usr_sam"] [data-testid="role-select"]');
    // Not a fixed list: the personalised database adds a role below admin, and it belongs here.
    await expect(picker.locator('option', { hasText: 'Operator' })).toHaveCount(1);
    await expect(picker.locator('option', { hasText: /^(Owner|Admin)$/ })).toHaveCount(0);
  });
});

test.describe('sessions and audit', () => {
  const live = (page) => page.locator('[data-testid="session-row"][data-session-id="ses_live_build_server"]');

  test('owner can stop someone else\'s live session (session:terminate on that device)', async ({ page }) => {
    await login(page, 'dana@example.test');
    await page.getByTestId('nav-sessions').click();
    await expect(live(page).getByTestId('stop-session')).toHaveCount(1);
    await expect(page.getByTestId('new-session')).toHaveCount(1);
  });

  test('operator can stop their own session', async ({ page }) => {
    await login(page, 'sam@example.test');
    await page.getByTestId('nav-sessions').click();
    await expect(live(page).getByTestId('stop-session')).toHaveCount(1);
  });

  test('audit lists events, denials included once one has happened', async ({ page, request }) => {
    const sam = await (await request.post('/v1/auth/login', { data: { email: 'sam@example.test', password: 'demo1234' } })).json();
    await request.get('/v1/orgs/org_acme/audit', { headers: { authorization: `Bearer ${sam.token}` } });   // 403, audited
    await login(page, 'dana@example.test');
    await page.getByTestId('nav-audit').click();
    await expect(page.locator('[data-testid="audit-row"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-row"][data-result="deny"]').first()).toBeVisible();
  });
});
