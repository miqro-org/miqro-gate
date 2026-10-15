import { test, expect, type Page } from '@playwright/test';

/**
 * /app/my-mcp「我的 MCP 接入」（ADR-0028 选项 A 自助面, issue #32）——真实浏览器里的
 * 路由与交互契约：空态分流、一次性明文、工具按需展开、以及 #1144 那类「离开本页后
 * 下一个路由渲染成空 outlet」的回归。API 全部 mock，不需要后端。
 */

const USER = {
  id: '0190-0000-0000-0002',
  username: 'alice',
  displayName: 'Alice',
  role: 'USER',
  mustChangePassword: false,
};

const CREDENTIAL = {
  issued: true,
  consumerId: '0190-0000-0000-3001',
  name: 'alice@portal',
  keyPrefix: 'mqk_api_1025b193',
  status: 'ACTIVE',
  capabilities: ['mcp:call'],
  createdAt: '2026-10-14T08:21:19Z',
  expiresAt: null,
};

const SERVICE = {
  serviceId: '0190-0000-0000-4001',
  name: 'slurm-mcp-local',
  description: '本机部署的 Agent-MCP',
  status: 'ONLINE',
  mcpUrl: 'https://gateway.test/mcpservers/slurm-mcp-local/mcp',
  sseUrl: 'https://gateway.test/mcpservers/slurm-mcp-local/sse',
  tools: [
    { toolId: 't1', toolName: 'check_job_status', description: '查询作业状态' },
    { toolId: 't2', toolName: 'submit_slurm_job', description: '提交作业' },
  ],
};

const HINT_NOT_ISSUED =
  '先签发你的 MCP 凭据；可用范围由管理员按你的消费者授权，签发后这里会列出可用服务。';

/** Mocks the /me surface; `issued` flips to true once the issue endpoint is hit. */
async function mockMeSurface(page: Page, initialIssued: boolean) {
  let issued = initialIssued;
  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: USER }));
  // #36: 默认当作"该部署没有可导出的证书"；证书用例自己覆盖这条。
  await page.route('**/api/v1/me/gateway-certificate', (route) =>
    route.fulfill({ json: { available: false } }),
  );
  await page.route('**/api/v1/me/mcp-services', (route) =>
    route.fulfill({
      json: {
        credential: issued
          ? CREDENTIAL
          : { ...CREDENTIAL, issued: false, name: null, keyPrefix: null },
        authHint: '认证：Authorization: Bearer <消费者 API Key 或 JWT>',
        hint: issued ? null : HINT_NOT_ISSUED,
        services: issued ? [SERVICE] : [],
      },
    }),
  );
  await page.route('**/api/v1/me/mcp-credential', (route) => {
    issued = true;
    return route.fulfill({
      status: 201,
      json: {
        credential: CREDENTIAL,
        apiKey: 'mqk_api_1025b193_testsecretmaterial',
        shownOnce: true,
      },
    });
  });
}

test('未签发时给空态与签发入口，签发后明文只显示一次且需勾选才能关闭', async ({ page }) => {
  await mockMeSurface(page, false);

  await page.goto('/app/my-mcp');
  await expect(page.locator('.new-shell__content').locator('h1')).toContainText('我的 MCP 接入');
  await expect(page.getByTestId('mcp-credential-empty')).toContainText('还没有签发凭据');
  // 服务区空态与凭据区空态不同名（未签发 vs 未授权），文案来自后端 hint
  await expect(page.getByTestId('mcp-services-empty')).toContainText(HINT_NOT_ISSUED);

  await page.getByTestId('mcp-issue-empty').click();

  const dialog = page.getByTestId('mcp-key-dialog');
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId('mcp-key-value')).toContainText('mqk_api_1025b193_testsecret');
  const close = page.getByTestId('mcp-key-close');
  await expect(close).toBeDisabled();
  await page.locator('label.next-my-mcp__ack').click();
  await expect(close).toBeEnabled();
  await close.click();
  await expect(dialog).toBeHidden();
});

test('已签发：计数行来自接口、工具按需展开、配置片段用占位而非明文', async ({ page }) => {
  await mockMeSurface(page, true);

  await page.goto('/app/my-mcp');
  await expect(page.getByTestId('mcp-credential-name')).toHaveText('alice@portal');
  await expect(page.getByTestId('mcp-services-panel')).toContainText('共 1 个服务');
  await expect(page.getByTestId('mcp-service-slurm-mcp-local')).toContainText('2 个工具');
  // 未展开时工具名不在 DOM 里
  await expect(page.getByTestId('mcp-tool-check_job_status')).toHaveCount(0);
  await page.getByTestId('mcp-service-tools-slurm-mcp-local').click();
  await expect(page.getByTestId('mcp-tool-check_job_status')).toBeVisible();
  await expect(page.getByTestId('mcp-tool-submit_slurm_job')).toBeVisible();

  const snippet = page.getByTestId('mcp-config-snippet');
  await expect(snippet).toContainText('https://gateway.test/mcpservers/slurm-mcp-local/mcp');
  await expect(snippet).not.toContainText('mqk_api_1025b193_testsecret');
});

test('离开 /app/my-mcp 后下一个路由仍渲染（#1144 同类回归）', async ({ page }) => {
  await mockMeSurface(page, true);
  await page.route('**/api/v1/me/usage/summary*', (route) =>
    route.fulfill({ json: { totals: {}, rows: [] } }),
  );

  await page.goto('/app/my-mcp');
  await expect(page.getByTestId('mcp-credential-panel')).toBeVisible();

  await page.locator('.new-shell__nav-item', { hasText: '我的密钥' }).click();
  await expect(page).toHaveURL(/\/app\/keys/);
  const content = page.locator('.new-shell__content');
  const { html, childCount } = await content.evaluate((el) => ({
    html: el.innerHTML,
    childCount: el.childElementCount,
  }));
  expect(html).not.toBe('<!---->');
  expect(childCount).toBeGreaterThan(0);
  await expect(content.locator('h1').first()).toBeVisible();
});

test('#36: 自签部署给出可下载的网关证书与信任命令', async ({ page }) => {
  await mockMeSurface(page, true);
  // 覆盖默认的「没有证书」：这台网关是自签的
  await page.route('**/api/v1/me/gateway-certificate', (route) =>
    route.fulfill({
      json: {
        available: true,
        pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
        selfSigned: true,
        subject: 'CN=localhost',
        issuer: 'CN=localhost',
        fingerprintSha256: '4C:73:C5:83:C7:4F:36:66',
        notAfter: '2029-01-15T09:22:04Z',
        fileName: 'miqrogate-ca.pem',
      },
    }),
  );

  await page.goto('/app/my-mcp');
  const block = page.getByTestId('mcp-cert-block');
  await expect(block).toBeVisible();
  await expect(block).toContainText('自签证书');
  await expect(block).toContainText('4C:73:C5:83:C7:4F:36:66'); // 指纹可核对
  await expect(page.getByTestId('mcp-cert-command')).toContainText('NODE_EXTRA_CA_CERTS');
  await expect(page.getByTestId('mcp-cert-download')).toBeVisible();
});
