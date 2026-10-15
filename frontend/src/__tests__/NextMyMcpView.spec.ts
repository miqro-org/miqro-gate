import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { defineComponent } from 'vue';
import NextMyMcpView from '@/views/next/NextMyMcpView.vue';
import * as api from '@/api';
import { ApiError } from '@/api/http';
import type { McpCredentialView, MyMcpServiceView, MyMcpServicesView } from '@/types/generated-api';

vi.mock('@/api', () => ({
  myMcpServices: vi.fn(),
  myMcpCredential: vi.fn(),
  issueMyMcpCredential: vi.fn(),
  rotateMyMcpCredential: vi.fn(),
  revokeMyMcpCredential: vi.fn(),
  myGatewayCertificate: vi.fn(),
  saveGatewayCertificate: vi.fn(),
}));

const mockApi = vi.mocked(api);

/** UiSelect sits on radix-vue's pointer-driven popup, which jsdom can't drive
 *  deterministically — the stub turns "pick an option" into a click. */
const SelectStub = defineComponent({
  name: 'UiSelect',
  props: {
    modelValue: { type: String, default: '' },
    options: { type: Array, default: () => [] },
    label: { type: String, default: '' },
  },
  emits: ['update:modelValue'],
  setup(props, { emit }) {
    return { props, pick: (value: unknown) => emit('update:modelValue', value) };
  },
  template: `
    <div class="ui-select-stub">
      <button
        v-for="opt in props.options"
        :key="opt.value"
        type="button"
        class="stub-option"
        :class="{ selected: props.modelValue === opt.value }"
        @click="pick(opt.value)"
      >{{ opt.label }}</button>
    </div>
  `,
});

const credential = (overrides: Partial<McpCredentialView> = {}): McpCredentialView => ({
  issued: true,
  consumerId: '8ab9c6e2-f398-4f48-a005-8c068bb0305c',
  name: 'selfmcp@portal',
  keyPrefix: 'mqk_api_1025b193',
  status: 'ACTIVE',
  capabilities: ['mcp:call'],
  createdAt: '2026-10-14T08:21:19Z',
  ...overrides,
});

/** 未签发时真实响应里这些字段是 null；生成的类型只声明 `| undefined`
 *  （springdoc 不产出 nullable），所以夹具按类型写 undefined。 */
const notIssued: McpCredentialView = credential({
  issued: false,
  consumerId: undefined,
  name: undefined,
  keyPrefix: undefined,
  status: undefined,
  capabilities: undefined,
  createdAt: undefined,
});

const service = (overrides: Partial<MyMcpServiceView> = {}): MyMcpServiceView => ({
  serviceId: '7d8f432c-5ee5-4304-9d3e-f25373fdf0e9',
  name: 'slurm-mcp-local',
  description: '本机部署的 MCP（Slurm/HPC）',
  status: 'ONLINE',
  mcpUrl: 'https://gateway.test/mcpservers/slurm-mcp-local/mcp',
  sseUrl: 'https://gateway.test/mcpservers/slurm-mcp-local/sse',
  tools: [
    { toolId: 't1', toolName: 'check_job_status', description: '查询作业状态' },
    { toolId: 't2', toolName: 'submit_slurm_job', description: '提交作业' },
  ],
  ...overrides,
});

const view = (overrides: Partial<MyMcpServicesView> = {}): MyMcpServicesView => ({
  credential: credential(),
  authHint: '认证：Authorization: Bearer <消费者 API Key 或 JWT>',
  services: [service()],
  ...overrides,
});

const HINT_NOT_ISSUED =
  '先签发你的 MCP 凭据；可用范围由管理员按你的消费者授权，签发后这里会列出可用服务。';
const HINT_NOTHING_GRANTED =
  '你的凭据还没有被授权任何 MCP 服务；请联系管理员在「MCP 服务 → 访问控制」里为它授权。';

describe('NextMyMcpView', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.resetAllMocks();
    document.body.innerHTML = '';
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
    // 默认当作"没配置证书导出"：老用例不受影响，证书相关用例各自覆盖。
    mockApi.myGatewayCertificate.mockResolvedValue({ available: false } as never);
  });

  function mountView() {
    return mount(NextMyMcpView, {
      global: { plugins: [createPinia()], stubs: { UiSelect: SelectStub } },
    });
  }

  const closeBtn = () =>
    document.querySelector('[data-testid="mcp-key-close"]') as HTMLButtonElement;
  const ackBox = () => document.querySelector('[data-testid="mcp-key-ack"]') as HTMLInputElement;

  it('renders the credential metadata and the tools the backend returned', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-credential-name"]').text()).toBe('selfmcp@portal');
    expect(wrapper.find('[data-testid="mcp-credential-scope"]').text()).toBe('mcp:call');
    expect(wrapper.find('[data-testid="mcp-credential-status"]').text()).toContain('正常');
    expect(wrapper.find('[data-testid="mcp-service-slurm-mcp-local"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('2 个工具');
    // 未展开时不渲染工具清单（列表规模可控，也避免误导为「已授权=已看到全部」）
    expect(wrapper.find('[data-testid="mcp-tools"]').exists()).toBe(false);

    await wrapper.find('[data-testid="mcp-service-tools-slurm-mcp-local"]').trigger('click');
    expect(wrapper.find('[data-testid="mcp-tool-check_job_status"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="mcp-tool-submit_slurm_job"]').exists()).toBe(true);
    // 有工具时不出现「没授权」引导
    expect(wrapper.find('[data-testid="mcp-service-no-tools"]').exists()).toBe(false);
  });

  it('explains the service-visible-but-no-tools case instead of only showing "0 个工具"', async () => {
    // 服务级放行、工具级一条都没授权：实测最常见的一种「看起来像坏了」的状态。
    mockApi.myMcpServices.mockResolvedValue(view({ services: [service({ tools: [] })] }));
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-service-slurm-mcp-local"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('0 个工具');
    const hint = wrapper.find('[data-testid="mcp-service-no-tools"]');
    expect(hint.exists()).toBe(true);
    expect(hint.text()).toContain('访问控制');
    // 0 工具时不渲染「查看工具」开关
    expect(wrapper.find('[data-testid="mcp-service-tools-slurm-mcp-local"]').exists()).toBe(false);
  });

  it('shows the upstream "no grants" answer as its own empty state (not "no data")', async () => {
    mockApi.myMcpServices.mockResolvedValue(view({ services: [], hint: HINT_NOTHING_GRANTED }));
    const wrapper = mountView();
    await flushPromises();

    const empty = wrapper.find('[data-testid="mcp-services-empty"]');
    expect(empty.text()).toContain('还没有被授权任何服务');
    // 文案直接用后端给的 hint：它说的下一步是「找管理员授权」，而不是「没有数据」
    expect(empty.text()).toContain(HINT_NOTHING_GRANTED);
    // 已签发时不再出现签发入口
    expect(wrapper.find('[data-testid="mcp-issue"]').exists()).toBe(false);
  });

  it('before issuance the two empty states differ, and issuing reveals the key once', async () => {
    mockApi.myMcpServices
      .mockResolvedValueOnce(view({ credential: notIssued, services: [], hint: HINT_NOT_ISSUED }))
      .mockResolvedValue(view({ hint: '你的凭据还没有被授权任何 MCP 服务；请联系管理员。' }));
    mockApi.issueMyMcpCredential.mockResolvedValue({
      credential: credential(),
      apiKey: 'mqk_api_1025b193_1025b1930e8bffe77ec436e6934fb293',
      shownOnce: true,
    });

    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-credential-empty"]').text()).toContain('还没有签发凭据');
    // 服务区的空态与凭据区不同名：「还没签发」vs「没被授权」
    expect(wrapper.find('[data-testid="mcp-services-empty"]').text()).toContain('还没有签发凭据');

    await wrapper.find('[data-testid="mcp-issue-empty"]').trigger('click');
    await flushPromises();

    expect(mockApi.issueMyMcpCredential).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).toContain(
      'mqk_api_1025b193_1025b1930e8bffe77ec436e6934fb293',
    );
    // 未勾选「我已保存」不允许关闭
    expect(closeBtn().disabled).toBe(true);
    ackBox().click();
    await flushPromises();
    expect(closeBtn().disabled).toBe(false);
  });

  it('rotate is gated behind a confirm and returns fresh key material for the same row', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.rotateMyMcpCredential.mockResolvedValue({
      credential: credential({ keyPrefix: 'mqk_api_df6eecee' }),
      apiKey: 'mqk_api_df6eecee_df6eecee14800c1f48a658e42d7a3c67',
      shownOnce: true,
    });

    const wrapper = mountView();
    await flushPromises();

    await wrapper.find('[data-testid="mcp-rotate"]').trigger('click');
    // 先弹确认，未确认前绝不能已经换过 Key
    expect(document.body.textContent).toContain('轮换 MCP 凭据？');
    expect(mockApi.rotateMyMcpCredential).not.toHaveBeenCalled();

    (document.querySelector('[data-testid="mcp-confirm-run"]') as HTMLButtonElement).click();
    await flushPromises();

    expect(mockApi.rotateMyMcpCredential).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).toContain(
      'mqk_api_df6eecee_df6eecee14800c1f48a658e42d7a3c67',
    );
    expect(document.body.textContent).toContain('凭据已轮换，旧 Key 已失效');
  });

  it('revoke is gated behind a confirm and refetches the view afterwards', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.revokeMyMcpCredential.mockResolvedValue(credential({ status: 'DISABLED' }));

    const wrapper = mountView();
    await flushPromises();
    expect(mockApi.myMcpServices).toHaveBeenCalledTimes(1);

    await wrapper.find('[data-testid="mcp-revoke"]').trigger('click');
    expect(document.body.textContent).toContain('撤销 MCP 凭据？');
    expect(mockApi.revokeMyMcpCredential).not.toHaveBeenCalled();

    (document.querySelector('[data-testid="mcp-confirm-run"]') as HTMLButtonElement).click();
    await flushPromises();

    expect(mockApi.revokeMyMcpCredential).toHaveBeenCalledTimes(1);
    expect(mockApi.myMcpServices).toHaveBeenCalledTimes(2);
  });

  it('cancel closes the confirm without touching the API', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    const wrapper = mountView();
    await flushPromises();

    await wrapper.find('[data-testid="mcp-revoke"]').trigger('click');
    (document.querySelector('[data-testid="mcp-confirm-cancel"]') as HTMLButtonElement).click();
    await flushPromises();

    expect(mockApi.revokeMyMcpCredential).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('撤销 MCP 凭据？');
  });

  it('builds a paste-ready client snippet from the backend URL and copies it', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    const wrapper = mountView();
    await flushPromises();

    const snippet = wrapper.find('[data-testid="mcp-config-snippet"]').text();
    expect(snippet).toContain('https://gateway.test/mcpservers/slurm-mcp-local/mcp');
    expect(snippet).toContain('Authorization');
    // 明文只显示一次，片段里只能是占位符
    expect(snippet).not.toContain('mqk_api_1025b193_');

    await wrapper.find('[data-testid="mcp-config-copy"]').trigger('click');
    await flushPromises();
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      expect.stringContaining('mcpServers'),
    );
  });

  it('surfaces a failed load with its requestId instead of an empty state', async () => {
    mockApi.myMcpServices.mockRejectedValue(
      new ApiError({
        type: 'about:blank',
        status: 500,
        code: 'INTERNAL',
        detail: '数据库不可用',
        requestId: 'req-500',
        title: 'Error',
      }),
    );
    const wrapper = mountView();
    await flushPromises();

    const alert = wrapper.find('[data-testid="mcp-load-error"]');
    expect(alert.text()).toContain('数据库不可用');
    expect(alert.text()).toContain('req-500');
  });

  // ---- #36：自签部署要把网关证书交到用户手里 ----

  const selfSigned = {
    available: true,
    pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    selfSigned: true,
    subject: 'CN=localhost',
    issuer: 'CN=localhost',
    fingerprintSha256: '60:BC:00:F9',
    notAfter: '2046-10-10T04:04:34Z',
    fileName: 'miqrogate-ca.pem',
  };

  it('#36 gives a self-signed deployment a download and the trust command', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.myGatewayCertificate.mockResolvedValue(selfSigned);
    const wrapper = mountView();
    await flushPromises();

    const block = wrapper.find('[data-testid="mcp-cert-block"]');
    expect(block.exists()).toBe(true);
    expect(block.text()).toContain('自签证书');
    expect(block.text()).toContain('60:BC:00:F9'); // 指纹可核对
    const command = wrapper.find('[data-testid="mcp-cert-command"]').text();
    expect(command).toContain('NODE_EXTRA_CA_CERTS');
    expect(command).toContain('miqrogate-ca.pem');
    // 给了可执行的方案，就不再重复那句没有出处的通用提示
    expect(wrapper.find('[data-testid="mcp-cert-generic-hint"]').exists()).toBe(false);

    await wrapper.find('[data-testid="mcp-cert-download"]').trigger('click');
    expect(mockApi.saveGatewayCertificate).toHaveBeenCalledWith(
      expect.objectContaining({ fileName: 'miqrogate-ca.pem', selfSigned: true }),
    );
  });

  it('#36 stays silent on a publicly trusted certificate (nothing for the user to do)', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.myGatewayCertificate.mockResolvedValue({
      ...selfSigned,
      selfSigned: false,
      issuer: 'CN=some-public-ca',
    });
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-cert-block"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="mcp-cert-generic-hint"]').exists()).toBe(false);
  });

  it('#36 falls back to the generic hint when the portal has no certificate to give', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.myGatewayCertificate.mockResolvedValue({ available: false } as never);
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-cert-block"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="mcp-cert-generic-hint"]').text()).toContain(
      'NODE_EXTRA_CA_CERTS',
    );
    // 证书只是附加能力：拿不到时页面其余部分照常
    expect(wrapper.find('[data-testid="mcp-credential-name"]').text()).toBe('selfmcp@portal');
  });

  it('#36 a failed certificate call never breaks the page', async () => {
    mockApi.myMcpServices.mockResolvedValue(view());
    mockApi.myGatewayCertificate.mockRejectedValue(new Error('boom'));
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="mcp-cert-block"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="mcp-load-error"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="mcp-credential-name"]').text()).toBe('selfmcp@portal');
  });
});
