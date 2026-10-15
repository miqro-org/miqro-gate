<script setup lang="ts">
/**
 * NextMyMcpView — /app/my-mcp「我的 MCP 接入」（ADR-0028 选项 A 的用户可见面, issue #32）。
 *
 * 三段：① 凭据（签发 / 轮换 / 撤销，明文只显示一次，轮换原地换 Key 且保留授权）；
 * ② 可用的服务与工具——**范围完全由后端 ACL 决定**，本页不做任何本地过滤，
 * 列表里没有的就是调不通的；③ 可直接粘贴的客户端配置片段。
 *
 * 接口全部在 /api/v1/me/mcp-*（会话鉴权）；发现面与凭据共用同一个 GET，
 * 所以签发/轮换/撤销之后统一重新拉一次，页面状态只有一个来源。
 */
import { computed, onMounted, ref } from 'vue';
import * as api from '@/api';
import { ApiError } from '@/api/http';
import {
  UiButton,
  UiDialog,
  UiEmptyState,
  UiPageGuide,
  UiSelect,
  UiStatusBadge,
  toast,
} from '@/ui';
import { MY_MCP_GUIDE } from '@/content/pageGuides';
import { countWhenLoaded } from '@/utils/load-state';
import type {
  IssuedMcpCredential,
  McpCredentialView,
  MyMcpServiceView,
  MyMcpServicesView,
} from '@/types/generated-api';

const data = ref<MyMcpServicesView | null>(null);
const loading = ref(true);
const loadError = ref('');
const loadRequestId = ref('');

const busy = ref(false);
const actionError = ref('');
const actionRequestId = ref('');

const credential = computed<McpCredentialView | null>(() => data.value?.credential ?? null);
const issued = computed(() => credential.value?.issued === true);
const revoked = computed(() => credential.value?.status === 'DISABLED');
const services = computed<MyMcpServiceView[]>(() => data.value?.services ?? []);
const scopeLabel = computed(() => {
  const caps = credential.value?.capabilities;
  return caps?.length ? caps.join(' · ') : '未设作用域（等于全权限）';
});

// ---- 一次性明文（签发 / 轮换共用同一个弹窗） ----
const revealOpen = ref(false);
const revealData = ref<IssuedMcpCredential | null>(null);
const revealMode = ref<'issue' | 'rotate'>('issue');
const revealAcked = ref(false);
const revealCopied = ref(false);
const revealApiKey = computed(() => revealData.value?.apiKey ?? '');

// ---- 二次确认（轮换 / 撤销） ----
interface ConfirmState {
  title: string;
  body: string;
  confirmLabel: string;
  tone: 'danger' | 'primary';
  run: () => Promise<void>;
}
const confirmState = ref<ConfirmState | null>(null);

// ---- 客户端配置：多个服务时给选择器，默认第一个 ----
const configServiceId = ref('');
const configService = computed<MyMcpServiceView | null>(
  () =>
    services.value.find((s) => s.serviceId === configServiceId.value) ?? services.value[0] ?? null,
);
const serviceOptions = computed(() =>
  services.value.map((s) => ({ value: s.serviceId ?? '', label: s.name ?? '' })),
);
const configSnippet = computed(() => {
  const svc = configService.value;
  if (!svc) return '';
  return JSON.stringify(
    {
      mcpServers: {
        [svc.name ?? 'mcp']: {
          url: svc.mcpUrl ?? '',
          headers: { Authorization: 'Bearer <签发或轮换时展示的 mqk_api_…>' },
        },
      },
    },
    null,
    2,
  );
});

const expanded = ref<Record<string, boolean>>({});

function toMessage(e: unknown, fallback: string): { message: string; requestId: string } {
  if (e instanceof ApiError) return { message: e.message, requestId: e.requestId ?? '' };
  return { message: fallback, requestId: '' };
}

async function load() {
  loading.value = true;
  loadError.value = '';
  try {
    data.value = await api.myMcpServices();
    const first = services.value[0];
    if (!configServiceId.value && first) {
      configServiceId.value = first.serviceId ?? '';
    }
  } catch (e) {
    const info = toMessage(e, '加载失败，请稍后重试');
    loadError.value = info.message;
    loadRequestId.value = info.requestId;
  } finally {
    loading.value = false;
  }
}

/** 统一跑一次写操作：禁按钮、清上一次错误、失败落横幅 + toast。 */
async function run(fn: () => Promise<void>) {
  busy.value = true;
  actionError.value = '';
  try {
    await fn();
  } catch (e) {
    const info = toMessage(e, '操作失败，请稍后重试');
    actionError.value = info.message;
    actionRequestId.value = info.requestId;
    toast.error(info.message);
  } finally {
    busy.value = false;
  }
}

function openReveal(result: IssuedMcpCredential, mode: 'issue' | 'rotate') {
  revealData.value = result;
  revealMode.value = mode;
  revealAcked.value = false;
  revealCopied.value = false;
  revealOpen.value = true;
}

function issue() {
  return run(async () => {
    const result = await api.issueMyMcpCredential();
    await load();
    openReveal(result, 'issue');
  });
}

function rotate() {
  return run(async () => {
    const result = await api.rotateMyMcpCredential();
    await load();
    openReveal(result, 'rotate');
  });
}

function revoke() {
  return run(async () => {
    await api.revokeMyMcpCredential();
    await load();
    toast.success('凭据已撤销');
  });
}

function askRotate() {
  confirmState.value = {
    title: '轮换 MCP 凭据？',
    body: '轮换后旧 Key 立即失效，已经配好它的客户端要换成新 Key；管理员给你的授权不受影响（还是同一条消费者）。',
    confirmLabel: '轮换',
    tone: 'primary',
    run: rotate,
  };
}

function askRevoke() {
  confirmState.value = {
    title: '撤销 MCP 凭据？',
    body: '撤销后该凭据立即失效（MCP 面与计费面都按未知 Key 401）。管理员给你的授权仍然保留——之后重新签发或轮换即可恢复。',
    confirmLabel: '撤销',
    tone: 'danger',
    run: revoke,
  };
}

async function runConfirm() {
  const state = confirmState.value;
  if (!state) return;
  confirmState.value = null;
  await state.run();
}

async function copyText(text: string, okMessage: string) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast.success(okMessage);
  } catch {
    toast.error('复制失败，请手动选择复制');
  }
}

async function copyReveal() {
  await copyText(revealApiKey.value, '凭据已复制');
  revealCopied.value = true;
}

function toggle(serviceId?: string) {
  if (!serviceId) return;
  expanded.value = { ...expanded.value, [serviceId]: !expanded.value[serviceId] };
}

function formatTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

onMounted(load);
</script>

<template>
  <div class="ui-page next-my-mcp">
    <header class="ui-page-header">
      <div>
        <h1 class="ui-page-title">我的 MCP 接入</h1>
        <p class="ui-page-desc">
          自助签发你的 MCP 凭据，查看管理员已授权给你的服务与工具，并按给出的地址在客户端里接入。
        </p>
      </div>
      <div class="ui-page-actions">
        <UiButton
          v-if="!loading && !issued"
          variant="primary"
          :loading="busy"
          data-testid="mcp-issue"
          @click="issue"
        >
          签发我的 MCP 凭据
        </UiButton>
      </div>
    </header>

    <UiPageGuide :guide="MY_MCP_GUIDE" storage-key="my-mcp" />

    <div v-if="loadError" class="ui-alert ui-alert--error" data-testid="mcp-load-error">
      {{ loadError
      }}<span v-if="loadRequestId" class="ui-request-id"> requestId: {{ loadRequestId }}</span>
    </div>

    <div v-if="actionError" class="ui-alert ui-alert--error" data-testid="mcp-action-error">
      {{ actionError
      }}<span v-if="actionRequestId" class="ui-request-id"> requestId: {{ actionRequestId }}</span>
    </div>

    <!-- ① 凭据 -->
    <section class="ui-panel next-my-mcp__panel" data-testid="mcp-credential-panel">
      <div class="ui-panel-head">
        <h2 class="ui-panel-title">我的 MCP 凭据</h2>
        <div v-if="issued" class="next-my-mcp__head-actions">
          <UiButton
            variant="secondary"
            :disabled="busy"
            data-testid="mcp-rotate"
            @click="askRotate"
          >
            轮换凭据
          </UiButton>
          <UiButton variant="ghost" :disabled="busy" data-testid="mcp-revoke" @click="askRevoke">
            撤销
          </UiButton>
        </div>
      </div>
      <div class="ui-panel-body">
        <div v-if="loading" class="ui-skeleton next-my-mcp__skeleton" />
        <!-- 读取失败时两种状态都不成立（不是「没有凭据」，而是「不知道」）：
             此时什么都不画，页面顶部的错误横幅是唯一结论。 -->
        <div
          v-else-if="!loadError && !issued"
          class="next-my-mcp__empty"
          data-testid="mcp-credential-empty"
        >
          <p class="next-my-mcp__empty-title">还没有签发凭据</p>
          <p class="next-my-mcp__empty-desc">{{ data?.hint }}</p>
          <UiButton variant="primary" :loading="busy" data-testid="mcp-issue-empty" @click="issue">
            签发我的 MCP 凭据
          </UiButton>
        </div>
        <template v-else-if="!loadError">
          <dl class="next-my-mcp__kv" data-testid="mcp-credential-meta">
            <div>
              <dt>名称</dt>
              <dd class="ui-mono" data-testid="mcp-credential-name">{{ credential?.name }}</dd>
            </div>
            <div>
              <dt>Key 前缀</dt>
              <dd class="ui-mono">{{ credential?.keyPrefix }}</dd>
            </div>
            <div>
              <dt>作用域</dt>
              <dd class="ui-mono" data-testid="mcp-credential-scope">{{ scopeLabel }}</dd>
            </div>
            <div>
              <dt>状态</dt>
              <dd>
                <UiStatusBadge
                  :tone="revoked ? 'neutral' : 'success'"
                  :label="revoked ? '已撤销' : '正常'"
                  data-testid="mcp-credential-status"
                />
              </dd>
            </div>
            <div v-if="credential?.createdAt">
              <dt>签发时间</dt>
              <dd>{{ formatTime(credential.createdAt) }}</dd>
            </div>
          </dl>
          <p class="next-my-mcp__note">
            明文 Key 只在签发与轮换时各显示一次（服务端只存摘要）；轮换原地换
            Key、管理员给你的授权保留。怀疑泄露时先轮换、确认后再撤销。
          </p>
        </template>
      </div>
    </section>

    <!-- ② 可用的服务与工具 -->
    <section class="ui-panel next-my-mcp__panel" data-testid="mcp-services-panel">
      <div class="ui-panel-head">
        <h2 class="ui-panel-title">我可以使用的 MCP 服务</h2>
        <span class="ui-panel-sub">
          共 {{ countWhenLoaded(loadError, services.length) }} 个服务
        </span>
      </div>
      <div class="ui-panel-body">
        <div v-if="loading" class="ui-skeleton next-my-mcp__skeleton" />
        <UiEmptyState
          v-else-if="!loadError && !services.length"
          :title="issued ? '还没有被授权任何服务' : '还没有签发凭据'"
          :description="data?.hint ?? ''"
          data-testid="mcp-services-empty"
        >
          <UiButton v-if="!issued" variant="primary" :loading="busy" @click="issue">
            签发我的 MCP 凭据
          </UiButton>
        </UiEmptyState>
        <div v-else-if="services.length" class="next-my-mcp__services">
          <article
            v-for="svc in services"
            :key="svc.serviceId"
            class="next-my-mcp__service"
            :data-testid="`mcp-service-${svc.name}`"
          >
            <div class="next-my-mcp__service-head">
              <div class="next-my-mcp__service-title">
                <span class="ui-mono next-my-mcp__service-name">{{ svc.name }}</span>
                <UiStatusBadge
                  :tone="svc.status === 'ONLINE' ? 'success' : 'neutral'"
                  :label="svc.status === 'ONLINE' ? '在线' : '已下线'"
                />
              </div>
              <div class="next-my-mcp__service-actions">
                <span class="next-my-mcp__tool-count">{{ (svc.tools ?? []).length }} 个工具</span>
                <UiButton
                  variant="secondary"
                  size="sm"
                  :data-testid="`mcp-service-copy-${svc.name}`"
                  @click="copyText(svc.mcpUrl ?? '', '接入地址已复制')"
                >
                  复制接入地址
                </UiButton>
                <UiButton
                  v-if="(svc.tools ?? []).length"
                  variant="ghost"
                  size="sm"
                  :data-testid="`mcp-service-tools-${svc.name}`"
                  @click="toggle(svc.serviceId)"
                >
                  {{ expanded[svc.serviceId ?? ''] ? '收起工具' : '查看工具' }}
                </UiButton>
              </div>
            </div>
            <p v-if="svc.description" class="next-my-mcp__service-desc">{{ svc.description }}</p>
            <p class="ui-mono next-my-mcp__service-url">{{ svc.mcpUrl }}</p>
            <!-- 服务级放行但工具级一条都没授权时（本机实测常见），只显示「0 个工具」
                 会让人以为页面坏了：这里必须说清下一步找谁。 -->
            <p
              v-if="!(svc.tools ?? []).length"
              class="next-my-mcp__service-hint"
              data-testid="mcp-service-no-tools"
            >
              该服务下还没有授权给你任何工具——请管理员在「MCP 服务 →
              访问控制」里为你的凭据授权后，工具会出现在这里。
            </p>
            <ul
              v-if="expanded[svc.serviceId ?? '']"
              class="next-my-mcp__tools"
              data-testid="mcp-tools"
            >
              <li
                v-for="tool in svc.tools ?? []"
                :key="tool.toolId"
                class="next-my-mcp__tool"
                :data-testid="`mcp-tool-${tool.toolName}`"
              >
                <span class="ui-mono next-my-mcp__tool-name">{{ tool.toolName }}</span>
                <span v-if="tool.description" class="next-my-mcp__tool-desc">
                  {{ tool.description }}
                </span>
              </li>
            </ul>
          </article>
        </div>
      </div>
    </section>

    <!-- ③ 客户端配置 -->
    <section class="ui-panel next-my-mcp__panel" data-testid="mcp-config-panel">
      <div class="ui-panel-head">
        <h2 class="ui-panel-title">在客户端里使用</h2>
      </div>
      <div class="ui-panel-body">
        <p v-if="data?.authHint" class="next-my-mcp__note" data-testid="mcp-auth-hint">
          {{ data.authHint }}
        </p>
        <template v-if="configService">
          <UiSelect
            v-if="services.length > 1"
            v-model="configServiceId"
            label="服务"
            :options="serviceOptions"
            width="320px"
            data-testid="mcp-config-service"
          />
          <div class="next-my-mcp__snippet" data-testid="mcp-config-snippet">
            <pre class="ui-mono">{{ configSnippet }}</pre>
          </div>
          <div class="next-my-mcp__snippet-actions">
            <UiButton
              variant="secondary"
              data-testid="mcp-config-copy"
              @click="copyText(configSnippet, '配置片段已复制')"
            >
              复制配置片段
            </UiButton>
          </div>
          <p class="next-my-mcp__note">
            把
            <span class="ui-mono">mqk_api_…</span>
            换成签发或轮换时展示的那串明文。上游 MCP
            的地址与后端密钥全程不下发，客户端只用网关签发的凭据。网关使用自签证书时，客户端还要先信任该
            CA——Node 内核的客户端可在启动前设
            <span class="ui-mono">NODE_EXTRA_CA_CERTS=&lt;CA 证书&gt;.pem</span>。
          </p>
        </template>
        <UiEmptyState
          v-else-if="!loadError"
          title="还没有可接入的服务"
          description="签发凭据并等管理员授权后，这里会给出可直接粘贴的配置片段。"
        />
      </div>
    </section>

    <!-- 一次性明文 -->
    <UiDialog
      v-if="revealData"
      :open="revealOpen"
      :title="revealMode === 'issue' ? '凭据已签发，仅显示一次' : '凭据已轮换，旧 Key 已失效'"
      :description="
        revealMode === 'issue'
          ? '请立即复制并保存到客户端的 MCP 配置；关闭后无法再次查看明文。'
          : '请同步更新已经配好这条凭据的客户端；关闭后无法再次查看明文。'
      "
      width="560px"
      :dismissible="false"
      data-testid="mcp-key-dialog"
      @update:open="(open: boolean) => (revealOpen = open)"
    >
      <p class="next-my-mcp__reveal-meta">
        名称 <span class="ui-mono">{{ revealData.credential?.name }}</span> · 作用域
        <span class="ui-mono">{{ (revealData.credential?.capabilities ?? []).join(' · ') }}</span>
      </p>
      <div class="next-my-mcp__secret-box" data-testid="mcp-key-value">
        <code>{{ revealData.apiKey }}</code>
      </div>
      <label class="next-my-mcp__ack">
        <input
          v-model="revealAcked"
          type="checkbox"
          class="next-my-mcp__ack-input"
          data-testid="mcp-key-ack"
        />
        <span class="next-my-mcp__ack-box" aria-hidden="true">
          <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
            <path
              d="M3.5 8.5 6.5 11.5 12.5 4.5"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </span>
        <span>我已保存该凭据</span>
      </label>
      <template #footer>
        <UiButton variant="secondary" data-testid="mcp-key-copy" @click="copyReveal">
          {{ revealCopied ? '已复制' : '复制' }}
        </UiButton>
        <UiButton
          variant="primary"
          :disabled="!revealAcked"
          data-testid="mcp-key-close"
          @click="revealOpen = false"
        >
          完成
        </UiButton>
      </template>
    </UiDialog>

    <!-- 二次确认 -->
    <UiDialog
      v-if="confirmState"
      :open="true"
      :title="confirmState.title"
      :description="confirmState.body"
      width="460px"
      data-testid="mcp-confirm"
      @update:open="confirmState = null"
    >
      <template #footer>
        <UiButton variant="ghost" data-testid="mcp-confirm-cancel" @click="confirmState = null">
          取消
        </UiButton>
        <UiButton
          :variant="confirmState.tone === 'danger' ? 'danger' : 'primary'"
          :loading="busy"
          data-testid="mcp-confirm-run"
          @click="runConfirm"
        >
          {{ confirmState.confirmLabel }}
        </UiButton>
      </template>
    </UiDialog>
  </div>
</template>

<style scoped>
.ui-alert {
  padding: var(--ui-space-3) var(--ui-space-4);
  margin-bottom: var(--ui-space-4);
  border-radius: var(--ui-radius-control);
  font-size: var(--ui-font-size-sm);
}

.ui-alert--error {
  background: var(--ui-danger-bg);
  color: var(--ui-danger-fg);
}

.next-my-mcp__panel {
  margin-bottom: var(--ui-space-5);
}

.next-my-mcp__head-actions {
  display: flex;
  align-items: center;
  gap: var(--ui-space-2);
}

.next-my-mcp__skeleton {
  height: 88px;
}

/* ---- ① 凭据 ---- */
.next-my-mcp__kv {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: var(--ui-space-4) var(--ui-space-6);
  margin: 0;
}

.next-my-mcp__kv > div {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.next-my-mcp__kv dt {
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__kv dd {
  margin: 0;
  font-size: var(--ui-font-size-md);
}

.next-my-mcp__note {
  margin: var(--ui-space-4) 0 0;
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
  line-height: 1.7;
}

.next-my-mcp__empty {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--ui-space-2);
}

.next-my-mcp__empty-title {
  margin: 0;
  font-size: var(--ui-font-size-lg);
  font-weight: 600;
}

.next-my-mcp__empty-desc {
  margin: 0 0 var(--ui-space-2);
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

/* ---- ② 服务与工具 ---- */
.next-my-mcp__services {
  display: flex;
  flex-direction: column;
  gap: var(--ui-space-3);
}

.next-my-mcp__service {
  border: 1px solid var(--ui-border);
  border-radius: var(--ui-radius-control);
  padding: var(--ui-space-4);
}

.next-my-mcp__service-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ui-space-3);
  flex-wrap: wrap;
}

.next-my-mcp__service-title {
  display: flex;
  align-items: center;
  gap: var(--ui-space-2);
}

.next-my-mcp__service-name {
  font-size: var(--ui-font-size-md);
  font-weight: 600;
}

.next-my-mcp__service-actions {
  display: flex;
  align-items: center;
  gap: var(--ui-space-2);
}

.next-my-mcp__tool-count {
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__service-desc {
  margin: var(--ui-space-2) 0 0;
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__service-url {
  margin: var(--ui-space-2) 0 0;
  color: var(--ui-text-2);
  font-size: var(--ui-font-size-sm);
  word-break: break-all;
}

.next-my-mcp__service-hint {
  margin: var(--ui-space-2) 0 0;
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__tools {
  list-style: none;
  margin: var(--ui-space-3) 0 0;
  padding: var(--ui-space-3) 0 0;
  border-top: 1px dashed var(--ui-border);
  display: flex;
  flex-direction: column;
  gap: var(--ui-space-2);
}

.next-my-mcp__tool {
  display: flex;
  gap: var(--ui-space-3);
  align-items: baseline;
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__tool-name {
  flex: 0 0 auto;
  min-width: 180px;
}

.next-my-mcp__tool-desc {
  color: var(--ui-text-3);
  overflow: hidden;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

/* ---- ③ 客户端配置 ---- */
.next-my-mcp__snippet {
  margin-top: var(--ui-space-3);
  padding: var(--ui-space-3) var(--ui-space-4);
  background: var(--ui-surface-2, var(--ui-card));
  border: 1px solid var(--ui-border);
  border-radius: var(--ui-radius-control);
  overflow-x: auto;
}

.next-my-mcp__snippet pre {
  margin: 0;
  font-size: var(--ui-font-size-sm);
  line-height: 1.6;
}

.next-my-mcp__snippet-actions {
  margin-top: var(--ui-space-3);
  display: flex;
  gap: var(--ui-space-2);
}

/* ---- 一次性明文 ---- */
.next-my-mcp__reveal-meta {
  margin: 0 0 var(--ui-space-3);
  color: var(--ui-text-3);
  font-size: var(--ui-font-size-sm);
}

.next-my-mcp__secret-box {
  padding: var(--ui-space-4);
  border: 1px dashed var(--ui-border);
  border-radius: var(--ui-radius-control);
  background: var(--ui-surface-2, var(--ui-card));
  word-break: break-all;
}

.next-my-mcp__secret-box code {
  font-family: var(--ui-font-mono, monospace);
  font-size: var(--ui-font-size-md);
}

.next-my-mcp__ack {
  display: flex;
  align-items: center;
  gap: var(--ui-space-2);
  margin-top: var(--ui-space-4);
  font-size: var(--ui-font-size-sm);
  cursor: pointer;
}

.next-my-mcp__ack-input {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.next-my-mcp__ack-box {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border: 1px solid var(--ui-border-strong, var(--ui-border));
  border-radius: 4px;
  color: transparent;
}

.next-my-mcp__ack-input:checked + .next-my-mcp__ack-box {
  background: var(--ui-brand);
  border-color: var(--ui-brand);
  color: #fff;
}

.next-my-mcp__ack-input:focus-visible + .next-my-mcp__ack-box {
  outline: 2px solid var(--ui-brand);
  outline-offset: 2px;
}
</style>
