import { GraphQLClient, gql } from 'graphql-request';
import { config } from '../config.js';

/**
 * PentAGI GraphQL istemcisi.
 *
 * KRITIK: Bu dosya, musterinin ASLA dogrudan erismedigi tek yer.
 * Musteri sadece bizim REST API'mize (routes/) konusuyor; bizim backend'imiz
 * kendi servis token'iyla PentAGI'ye baglaniyor. Boylece:
 *  - PentAGI'nin admin arayuzu, model/saglayici ayarlari, diger flow'lar
 *    musteriye hicbir zaman gorunmuyor.
 *  - Anthropic key'i sadece bu backend <-> PentAGI arasinda kaliyor,
 *    musteriye hic gecmiyor.
 *
 * Gercek schema'dan (backend/pkg/graph/schema.graphqls) dogrulanan alanlar:
 *  createFlow(modelProvider: String!, input: String!, resourceIds: [ID!]): Flow!
 *  flow(flowId: ID!): Flow!
 *  tasks(flowId: ID!): [Task!]
 *  messageLogs(flowId: ID!): [MessageLog!]
 *  screenshots(flowId: ID!): [Screenshot!]
 *  finishFlow(flowId: ID!): ResultType!
 *  deleteFlow(flowId: ID!): ResultType!
 */

function client() {
  return new GraphQLClient(config.pentagi.graphqlUrl, {
    headers: { Authorization: `Bearer ${config.pentagi.serviceToken}` },
  });
}

const CREATE_FLOW = gql`
  mutation CreateFlow($provider: String!, $input: String!) {
    createFlow(modelProvider: $provider, input: $input) {
      id
      status
      title
    }
  }
`;

export async function createFlow(modelProvider: string, prompt: string) {
  const data = await client().request<{ createFlow: { id: string | number; status: string; title: string } }>(
    CREATE_FLOW,
    { provider: modelProvider, input: prompt },
  );
  // PentAGI flow id'sini Int dondurebiliyor; bizim DB kolonu String, o yuzden
  // burada normalize ediyoruz. GraphQL ID tipi sorgularda string'i de kabul eder.
  return { ...data.createFlow, id: String(data.createFlow.id) };
}

const GET_FLOW_STATUS = gql`
  query GetFlow($flowId: ID!) {
    flow(flowId: $flowId) {
      id
      status
    }
  }
`;

export async function getFlowStatus(pentagiFlowId: string) {
  const data = await client().request<{ flow: { id: string; status: string } }>(GET_FLOW_STATUS, {
    flowId: pentagiFlowId,
  });
  return data.flow;
}

const GET_FLOW_LOGS = gql`
  query GetFlowLogs($flowId: ID!) {
    tasks(flowId: $flowId) {
      id
      title
      status
      result
    }
    messageLogs(flowId: $flowId) {
      id
      type
      message
      createdAt
    }
    screenshots(flowId: $flowId) {
      id
      url
      name
    }
  }
`;

export interface FlowLogs {
  tasks: Array<{ id: string; title: string; status: string; result: string | null }>;
  messageLogs: Array<{ id: string; type: string; message: string; createdAt: string }>;
  screenshots: Array<{ id: string; url: string; name: string }>;
}

export async function getFlowLogs(pentagiFlowId: string): Promise<FlowLogs> {
  return client().request<FlowLogs>(GET_FLOW_LOGS, { flowId: pentagiFlowId });
}

// Kapsam (scope) izleme: ajanin ERISTIGI hedefleri gormek icin calistirilan
// komutlar (terminalLogs.text) ve tool cagri argumanlari (toolCallLogs.args).
const GET_SCOPE_LOGS = gql`
  query GetScopeLogs($flowId: ID!) {
    toolCallLogs(flowId: $flowId) {
      id
      name
      args
      result
    }
    terminalLogs(flowId: $flowId) {
      id
      text
    }
  }
`;

export interface ScopeLogs {
  toolCallLogs: Array<{ id: string; name: string; args: string | null; result: string | null }>;
  terminalLogs: Array<{ id: string; text: string | null }>;
}

export async function getScopeLogs(pentagiFlowId: string): Promise<ScopeLogs> {
  return client().request<ScopeLogs>(GET_SCOPE_LOGS, { flowId: pentagiFlowId });
}

const GET_TOOLCALL_COUNT = gql`
  query GetToolcallStats($flowId: ID!) {
    toolcallsStatsByFlow(flowId: $flowId) {
      totalCount
    }
  }
`;

/**
 * ONEMLI NOT: PentAGI'nin GraphQL API'sinde flow bazinda tur/adim tavani
 * (max tool calls) set etmek icin bir alan YOK — bu limit sadece instance
 * genelinde .env uzerinden (MAX_GENERAL_AGENT_TOOL_CALLS,
 * MAX_LIMITED_AGENT_TOOL_CALLS) ayarlaniyor. Yani "paket bazli sabit maliyet
 * tavani" bizim backend'imizin kendi sorumlulugu: worker.ts periyodik olarak
 * toolcallsStatsByFlow ile sayaci okuyup, paketin maxToolCalls degerini
 * asinca stopFlow cagiriyor (asagida). Bu bir HARD limit degil, bir polling
 * araligi kadar gecikmeli bir "yumusak" tavan — polling araligini kisa
 * tutmak (ör. 5-10 saniye) asimi kucuk tutar.
 */
export async function getToolCallCount(pentagiFlowId: string): Promise<number> {
  const data = await client().request<{ toolcallsStatsByFlow: { totalCount: number } }>(
    GET_TOOLCALL_COUNT,
    { flowId: pentagiFlowId },
  );
  return data.toolcallsStatsByFlow.totalCount;
}

// NOT: ResultType bir enum ("success" | "error"), obje degil — { success } gibi
// alt alan secmeye CALISMA, dogrudan skaler deger olarak gelir.
const STOP_FLOW = gql`
  mutation StopFlow($flowId: ID!) {
    stopFlow(flowId: $flowId)
  }
`;

export async function stopFlow(pentagiFlowId: string) {
  const data = await client().request<{ stopFlow: 'success' | 'error' }>(STOP_FLOW, {
    flowId: pentagiFlowId,
  });
  return data.stopFlow === 'success';
}

const FINISH_FLOW = gql`
  mutation FinishFlow($flowId: ID!) {
    finishFlow(flowId: $flowId)
  }
`;

export async function finishFlow(pentagiFlowId: string) {
  const data = await client().request<{ finishFlow: 'success' | 'error' }>(FINISH_FLOW, {
    flowId: pentagiFlowId,
  });
  return data.finishFlow === 'success';
}

const DELETE_FLOW = gql`
  mutation DeleteFlow($flowId: ID!) {
    deleteFlow(flowId: $flowId)
  }
`;

/**
 * Rapor teslim edildikten sonra PentAGI tarafindaki ham veriyi (flow-{id}-data/,
 * DB kayitlari) silmek icin cagrilir. Bu, "arka plandaki her sey elimizde kalir"
 * riskini azaltan en onemli adimlardan biri — ham pentest verisini uzun sure
 * tutmuyoruz, sadece sifreli nihai raporu tutuyoruz.
 */
export async function purgeFlowRawData(pentagiFlowId: string) {
  await client().request(DELETE_FLOW, { flowId: pentagiFlowId });
}
