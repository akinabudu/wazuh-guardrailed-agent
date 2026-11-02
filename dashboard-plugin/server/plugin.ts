import axios, { AxiosError, AxiosInstance } from 'axios';
import { createHash, createHmac, randomBytes } from 'crypto';
import { schema } from '@osd/config-schema';
import {
  CoreSetup,
  CoreStart,
  IRouter,
  Logger,
  OpenSearchDashboardsRequest,
  Plugin,
  PluginInitializerContext,
  RequestHandlerContext,
} from 'opensearch-dashboards/server';

type Analyst = {
  username: string;
  token: string;
  apiHostID: string;
};

type Proposal = {
  id: number;
  agent_id?: string;
  tier: string;
};

type WazuhAgent = {
  id?: string;
  name?: string;
  status?: string;
  ip?: string;
};

function cookie(request: OpenSearchDashboardsRequest, name: string): string {
  const header = request.headers.cookie || '';
  const part = header.split(';').map(value => value.trim()).find(value =>
    value.startsWith(`${name}=`),
  );
  return part ? decodeURIComponent(part.slice(name.length + 1)) : '';
}

export class WazuhGuardrailPlugin implements Plugin {
  private readonly logger: Logger;
  private readonly backend: AxiosInstance;
  private readonly serviceToken: string;

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
    this.serviceToken = process.env.WAZUH_GUARDRAIL_SHARED_SECRET || '';
    this.backend = axios.create({
      baseURL:
        process.env.WAZUH_GUARDRAIL_BACKEND_URL ||
        'http://guardrail-backend:8000',
      timeout: 15000,
    });
  }

  public setup(core: CoreSetup) {
    const router = core.http.createRouter();
    this.defineRoutes(router);
    return {};
  }

  public start(_core: CoreStart) {}

  public stop() {}

  private async analyst(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
  ): Promise<Analyst> {
    if (!this.serviceToken) {
      throw new Error('WAZUH_GUARDRAIL_SHARED_SECRET is not configured');
    }
    const wazuh = (context as any).wazuh_core;
    const identity = await wazuh.dashboardSecurity.getCurrentUser(
      request,
      context,
    );
    if (!identity.username) {
      throw Object.assign(new Error('Wazuh session is incomplete'), {
        statusCode: 401,
      });
    }
    let apiHostID = cookie(request, 'wz-api');
    if (!apiHostID) {
      const hosts = await wazuh.manageHosts.get(undefined, {
        excludePassword: true,
      });
      apiHostID = (hosts[0] && hosts[0].id) || '';
    }
    if (!apiHostID) {
      throw Object.assign(new Error('No Wazuh API host is configured'), {
        statusCode: 503,
      });
    }
    const token = await wazuh.api.client.asCurrentUser.authenticate(apiHostID);
    return { username: identity.username, token, apiHostID };
  }

  private async wazuhRequest(
    context: RequestHandlerContext,
    analyst: Analyst,
    method: string,
    path: string,
    data: Record<string, unknown>,
  ) {
    const wazuh = (context as any).wazuh_core;
    return wazuh.serverAPIClient._request(method, path, data, {
      apiHostID: analyst.apiHostID,
      token: analyst.token,
    });
  }

  private async authorizeAgent(
    context: RequestHandlerContext,
    analyst: Analyst,
    agentID: string,
  ) {
    const result = await this.wazuhRequest(
      context,
      analyst,
      'GET',
      '/agents',
      { params: { agents_list: agentID, limit: 1 } },
    );
    const items = result?.data?.data?.affected_items || [];
    if (!items.some((item: { id?: string }) => item.id === agentID)) {
      throw Object.assign(new Error('You cannot access this Wazuh agent'), {
        statusCode: 403,
      });
    }
  }

  /**
   * Sign one backend call (checked by verify_signature() in backend/main.py).
   * The HMAC covers a timestamp, a one-time nonce, the method, the path, the
   * analyst resolved from the Wazuh session and the body hash, so a captured
   * request cannot be replayed, redirected or altered.
   */
  private headers(
    analyst: Analyst,
    method: string,
    path: string,
    body: string,
    includeWazuhToken = false,
  ) {
    const timestamp = (Date.now() / 1000).toFixed(3);
    const nonce = randomBytes(16).toString('hex');
    const message = [
      timestamp,
      nonce,
      method.toUpperCase(),
      path,
      analyst.username,
      createHash('sha256').update(body).digest('hex'),
    ].join('\n');
    return {
      'content-type': 'application/json',
      'x-analyst': analyst.username,
      'x-guardrail-timestamp': timestamp,
      'x-guardrail-nonce': nonce,
      'x-guardrail-signature': createHmac('sha256', this.serviceToken)
        .update(message)
        .digest('hex'),
      ...(includeWazuhToken ? { 'x-wazuh-token': analyst.token } : {}),
    };
  }

  private async call(
    analyst: Analyst,
    method: 'GET' | 'POST',
    path: string,
    payload?: unknown,
    includeWazuhToken = false,
  ) {
    // Send exactly the bytes that were signed.
    const body = payload === undefined ? '' : JSON.stringify(payload);
    return this.backend.request({
      method,
      url: path,
      data: body || undefined,
      transformRequest: [(data: unknown) => data],
      headers: this.headers(analyst, method, path, body, includeWazuhToken),
    });
  }

  private error(response: any, error: unknown) {
    const axiosError = error as AxiosError<{ detail?: string }>;
    const statusCode =
      axiosError.response?.status || (error as any)?.statusCode || 500;
    const message =
      axiosError.response?.data?.detail ||
      (error as Error)?.message ||
      'Guardrailed AI request failed';
    this.logger.warn(`Guardrailed AI request failed (${statusCode})`);
    return response.customError({ statusCode, body: { message } });
  }

  private defineRoutes(router: IRouter) {
    router.get(
      { path: '/api/wazuh_guardrail/session', validate: false },
      async (context, request, response) => {
        try {
          const analyst = await this.analyst(context, request);
          return response.ok({ body: { username: analyst.username } });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );

    router.get(
      { path: '/api/wazuh_guardrail/agents', validate: false },
      async (context, request, response) => {
        try {
          const analyst = await this.analyst(context, request);
          const result = await this.wazuhRequest(
            context,
            analyst,
            'GET',
            '/agents',
            {
              params: {
                limit: 500,
                sort: '+id',
                select: 'id,name,status,ip',
              },
            },
          );
          const items = result?.data?.data?.affected_items || [];
          const agents = (items as WazuhAgent[])
            .filter(agent => agent.id && agent.name)
            .map(agent => ({
              id: agent.id,
              name: agent.name,
              status: agent.status || 'unknown',
              ip: agent.ip || '',
            }));
          return response.ok({ body: { agents } });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );

    router.post(
      {
        path: '/api/wazuh_guardrail/investigate',
        validate: {
          body: schema.object({
            agent_id: schema.string({ minLength: 1, maxLength: 32 }),
            alert_id: schema.maybe(schema.string({ maxLength: 128 })),
            rule_id: schema.maybe(schema.string({ maxLength: 64 })),
            description: schema.maybe(schema.string({ maxLength: 2000 })),
          }),
        },
      },
      async (context, request, response) => {
        try {
          const analyst = await this.analyst(context, request);
          await this.authorizeAgent(
            context,
            analyst,
            request.body.agent_id,
          );
          const result = await this.call(
            analyst,
            'POST',
            '/investigate',
            request.body,
          );
          return response.ok({ body: result.data });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );

    router.get(
      { path: '/api/wazuh_guardrail/queue', validate: false },
      async (context, request, response) => {
        try {
          const analyst = await this.analyst(context, request);
          const result = await this.call(analyst, 'GET', '/queue');
          const visible: Proposal[] = [];
          for (const proposal of result.data.pending as Proposal[]) {
            if (!proposal.agent_id) continue;
            try {
              await this.authorizeAgent(
                context,
                analyst,
                proposal.agent_id,
              );
              visible.push(proposal);
            } catch (error) {
              const status =
                (error as AxiosError).response?.status ||
                (error as any)?.statusCode;
              if (status !== 401 && status !== 403) throw error;
            }
          }
          return response.ok({ body: { pending: visible } });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );

    router.post(
      {
        path: '/api/wazuh_guardrail/proposals/{id}/{decision}',
        validate: {
          params: schema.object({
            id: schema.number({ min: 1 }),
            decision: schema.oneOf([
              schema.literal('approve'),
              schema.literal('reject'),
            ]),
          }),
          body: schema.object({
            justification: schema.maybe(schema.string({ maxLength: 2000 })),
          }),
        },
      },
      async (context, request, response) => {
        try {
          const analyst = await this.analyst(context, request);
          const proposalResult = await this.call(
            analyst,
            'GET',
            `/proposals/${request.params.id}`,
          );
          const proposal = proposalResult.data as Proposal;
          if (!proposal.agent_id) {
            throw Object.assign(new Error('Proposal has no Wazuh agent'), {
              statusCode: 409,
            });
          }
          await this.authorizeAgent(
            context,
            analyst,
            proposal.agent_id,
          );
          if (proposal.tier === 'elevated') {
            throw Object.assign(
              new Error('This action requires a separate second approver'),
              { statusCode: 501 },
            );
          }
          const result = await this.call(
            analyst,
            'POST',
            `/proposals/${request.params.id}/${request.params.decision}`,
            request.body,
            request.params.decision === 'approve',
          );
          return response.ok({ body: result.data });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );
  }
}
