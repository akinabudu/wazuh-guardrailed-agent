import axios, { AxiosError, AxiosInstance } from 'axios';
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
    const token = cookie(request, 'wz-token');
    const apiHostID = cookie(request, 'wz-api');
    if (!identity.username || !token || !apiHostID) {
      throw Object.assign(new Error('Wazuh session is incomplete'), {
        statusCode: 401,
      });
    }
    return { username: identity.username, token, apiHostID };
  }

  private async authorizeAgent(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    analyst: Analyst,
    agentID: string,
  ) {
    const wazuh = (context as any).wazuh_core;
    const result = await wazuh.api.client.asCurrentUser.request(
      'GET',
      '/agents',
      { params: { agents_list: agentID, limit: 1 } },
      { apiHostID: analyst.apiHostID },
    );
    const items = result?.data?.data?.affected_items || [];
    if (!items.some((item: { id?: string }) => item.id === agentID)) {
      throw Object.assign(new Error('You cannot access this Wazuh agent'), {
        statusCode: 403,
      });
    }
  }

  private headers(analyst: Analyst, includeWazuhToken = false) {
    return {
      'x-analyst': analyst.username,
      'x-guardrail-token': this.serviceToken,
      ...(includeWazuhToken ? { 'x-wazuh-token': analyst.token } : {}),
    };
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

    router.post(
      {
        path: '/api/wazuh_guardrail/investigate',
        validate: {
          body: schema.object({
            agent_id: schema.string({ minLength: 1, maxLength: 32 }),
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
            request,
            analyst,
            request.body.agent_id,
          );
          const result = await this.backend.post('/investigate', request.body, {
            headers: this.headers(analyst),
          });
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
          const result = await this.backend.get('/queue', {
            headers: this.headers(analyst),
          });
          const visible: Proposal[] = [];
          for (const proposal of result.data.pending as Proposal[]) {
            if (!proposal.agent_id) continue;
            try {
              await this.authorizeAgent(
                context,
                request,
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
          const proposalResult = await this.backend.get(
            `/proposals/${request.params.id}`,
            { headers: this.headers(analyst) },
          );
          const proposal = proposalResult.data as Proposal;
          if (!proposal.agent_id) {
            throw Object.assign(new Error('Proposal has no Wazuh agent'), {
              statusCode: 409,
            });
          }
          await this.authorizeAgent(
            context,
            request,
            analyst,
            proposal.agent_id,
          );
          if (proposal.tier === 'elevated') {
            throw Object.assign(
              new Error('This action requires a separate second approver'),
              { statusCode: 501 },
            );
          }
          const result = await this.backend.post(
            `/proposals/${request.params.id}/${request.params.decision}`,
            request.body,
            {
              headers: this.headers(
                analyst,
                request.params.decision === 'approve',
              ),
            },
          );
          return response.ok({ body: result.data });
        } catch (error) {
          return this.error(response, error);
        }
      },
    );
  }
}
