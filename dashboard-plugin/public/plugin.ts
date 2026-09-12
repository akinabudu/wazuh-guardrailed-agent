import {
  AppMountParameters,
  CoreSetup,
  CoreStart,
  Plugin,
  PluginInitializerContext,
} from 'opensearch_dashboards/public';

export class WazuhGuardrailPlugin implements Plugin {
  constructor(_initializerContext: PluginInitializerContext) {}

  public setup(core: CoreSetup) {
    core.application.register({
      id: 'wazuhGuardrail',
      title: 'Guardrailed AI',
      order: 9100,
      mount: async (params: AppMountParameters) => {
        const [coreStart] = await core.getStartServices();
        const { renderApp } = await import('./application');
        return renderApp(coreStart.http, params);
      },
    });
    return {};
  }

  public start(_core: CoreStart) {}

  public stop() {}
}
