import { PluginInitializerContext } from 'opensearch-dashboards/server';

import { WazuhGuardrailPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhGuardrailPlugin(initializerContext);
}
