import {
  PluginInitializer,
  PluginInitializerContext,
} from 'opensearch_dashboards/public';

import { WazuhGuardrailPlugin } from './plugin';

export const plugin: PluginInitializer = (
  initializerContext: PluginInitializerContext,
) => new WazuhGuardrailPlugin(initializerContext);
