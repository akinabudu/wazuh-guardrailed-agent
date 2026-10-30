#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { WazuhLabStack } from "../lib/wazuh-lab-stack";
import { config } from "../config";

const app = new cdk.App();

// The guardrailed-agent evaluation lab. Deploy with `npx cdk deploy WazuhLabStack`.
// No termination protection: it is deleted once the evaluation is recorded.
new WazuhLabStack(app, "WazuhLabStack", {
  env: {
    account: config.account || process.env.CDK_DEFAULT_ACCOUNT,
    region: config.region,
  },
  description:
    "wazuh-lab - Wazuh + guardrailed agent host, a monitored Linux endpoint and an attacker box, all spot and SSM-only",
});

app.synth();
