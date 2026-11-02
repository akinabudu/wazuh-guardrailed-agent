// Configuration for WazuhLabStack, the evaluation lab of this repository.
//
// Copied from the stack that ran the thesis evaluation (orglobal-website-cdk,
// branch feat/wazuh-lab, commit da09840). The values are the ones the evaluation
// used, except that the subnet, the branch the host clones and the AWS CLI
// profile can be set from the environment, so the stack deploys into any account.

export const config = {
  // The pinned AMI below exists only in us-east-1, so the region is fixed.
  region: "us-east-1",
  account: process.env.CDK_DEFAULT_ACCOUNT ?? process.env.AWS_ACCOUNT_ID ?? "",

  // ── Wazuh lab (thesis evaluation) ────────────────────────────────────────
  // Three spot boxes for the guardrailed-agent thesis evaluation: the Wazuh +
  // agent host, one monitored Linux endpoint, and an attacker box so emulated
  // attacks come from an address other than the manager's. All reached over
  // SSM only; nothing is open to the internet.
  wazuhLab: {
    projectTag: "wazuh-lab",
    repoUrl: "https://github.com/akinabudu/wazuh-guardrailed-agent",
    // Branch the host clones on first boot (git clone --branch). The deployed
    // lab cloned main; the Bedrock provider is on feat/bedrock-provider.
    repoBranch: process.env.WAZUH_LAB_REPO_BRANCH || "main",
    // One AZ so the three boxes talk over the VPC without cross-AZ charges.
    // The evaluation used subnet-0c3b55b245c4e5476 (us-east-1a of the author's
    // default VPC). Unset, the stack uses the default VPC's first public subnet.
    subnetId: process.env.WAZUH_LAB_SUBNET_ID || undefined,
    // 16 GB, 4 vCPU: the host specification the thesis targets.
    hostInstanceType: "t3.xlarge",
    // 60 GB filled up during a full evaluation run, so the host gets 120 GB.
    // Changing this changes the launch template and so REPLACES the host.
    hostVolumeGb: 120,
    endpointInstanceType: "t3.small",
    attackerInstanceType: "t3.micro",
    // Pinned. Resolving Canonical's "current" SSM parameter at deploy time
    // rebuilt all three boxes on an IAM-only deploy (2026-10-25). This is the
    // Ubuntu 24.04 image those boxes run; bump it only to rebuild deliberately.
    ubuntuAmi: "ami-0d6dd9e8265d48906",
    // AWS CLI profile named in the DashboardTunnelCommand output, if any.
    awsProfile: process.env.AWS_PROFILE || undefined,
    wazuhAgentVersion: "4.14.9-1",
  },
} as const;

export type Config = typeof config;
