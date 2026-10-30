# Evaluation lab (AWS CDK)

`WazuhLabStack` creates the laboratory used for the thesis evaluation: three EC2
spot instances in one subnet of the account's default VPC, in `us-east-1`.

| Box | Type | Role |
|---|---|---|
| `wazuh-lab-host` | t3.xlarge (4 vCPU, 16 GB), 60 GB gp3 | Wazuh 4.9.2 single-node and the guardrailed agent. On first boot it clones this repository and runs `setup.sh`. |
| `wazuh-lab-endpoint` | t3.small | The monitored Ubuntu 24.04 endpoint: Wazuh agent 4.9.2, auditd, real-time FIM, sshd, nginx and Atomic Red Team. |
| `wazuh-lab-attacker` | t3.micro | Source of the emulated SSH and HTTP attacks and of the injection payloads. |

No box accepts traffic from the internet. They are administered over AWS Systems
Manager, and the Wazuh dashboard is reached through an SSM port-forward (the
`DashboardTunnelCommand` stack output). The host role may send SSM commands only
to boxes tagged `Project=wazuh-lab`, and may invoke the three Claude models
of the evaluation on Amazon Bedrock.

## Deploy

Requires Node.js 22, AWS credentials for the target account, a bootstrapped CDK
environment (`npx cdk bootstrap`) and Bedrock model access for Claude Opus 4.6
in the account.

```bash
cd infra
npm ci
npx cdk deploy WazuhLabStack
```

Optional environment variables:

| Variable | Default | Effect |
|---|---|---|
| `WAZUH_LAB_SUBNET_ID` | first public subnet of the default VPC | Subnet for all three boxes |
| `WAZUH_LAB_REPO_BRANCH` | `main` | Branch the host clones on first boot. The Bedrock provider is on `feat/bedrock-provider`. |
| `AWS_PROFILE` | none | Profile named in the `DashboardTunnelCommand` output |

The host's first boot takes several minutes. Progress is in
`/var/log/lab-setup.log` on each box, and `/var/lib/lab-setup.done` appears when a
box has finished. To run a specific commit, check it out on the host in
`/home/ubuntu/wazuh-guardrailed-agent` and run `./setup.sh` again as `ubuntu`.

## Tear down

The spot requests are persistent, so they relaunch any instance CloudFormation
terminates. Cancel them first, then destroy the stack:

```bash
aws ec2 describe-instances --filters Name=tag:Project,Values=wazuh-lab \
  --query 'Reservations[].Instances[].SpotInstanceRequestId'
aws ec2 cancel-spot-instance-requests --spot-instance-request-ids <ids>
npx cdk destroy WazuhLabStack
```

Changing the AMI, the host volume size or any user data replaces all three boxes
and wipes their disks. Before such a deploy, create a change set with
`npx cdk deploy WazuhLabStack --no-execute`, check its Replacement column, and
copy any results off the host.

## Provenance

This is a copy of the stack that ran the evaluation, which lived in the author's
infrastructure repository (`orglobal-website-cdk`, branch `feat/wazuh-lab`,
commit `da09840`). Three things differ from that copy, none of which changes the
resources created:

- The subnet, the branch the host clones and the AWS CLI profile in the tunnel
  command come from the environment instead of being fixed to the author's
  account. The evaluation used subnet `subnet-0c3b55b245c4e5476` (us-east-1a).
- The stack has its own CDK app (`bin/wazuh-lab.ts`) and `package.json`, with
  the same `aws-cdk-lib` (2.242.0) and CDK CLI (2.1110.0) versions and the same
  feature flags in `cdk.json`.
- `cdk.context.json`, which records the deploying account's VPC lookups, is not
  committed.
