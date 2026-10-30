import * as fs from "fs";
import * as path from "path";
import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { config } from "../config";

/**
 * Lab for the guardrailed-agent thesis evaluation.
 *
 * Deploy it by name:
 *
 *     npx cdk deploy WazuhLabStack
 *
 * WHAT IT CREATES. Three spot boxes in one subnet of the default VPC:
 *   - host:     Wazuh 4.9.2 single-node and the guardrailed agent, which
 *               calls Claude Opus 4.6 on Bedrock with the host role;
 *               provisioned on first boot by the repo's own setup.sh
 *   - endpoint: the monitored Linux box (Wazuh agent, auditd, Atomic Red Team)
 *   - attacker: the source of emulated SSH/HTTP attacks and injection payloads
 * None accepts traffic from the internet. Operators reach them over SSM, and
 * the dashboard through an SSM port-forward.
 *
 * TEARING DOWN. The spot requests are persistent so an interruption stops the
 * boxes instead of losing the lab. Cancel them before `cdk destroy`, or they
 * relaunch the instances CloudFormation terminates:
 *
 *     aws ec2 describe-instances --filters Name=tag:Project,Values=wazuh-lab \
 *       --query 'Reservations[].Instances[].SpotInstanceRequestId'
 *     aws ec2 cancel-spot-instance-requests --spot-instance-request-ids ...
 *
 * The requests themselves carry no tags, so find them through the instances.
 * A deploy that replaces a box leaves the old box's request active, and it
 * relaunches an untagged copy that holds the lab's security groups. After any
 * replacement, look for requests whose instance has no Name tag.
 */
export class WazuhLabStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    const lab = config.wazuhLab;
    cdk.Tags.of(this).add("Project", lab.projectTag);

    const vpc = ec2.Vpc.fromLookup(this, "DefaultVpc", { isDefault: true });
    const ami = ec2.MachineImage.genericLinux({ [this.region]: lab.ubuntuAmi });

    // ── Security groups ──────────────────────────────────────────────────
    const hostSg = new ec2.SecurityGroup(this, "HostSg", {
      vpc,
      description: "wazuh-lab host - agent enrolment from the endpoint only",
    });
    const endpointSg = new ec2.SecurityGroup(this, "EndpointSg", {
      vpc,
      description: "wazuh-lab endpoint - SSH and HTTP from the attacker only",
    });
    const attackerSg = new ec2.SecurityGroup(this, "AttackerSg", {
      vpc,
      description: "wazuh-lab attacker - no inbound",
    });
    hostSg.addIngressRule(endpointSg, ec2.Port.tcp(1514), "Wazuh agent events");
    hostSg.addIngressRule(endpointSg, ec2.Port.tcp(1515), "Wazuh agent enrolment");
    endpointSg.addIngressRule(attackerSg, ec2.Port.tcp(22), "emulated SSH attacks");
    endpointSg.addIngressRule(attackerSg, ec2.Port.tcp(80), "emulated HTTP attacks");

    // ── Roles ────────────────────────────────────────────────────────────
    const ssmRole = (name: string) =>
      new iam.Role(this, name, {
        assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
        ],
      });
    const hostRole = ssmRole("HostRole");
    const endpointRole = ssmRole("EndpointRole");
    const attackerRole = ssmRole("AttackerRole");

    // The evaluation harness runs on the host and drives the endpoint and the
    // attacker over SSM. Only boxes carrying the lab's Project tag.
    hostRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["ssm:SendCommand"],
        resources: [`arn:aws:ec2:${this.region}:${this.account}:instance/*`],
        conditions: {
          StringEquals: { "ssm:resourceTag/Project": lab.projectTag },
        },
      })
    );
    hostRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["ssm:SendCommand"],
        resources: [`arn:aws:ssm:${this.region}::document/AWS-RunShellScript`],
      })
    );
    hostRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["ssm:GetCommandInvocation", "ec2:DescribeInstances"],
        resources: ["*"],
      })
    );

    // The backend's model: Claude on Bedrock (LLM_PROVIDER=bedrock, the
    // default). Newer models go through the Messages-API endpoint (bedrock-mantle).
    hostRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["bedrock-mantle:CreateInference"],
        resources: ["*"],
      })
    );
    // Models this account can invoke are served through InvokeModel on US
    // cross-region inference profiles, which may route to any US region.
    const invokeModels = [
      "anthropic.claude-sonnet-4-5-20250929-v1:0",
      "anthropic.claude-sonnet-4-6",
      "anthropic.claude-opus-4-6-v1",
    ];
    hostRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        resources: invokeModels.flatMap((m) => [
          `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/us.${m}`,
          `arn:aws:bedrock:*::foundation-model/${m}`,
        ]),
      })
    );

    // ── Boxes ────────────────────────────────────────────────────────────
    const script = (name: string) =>
      fs.readFileSync(path.join(__dirname, "../assets/wazuh-lab", name), "utf8");

    const spotBox = (
      name: string,
      instanceType: string,
      sg: ec2.SecurityGroup,
      role: iam.Role,
      userData: ec2.UserData,
      volumeGb: number
    ) => {
      const template = new ec2.LaunchTemplate(this, `${name}Template`, {
        machineImage: ami,
        instanceType: new ec2.InstanceType(instanceType),
        securityGroup: sg,
        role,
        userData,
        requireImdsv2: true,
        spotOptions: {
          requestType: ec2.SpotRequestType.PERSISTENT,
          interruptionBehavior: ec2.SpotInstanceInterruption.STOP,
        },
        blockDevices: [
          {
            deviceName: "/dev/sda1",
            volume: ec2.BlockDeviceVolume.ebs(volumeGb, {
              volumeType: ec2.EbsDeviceVolumeType.GP3,
              encrypted: true,
            }),
          },
        ],
      });
      const instance = new ec2.CfnInstance(this, name, {
        launchTemplate: {
          launchTemplateId: template.launchTemplateId,
          version: template.latestVersionNumber,
        },
        subnetId: lab.subnetId ?? vpc.publicSubnets[0].subnetId,
        tags: [{ key: "Name", value: `wazuh-lab-${name.toLowerCase()}` }],
      });
      return instance;
    };

    const hostUserData = ec2.UserData.custom(
      script("host-user-data.sh")
        .replace("__REPO_URL__", lab.repoUrl)
        .replace("__REPO_BRANCH__", lab.repoBranch)
    );
    const host = spotBox(
      "Host", lab.hostInstanceType, hostSg, hostRole, hostUserData, lab.hostVolumeGb
    );

    // The endpoint enrols with the host's private address, known only at deploy.
    const [beforeIp, afterIp] = script("endpoint-user-data.sh")
      .replace("__WAZUH_AGENT_VERSION__", lab.wazuhAgentVersion)
      .split("__MANAGER_IP__");
    const endpointUserData = ec2.UserData.custom(
      cdk.Fn.join("", [beforeIp, host.attrPrivateIp, afterIp])
    );
    const endpoint = spotBox(
      "Endpoint", lab.endpointInstanceType, endpointSg, endpointRole, endpointUserData, 20
    );

    const attacker = spotBox(
      "Attacker", lab.attackerInstanceType, attackerSg, attackerRole,
      ec2.UserData.custom(script("attacker-user-data.sh")), 10
    );

    new cdk.CfnOutput(this, "HostInstanceId", { value: host.ref });
    new cdk.CfnOutput(this, "EndpointInstanceId", { value: endpoint.ref });
    new cdk.CfnOutput(this, "AttackerInstanceId", { value: attacker.ref });
    new cdk.CfnOutput(this, "HostPrivateIp", { value: host.attrPrivateIp });
    new cdk.CfnOutput(this, "DashboardTunnelCommand", {
      value: cdk.Fn.join("", [
        `aws ssm start-session${lab.awsProfile ? ` --profile ${lab.awsProfile}` : ""} --region ${this.region} --target `,
        host.ref,
        " --document-name AWS-StartPortForwardingSession",
        ' --parameters "portNumber=443,localPortNumber=8443"',
      ]),
    });
  }
}
