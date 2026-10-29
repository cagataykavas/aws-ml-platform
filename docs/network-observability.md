# VPC network observability

The platform's private subnets deliberately have no default Internet route. That boundary is safer
when operators can prove which flows were accepted, which were rejected, and whether telemetry
delivery itself is complete.

`infra/observability.tf` enables VPC Flow Logs for all accepted and rejected traffic and delivers
one-minute aggregates to a dedicated CloudWatch log group. A custom format retains addresses,
ports, protocol, packet and byte counts, action, delivery status, direction and traffic path.

The delivery role is separate from the inference task role. It can write only to the flow-log group
and use the CloudWatch Logs describe calls required by the VPC Flow Logs service.

Two metric filters turn the raw evidence into operational signals:

- `RejectedPackets` sums the packet count for `REJECT` records. Its alarm requires two consecutive
  five-minute breaches to reduce one-window noise.
- `SkippedFlowRecords` counts `SKIPDATA` records. Any occurrence alarms because the network audit
  trail may be incomplete.

For incident triage, the optional Contributor Insights layer preserves the high-cardinality details
that a single alarm metric cannot. Set `enable_vpc_flow_contributor_insights = true` to create two
rules that rank rejected packet totals by:

- source address, interface and flow direction;
- destination address, destination port and IP protocol number.

Both rules require `action = REJECT` and `log_status = OK`, so incomplete `SKIPDATA` records do not
distort the ranking. Their names are exported through `vpc_flow_contributor_insight_rules` for use
in dashboards and incident runbooks.

Set both observability flags to add the incident view:

```hcl
enable_vpc_flow_contributor_insights = true
enable_network_incident_dashboard    = true
```

The dashboard is fail-closed: it cannot be enabled without the contributor rules. It places the
two alarm states, rejected-packet volume, telemetry gaps and the source/destination contributor
signals in one bounded six-hour view. Each contributor panel compares the top contributor's packet
total with the number of unique contributor tuples, so an operator can distinguish one dominant
source or destination from a broad scan without copying high-cardinality addresses into metrics.

The final widget is an incident-record checklist. It requires a ticket and time window, an explicit
telemetry-completeness decision and the security-group, route-table or endpoint-policy change ID
associated with the spike. The dashboard does not persist the incident record; the operator must
write those fields into the organization's governed incident system.

Alarm actions are explicit inputs rather than placeholder resources:

```hcl
network_alarm_actions = [aws_sns_topic.platform_incidents.arn]
```

Only SNS topic and Lambda function ARNs are accepted because both ALARM and OK transitions use the
same targets. Every action must match the deployment partition and Region; SNS topics must also be
owned by the alarm account. A same-Region Lambda relay with an explicit resource policy remains the
supported cross-account path. Duplicate actions and unsupported resource types fail validation.
CloudWatch permits five actions per state transition, so the module accepts at most five external
actions, or four when the managed topic consumes the remaining slot. The managed topic cannot also
be supplied as an external action.

The empty default keeps pull-request validation credential-free. A deployment environment should
wire the list to governed targets, grant the exact alarm ARNs in destination policies and calibrate
`rejected_packet_alarm_threshold` from known-good traffic. ARN and topology validation does not
prove that a destination exists or can receive a live transition.

Alternatively, set `enable_managed_network_incident_topic = true` to attach both ALARM and OK
transitions to a repository-managed SNS topic. The topic uses a dedicated rotating customer-managed
KMS key. Its resource policy permits `SNS:Publish` only from the two exact CloudWatch alarm ARNs in
the current account and denies every non-TLS request. The KMS grant is independently scoped to the
same account, alarm ARNs and exact SNS encryption context. Existing `network_alarm_actions` remain
attached and duplicate action ARNs are removed.

The managed topic is an integration boundary, not an incident system by itself. Connect the
exported topic ARN to a governed subscriber and test delivery, retries and subscriber-side access
controls in the target environment. Enabling the topic creates KMS and SNS costs; disabling it
preserves the zero-resource default.

For a durable repository-managed boundary, enable the queue and declare its only consumer role:

```hcl
enable_managed_network_incident_topic                    = true
enable_managed_network_incident_queue                    = true
managed_network_incident_consumer_role_arn               = "arn:aws:iam::123456789012:role/network-incident-consumer"
managed_network_incident_max_receive_count               = 5
managed_network_incident_queue_age_threshold_seconds     = 300
managed_network_incident_queue_escalation_actions = [
  "arn:aws:sns:eu-central-1:123456789012:independent-paging",
]
```

This creates a customer-key-encrypted SQS subscription plus an encrypted 14-day dead-letter queue.
The queue policies accept `SendMessage` only from the exact managed topic in the current account,
deny non-TLS requests and give the declared role receive/delete/visibility access without publish
access. The KMS policy independently permits scoped SNS encryption and limits the consumer role to
decrypting the two queue encryption contexts. Messages move to the DLQ when either SNS cannot
deliver them or the consumer exceeds the configured receive count; the SNS envelope is retained so
operators can distinguish alarm metadata from the payload.

Two queue-health alarms close the silent-failure gap. The consumer alarm requires the oldest visible
message to remain above the configured age for three consecutive one-minute periods; a transient
burst therefore does not page. The dead-letter alarm changes state as soon as any failed message is
visible. Both alarms treat missing metrics as healthy and send ALARM and OK transitions through the
same encrypted topic. Their exact ARNs are added to the SNS and KMS resource policies rather than
granting CloudWatch wildcard publication.

Because queue-health notifications also enter the managed queue, enabling the queue requires at
least one unique action ARN in `managed_network_incident_queue_escalation_actions`. The module sends
both ALARM and OK transitions directly to those actions as well as to the managed topic, and rejects
the managed topic's own ARN as an escalation path. A stalled queue consumer therefore cannot be its
own only notification path. Because both state transitions use the same action list, only SNS topic
and Lambda function ARNs are accepted. Actions must use the deployment partition and Region; SNS
topics must also be in the alarm account. Use a Lambda relay with an explicit resource policy for a
cross-account destination. At most four independent actions are accepted because the managed topic
uses the fifth CloudWatch action slot.

CloudWatch does not verify that a configured action exists. The deployment owner must therefore
grant SNS publication or Lambda invocation to the exact alarm ARNs and source account. Lambda
policies should grant `lambda.alarms.cloudwatch.amazonaws.com`, not the general CloudWatch service
principal. Destination policy, KMS grants and subscriber health remain deployment responsibilities.
The alarms detect backlog symptoms; they do not automatically redrive or delete messages.

### Read-only deployed-route preflight

Mocked Terraform plans prove the intended resource shape, but not whether a deployed subscription
is confirmed or whether its live policies still match the repository contract. After deployment,
run the credentialed preflight from an identity with read-only SNS and SQS inspection permissions:

```bash
terraform -chdir=infra output -json managed_network_incident_route \
  | python scripts/verify_network_incident_route.py -
```

The identity needs `sns:GetTopicAttributes`, `sns:ListSubscriptionsByTopic`,
`sns:GetSubscriptionAttributes`, `sqs:GetQueueUrl` and `sqs:GetQueueAttributes` for the managed
resources. The verifier fails closed unless it observes:

- one confirmed subscription from the exact topic to the exact consumer queue;
- KMS identifiers on the topic, consumer queue and dead-letter queue;
- exact account/alarm constraints on CloudWatch publication and exact topic/account constraints on
  queue delivery;
- bounded consumer redrive and an SNS delivery-failure redrive path to the expected dead-letter
  queue;
- a dead-letter allow policy scoped to the consumer queue and retention of the SNS envelope.

Results are JSON so a deployment pipeline can archive the evidence without scraping prose. The
verifier deliberately makes no publish, receive, delete or alarm-state calls. That avoids disturbing
real incident traffic, but also means this check does not prove data-plane delivery, KMS key-policy
usability or consumer processing.

### Isolated data-plane delivery canary

Enable the separate canary path when a deployment gate must prove encrypted SNS-to-SQS delivery:

```hcl
enable_managed_network_incident_topic   = true
enable_network_incident_delivery_canary = true
network_incident_canary_role_arn        = "arn:aws:iam::123456789012:role/network-incident-canary"
```

The canary queue is not the incident consumer queue or its DLQ. Its subscription retains the SNS
envelope and has a `MessageAttributes` filter that accepts only `route_canary=true`; CloudWatch alarm
messages have no such attribute and therefore never enter the canary queue. The production
subscription independently permits missing or non-canary values and rejects `route_canary=true`, so
the probe never enters the production consumer queue. The queue uses the route
KMS key, retains messages for five minutes and grants receive/delete access only to the declared
runner role. Topic publication and KMS use are scoped to the same role and exact encryption contexts.

```bash
terraform -chdir=infra output -json managed_network_incident_route \
  | python scripts/run_network_incident_delivery_canary.py - \
      --receive-attempts 3 --wait-seconds 10
```

The dependency-free probe generates a unique run ID, publishes one filtered message, validates the
topic ARN, SNS envelope, attribute and complete inner payload, and deletes only that matching
delivery. Stale canaries are ignored rather than deleted; a malformed matching delivery fails closed.
Every AWS CLI call and the number and duration of long polls are bounded. The emitted JSON can be
archived as deployment evidence without including credentials or arbitrary message bodies.

The canary proves the dedicated topic-to-queue path and runner KMS permissions. It does not change an
alarm state, read or delete production incident traffic, execute the production consumer, or prove
redrive behavior. Keep the opt-in queue disabled where a live delivery gate is unnecessary.

### Non-production redrive canary

Use the manually dispatched `incident-redrive-canary` workflow when a deployment gate must verify
the live SQS retry and dead-letter policy. The workflow requires a separately protected GitHub
Environment, a dedicated source queue ending in `-fault-injection`, and its matching `-dlq`. The
production consumer ARN is validated only as a boundary: the source and DLQ must be different ARNs
in the same account and Region, and the runtime never resolves or calls the production queue.

Before credentials are requested, the route builder validates the expected account, Region, naming
contract and distinct queue identities. After OIDC exchange, the runtime verifies that both queue
URLs resolve to the declared ARNs, the source has a bounded `maxReceiveCount` of 2–5, the DLQ admits
redrive from only that source, and both approximate visible/in-flight counts are zero. It then sends
one exact poison payload, forces repeated visibility only for that payload, observes it in the DLQ,
and deletes only the verified DLQ message. Unrelated traffic, malformed receive counts, policy drift
and exhausted polling fail closed.

The drill additionally requires the passing live-boundary receipt from the immediately preceding
preflight. It verifies the exact check set, current workflow run/attempt authorization identifier and
queue-route commitment before any SQS call. A canonical SHA-256 commitment to that receipt travels
inside the poison message and final receipt, so archived evidence can link one boundary decision to
one execution without exposing IAM policies or queue ARNs.

The receipt commits to the complete route with SHA-256 and records bounded receive evidence without
including queue ARNs or message bodies. Configure the OIDC role without any production-queue
permission and scope its SQS calls to the two fault queues. A failed run attempts to delete the last
known source receipt, but AWS may reject a stale handle; short non-production retention remains a
required backstop.

This drill deterministically emulates a consumer that refuses the poison message. It does not invoke
the real application consumer, validate Lambda/ECS error handling, prove queue-count freshness, or
exercise production traffic. Pull-request CI uses fake AWS responses and makes no live AWS claim.

The queue fails closed unless the managed topic, consumer role and independent escalation action
are all supplied. It does not
create the consumer workload, automated redrive, paging workflow or cross-account access. Those
remain deployment-specific controls. The isolated canary proves its own filtered route, while the
production consumer and dead-letter path still require environment-specific validation.

Contributor Insights and the dashboard are disabled by default because enabled rules incur
per-event analysis charges and dashboards can add account-level cost. Enable them deliberately in
environments where faster attribution justifies that cost; the rules target one exact log group
rather than a wildcard. Dashboard viewers need permission to read the dashboard, alarm/metric data
and Contributor Insights reports.

## Limits and trust boundary

Flow Logs are diagnostic metadata, not packet capture. They do not contain payloads and cannot
prove application-layer intent. Delivery is eventually available, aggregation loses per-packet
ordering, and AWS may emit `SKIPDATA` under internal capacity constraints. NAT, load-balancer and
application logs remain separate evidence sources.

The metric alarm still aggregates all rejected packets and the insight rules identify top
contributors rather than intent. A noisy but harmless source can therefore dominate both views.
Production deployments should correlate contributors with security-group changes, load-balancer
and application logs, and known scanner ranges. Log retention and alarm routing must also follow
the organization's data-classification and incident-response policies.
