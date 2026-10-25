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

The empty default keeps pull-request validation credential-free. A deployment environment should
wire the list to a governed SNS/incident route and calibrate `rejected_packet_alarm_threshold` from
known-good traffic.

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
own only notification path. The external action's resource policy, KMS grants and subscriber health
remain the deployment owner's responsibility. The alarms detect backlog symptoms; they do not
automatically redrive or delete messages.

The queue fails closed unless the managed topic, consumer role and independent escalation action
are all supplied. It does not
create the consumer workload, automated redrive, paging workflow or cross-account access. Those
remain deployment-specific controls, and live delivery still needs a canary because mocked Terraform
plans prove configuration shape rather than AWS runtime behavior.

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
