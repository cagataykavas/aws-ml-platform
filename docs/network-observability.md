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
