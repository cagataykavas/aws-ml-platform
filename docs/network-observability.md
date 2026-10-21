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

Alarm actions are explicit inputs rather than placeholder resources:

```hcl
network_alarm_actions = [aws_sns_topic.platform_incidents.arn]
```

The empty default keeps pull-request validation credential-free. A deployment environment should
wire the list to a governed SNS/incident route and calibrate `rejected_packet_alarm_threshold` from
known-good traffic.

Contributor Insights is disabled by default because enabled rules incur per-event analysis charges
and analyze only new records. Enable it deliberately in environments where the faster attribution
justifies that cost; the rules target one exact log group rather than a wildcard.

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
