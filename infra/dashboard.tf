locals {
  network_incident_widgets = [
    {
      type   = "text"
      x      = 0
      y      = 0
      width  = 24
      height = 3
      properties = {
        markdown = join("\n", [
          "# ML platform network incident triage",
          "Use the alarm state to set the time window, verify flow-log delivery, then compare rejected-packet volume with both Contributor Insights signals.",
          "Contributor rules: `${local.rejected_flow_rule_names.sources}` and `${local.rejected_flow_rule_names.destinations}`.",
        ])
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 3
      width  = 8
      height = 6
      properties = {
        title  = "Network alarm state"
        view   = "timeSeries"
        region = var.aws_region
        annotations = {
          alarms = [
            aws_cloudwatch_metric_alarm.rejected_packets.arn,
            aws_cloudwatch_metric_alarm.flow_log_delivery.arn,
          ]
        }
      }
    },
    {
      type   = "metric"
      x      = 8
      y      = 3
      width  = 8
      height = 6
      properties = {
        title   = "Rejected packet volume"
        view    = "timeSeries"
        stacked = false
        region  = var.aws_region
        period  = 300
        stat    = "Sum"
        metrics = [[
          "MLPlatform/Network",
          "RejectedPackets",
          { id = "rejected", label = "Rejected packets" },
        ]]
        annotations = {
          horizontal = [{
            value = var.rejected_packet_alarm_threshold
            label = "Alarm threshold"
            color = "#d62728"
          }]
        }
      }
    },
    {
      type   = "metric"
      x      = 16
      y      = 3
      width  = 8
      height = 6
      properties = {
        title   = "Flow-log delivery gaps"
        view    = "timeSeries"
        stacked = false
        region  = var.aws_region
        period  = 300
        stat    = "Sum"
        metrics = [[
          "MLPlatform/Network",
          "SkippedFlowRecords",
          { id = "skipped", label = "SKIPDATA records" },
        ]]
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 9
      width  = 12
      height = 6
      properties = {
        title   = "Rejected sources: concentration and cardinality"
        view    = "timeSeries"
        stacked = false
        region  = var.aws_region
        period  = 300
        metrics = [
          [{
            expression = "INSIGHT_RULE_METRIC(\"${local.rejected_flow_rule_names.sources}\", \"MaxContributorValue\")"
            id         = "source_top"
            label      = "Top source packet total"
          }],
          [{
            expression = "INSIGHT_RULE_METRIC(\"${local.rejected_flow_rule_names.sources}\", \"UniqueContributors\")"
            id         = "source_unique"
            label      = "Unique source/interface/direction tuples"
            yAxis      = "right"
          }],
        ]
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 9
      width  = 12
      height = 6
      properties = {
        title   = "Rejected destinations: concentration and cardinality"
        view    = "timeSeries"
        stacked = false
        region  = var.aws_region
        period  = 300
        metrics = [
          [{
            expression = "INSIGHT_RULE_METRIC(\"${local.rejected_flow_rule_names.destinations}\", \"MaxContributorValue\")"
            id         = "destination_top"
            label      = "Top destination packet total"
          }],
          [{
            expression = "INSIGHT_RULE_METRIC(\"${local.rejected_flow_rule_names.destinations}\", \"UniqueContributors\")"
            id         = "destination_unique"
            label      = "Unique destination/port/protocol tuples"
            yAxis      = "right"
          }],
        ]
      }
    },
    {
      type   = "text"
      x      = 0
      y      = 15
      width  = 24
      height = 5
      properties = {
        markdown = join("\n", [
          "## Incident record checklist",
          "1. Record alarm start/end, ticket ID and affected environment.",
          "2. Confirm `SkippedFlowRecords = 0`; otherwise mark network evidence incomplete.",
          "3. Inspect both Contributor Insights reports and correlate the leading tuples with ALB/application logs.",
          "4. Record the security-group, route-table or endpoint-policy change ID—or explicitly record `no infrastructure change`.",
          "5. Preserve the time window and rule names in the incident timeline; contributor rank does not establish malicious intent.",
        ])
      }
    },
  ]
}

resource "aws_cloudwatch_dashboard" "network_incident" {
  count = var.enable_network_incident_dashboard ? 1 : 0

  dashboard_name = var.network_incident_dashboard_name
  dashboard_body = jsonencode({
    start          = "-PT6H"
    periodOverride = "inherit"
    widgets        = local.network_incident_widgets
  })

  lifecycle {
    precondition {
      condition     = var.enable_vpc_flow_contributor_insights
      error_message = "The network incident dashboard requires enable_vpc_flow_contributor_insights = true."
    }
  }
}

output "network_incident_dashboard" {
  value = var.enable_network_incident_dashboard ? {
    name = aws_cloudwatch_dashboard.network_incident[0].dashboard_name
    arn  = aws_cloudwatch_dashboard.network_incident[0].dashboard_arn
  } : null
  description = "Enabled CloudWatch dashboard for rejected-flow incident triage; null when disabled."
}
