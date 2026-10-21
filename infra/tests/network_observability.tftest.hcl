mock_provider "aws" {
  override_data {
    target = data.aws_availability_zones.available
    values = {
      names = ["eu-central-1a", "eu-central-1b"]
    }
  }
}

variables {
  ecs_cluster_name = "test-cluster"
  ecs_service_name = "test-service"
  alb_dimension    = "app/test/0123456789abcdef"
}

run "contributor_rules_are_explicitly_opted_out" {
  command = plan

  assert {
    condition = (
      length(aws_cloudwatch_contributor_insight_rule.rejected_sources) == 0
      && length(aws_cloudwatch_contributor_insight_rule.rejected_destinations) == 0
    )
    error_message = "Contributor Insights must remain off unless the chargeable feature is explicitly enabled."
  }

  assert {
    condition     = length(output.vpc_flow_contributor_insight_rules) == 0
    error_message = "The output must be empty when Contributor Insights is disabled."
  }
}

run "contributor_rules_preserve_rejected_flow_dimensions" {
  command = plan

  variables {
    enable_vpc_flow_contributor_insights = true
  }

  assert {
    condition = (
      length(aws_cloudwatch_contributor_insight_rule.rejected_sources) == 1
      && length(aws_cloudwatch_contributor_insight_rule.rejected_destinations) == 1
    )
    error_message = "Enabling Contributor Insights must create exactly two rejected-flow rules."
  }

  assert {
    condition = (
      aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_state == "ENABLED"
      && aws_cloudwatch_contributor_insight_rule.rejected_destinations[0].rule_state == "ENABLED"
    )
    error_message = "Both opt-in rules must start in the enabled state."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Schema.Name == "CloudWatchLogRule"
      && jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Schema.Version == 1
      && jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).LogFormat == "CLF"
    )
    error_message = "The source rule must use the CloudWatch CLF rule schema."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Fields["13"] == "action"
      && jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Fields["14"] == "log_status"
      && jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Fields["16"] == "traffic_path"
    )
    error_message = "The CLF aliases must stay aligned with the 16-field VPC Flow Log format."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_sources[0].rule_definition).Contribution.Keys
      == ["srcaddr", "interface_id", "flow_direction"]
    )
    error_message = "The source rule must retain source, interface and direction dimensions."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_contributor_insight_rule.rejected_destinations[0].rule_definition).Contribution.Keys
      == ["dstaddr", "dstport", "protocol"]
    )
    error_message = "The destination rule must retain address, port and protocol dimensions."
  }

  assert {
    condition = alltrue([
      for rule in [
        aws_cloudwatch_contributor_insight_rule.rejected_sources[0],
        aws_cloudwatch_contributor_insight_rule.rejected_destinations[0],
        ] : (
        jsondecode(rule.rule_definition).AggregateOn == "Sum"
        && jsondecode(rule.rule_definition).Contribution.ValueOf == "packets"
        && jsondecode(rule.rule_definition).Contribution.Filters == [
          { Match = "action", In = ["REJECT"] },
          { Match = "log_status", In = ["OK"] },
        ]
      )
    ])
    error_message = "Both rules must sum packet counts only for complete REJECT records."
  }

  assert {
    condition = output.vpc_flow_contributor_insight_rules == [
      "ml-platform-rejected-sources",
      "ml-platform-rejected-destinations",
    ]
    error_message = "The output must expose both enabled rule names for runbook integration."
  }
}

run "incident_dashboard_is_explicitly_opted_out" {
  command = plan

  variables {
    enable_vpc_flow_contributor_insights = true
  }

  assert {
    condition     = length(aws_cloudwatch_dashboard.network_incident) == 0
    error_message = "The incident dashboard must remain off unless explicitly enabled."
  }

  assert {
    condition     = output.network_incident_dashboard == null
    error_message = "The dashboard output must be null while the dashboard is disabled."
  }
}

run "incident_dashboard_requires_contributor_rules" {
  command = plan

  variables {
    enable_network_incident_dashboard = true
  }

  expect_failures = [aws_cloudwatch_dashboard.network_incident]
}

run "incident_dashboard_binds_alarms_metrics_and_reports" {
  command = plan

  variables {
    enable_vpc_flow_contributor_insights = true
    enable_network_incident_dashboard    = true
  }

  assert {
    condition     = length(aws_cloudwatch_dashboard.network_incident) == 1
    error_message = "The dashboard opt-in must create exactly one dashboard."
  }

  assert {
    condition = (
      local.network_incident_window == "-PT6H"
      && length(local.network_incident_widgets) == 7
    )
    error_message = "The dashboard must retain the bounded six-hour window and seven-widget incident layout."
  }

  assert {
    condition     = length(local.network_incident_widgets[1].properties.annotations.alarms) == 2
    error_message = "The alarm-state widget must bind both rejection and telemetry-delivery alarms."
  }

  assert {
    condition = (
      local.network_incident_widgets[2].properties.metrics[0][1] == "RejectedPackets"
      && local.network_incident_widgets[3].properties.metrics[0][1] == "SkippedFlowRecords"
    )
    error_message = "The dashboard must expose rejection volume and flow-log delivery gaps separately."
  }

  assert {
    condition = (
      local.network_incident_widgets[4].properties.metrics[0][0].expression == "INSIGHT_RULE_METRIC(\"ml-platform-rejected-sources\", \"MaxContributorValue\")"
      && local.network_incident_widgets[4].properties.metrics[1][0].expression == "INSIGHT_RULE_METRIC(\"ml-platform-rejected-sources\", \"UniqueContributors\")"
      && local.network_incident_widgets[5].properties.metrics[0][0].expression == "INSIGHT_RULE_METRIC(\"ml-platform-rejected-destinations\", \"MaxContributorValue\")"
      && local.network_incident_widgets[5].properties.metrics[1][0].expression == "INSIGHT_RULE_METRIC(\"ml-platform-rejected-destinations\", \"UniqueContributors\")"
    )
    error_message = "Both contributor widgets must show top-contributor concentration and unique-cardinality signals."
  }

  assert {
    condition = alltrue([
      strcontains(local.network_incident_widgets[6].properties.markdown, "ticket ID"),
      strcontains(local.network_incident_widgets[6].properties.markdown, "security-group"),
      strcontains(local.network_incident_widgets[6].properties.markdown, "route-table"),
      strcontains(local.network_incident_widgets[6].properties.markdown, "evidence incomplete"),
    ])
    error_message = "The dashboard must retain the minimum incident-record and evidence-quality checklist."
  }

  assert {
    condition     = output.network_incident_dashboard.name == "ml-platform-network-incidents"
    error_message = "The output must expose the governed dashboard name for runbook integration."
  }
}
