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
