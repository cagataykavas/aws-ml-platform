mock_provider "aws" {
  override_data {
    target = data.aws_availability_zones.available
    values = {
      names = ["eu-central-1a", "eu-central-1b"]
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
    }
  }

}

variables {
  ecs_cluster_name = "test-cluster"
  ecs_service_name = "test-service"
  alb_dimension    = "app/test/0123456789abcdef"
}

run "managed_incident_route_is_explicitly_opted_out" {
  command = plan

  assert {
    condition = (
      length(aws_kms_key.network_incidents) == 0
      && length(aws_sns_topic.network_incidents) == 0
      && length(aws_sns_topic_policy.network_incidents) == 0
      && length(aws_sqs_queue.network_incidents) == 0
      && length(aws_sqs_queue.network_incident_dlq) == 0
      && length(aws_sns_topic_subscription.network_incident_queue) == 0
    )
    error_message = "The managed incident route and subscriber must remain absent unless explicitly enabled."
  }

  assert {
    condition     = output.managed_network_incident_route == null
    error_message = "The managed incident output must be null while disabled."
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.rejected_packets.alarm_actions) == 0
      && length(aws_cloudwatch_metric_alarm.flow_log_delivery.alarm_actions) == 0
    )
    error_message = "Opt-out must preserve the empty default alarm route."
  }
}

run "managed_incident_route_is_encrypted_scoped_and_tls_only" {
  command = plan

  variables {
    enable_managed_network_incident_topic = true
  }

  assert {
    condition = (
      length(aws_kms_key.network_incidents) == 1
      && length(aws_sns_topic.network_incidents) == 1
      && length(aws_sns_topic_policy.network_incidents) == 1
    )
    error_message = "Opt-in must create exactly one KMS key, SNS topic and topic policy."
  }

  assert {
    condition = (
      aws_kms_key.network_incidents[0].enable_key_rotation
      && aws_kms_key.network_incidents[0].deletion_window_in_days == 30
      && aws_sns_topic.network_incidents[0].name == "ml-platform-network-incidents"
    )
    error_message = "The managed topic must use a rotating customer-managed key with a recovery window."
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.rejected_packets.alarm_actions) == 1
      && length(aws_cloudwatch_metric_alarm.rejected_packets.ok_actions) == 1
      && length(aws_cloudwatch_metric_alarm.flow_log_delivery.alarm_actions) == 1
      && length(aws_cloudwatch_metric_alarm.flow_log_delivery.ok_actions) == 1
    )
    error_message = "Both ALARM and OK transitions must route through the managed topic."
  }

  assert {
    condition = (
      jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[1].Principal.Service == "cloudwatch.amazonaws.com"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[1].Action == "SNS:Publish"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[1].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
      && length(jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[1].Condition.ArnEquals["aws:SourceArn"]) == 2
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[2].Effect == "Deny"
      && jsondecode(aws_sns_topic_policy.network_incidents[0].policy).Statement[2].Condition.Bool["aws:SecureTransport"] == "false"
    )
    error_message = "The topic policy must allow only scoped CloudWatch alarms and deny insecure transport."
  }

  assert {
    condition = (
      jsondecode(aws_kms_key.network_incidents[0].policy).Statement[1].Principal.Service == "cloudwatch.amazonaws.com"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[1].Action == ["kms:Decrypt", "kms:GenerateDataKey*"]
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[1].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[1].Condition.StringEquals["kms:EncryptionContext:aws:sns:topicArn"] == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && length(jsondecode(aws_kms_key.network_incidents[0].policy).Statement[1].Condition.ArnEquals["aws:SourceArn"]) == 2
    )
    error_message = "The KMS grant must bind CloudWatch to the account, exact alarms and SNS encryption context."
  }

  assert {
    condition     = output.managed_network_incident_route.topic_arn == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
    error_message = "The route output must expose the deterministic managed topic ARN."
  }
}

run "managed_route_preserves_and_deduplicates_external_actions" {
  command = plan

  variables {
    enable_managed_network_incident_topic = true
    network_alarm_actions = [
      "arn:aws:sns:eu-central-1:123456789012:external-incidents",
      "arn:aws:sns:eu-central-1:123456789012:external-incidents",
    ]
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.rejected_packets.alarm_actions) == 2
      && length(aws_cloudwatch_metric_alarm.flow_log_delivery.alarm_actions) == 2
      && contains(
        aws_cloudwatch_metric_alarm.rejected_packets.alarm_actions,
        "arn:aws:sns:eu-central-1:123456789012:external-incidents",
      )
    )
    error_message = "Managed routing must preserve external actions without duplicate deliveries."
  }
}

run "managed_incident_queue_requires_the_managed_topic" {
  command = plan

  variables {
    enable_managed_network_incident_queue       = true
    managed_network_incident_consumer_role_arn = "arn:aws:iam::123456789012:role/network-incident-consumer"
  }

  expect_failures = [terraform_data.managed_network_incident_queue_contract[0]]
}

run "managed_incident_queue_requires_an_explicit_consumer" {
  command = plan

  variables {
    enable_managed_network_incident_topic = true
    enable_managed_network_incident_queue = true
  }

  expect_failures = [terraform_data.managed_network_incident_queue_contract[0]]
}

run "managed_incident_queue_rejects_malformed_consumer_arns" {
  command = plan

  variables {
    enable_managed_network_incident_topic       = true
    enable_managed_network_incident_queue       = true
    managed_network_incident_consumer_role_arn = "arn:aws:iam::123456789012:user/not-a-role"
  }

  expect_failures = [var.managed_network_incident_consumer_role_arn]
}

run "managed_incident_queue_rejects_derived_names_over_the_sqs_limit" {
  command = plan

  variables {
    enable_managed_network_incident_topic       = true
    enable_managed_network_incident_queue       = true
    managed_network_incident_consumer_role_arn = "arn:aws:iam::123456789012:role/network-incident-consumer"
    managed_network_incident_topic_name         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  expect_failures = [terraform_data.managed_network_incident_queue_contract[0]]
}

run "managed_incident_queue_is_encrypted_scoped_and_redriven" {
  command = plan

  variables {
    enable_managed_network_incident_topic       = true
    enable_managed_network_incident_queue       = true
    managed_network_incident_consumer_role_arn = "arn:aws:iam::123456789012:role/network-incident-consumer"
    managed_network_incident_max_receive_count = 7
  }

  assert {
    condition = (
      length(terraform_data.managed_network_incident_queue_contract) == 1
      && length(aws_sqs_queue.network_incidents) == 1
      && length(aws_sqs_queue.network_incident_dlq) == 1
      && length(aws_sqs_queue_policy.network_incident_queues) == 2
      && length(aws_sns_topic_subscription.network_incident_queue) == 1
    )
    error_message = "Queue opt-in must create one subscriber, one DLQ, two policies and one subscription."
  }

  assert {
    condition = (
      aws_sqs_queue.network_incidents[0].kms_data_key_reuse_period_seconds == 300
      && aws_sqs_queue.network_incident_dlq[0].kms_data_key_reuse_period_seconds == 300
      && aws_sqs_queue.network_incident_dlq[0].message_retention_seconds == 1209600
    )
    error_message = "Both queues must bound KMS data-key reuse and retain dead letters for 14 days."
  }

  assert {
    condition = (
      jsondecode(aws_sqs_queue.network_incidents[0].redrive_policy).deadLetterTargetArn == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer-dlq"
      && jsondecode(aws_sqs_queue.network_incidents[0].redrive_policy).maxReceiveCount == 7
      && jsondecode(aws_sqs_queue.network_incident_dlq[0].redrive_allow_policy).redrivePermission == "byQueue"
      && jsondecode(aws_sqs_queue.network_incident_dlq[0].redrive_allow_policy).sourceQueueArns == ["arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"]
      && jsondecode(aws_sns_topic_subscription.network_incident_queue[0].redrive_policy).deadLetterTargetArn == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer-dlq"
    )
    error_message = "Consumer and subscription failures must redrive only to the bounded incident DLQ."
  }

  assert {
    condition = (
      aws_sns_topic_subscription.network_incident_queue[0].protocol == "sqs"
      && aws_sns_topic_subscription.network_incident_queue[0].endpoint == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
      && aws_sns_topic_subscription.network_incident_queue[0].raw_message_delivery == false
    )
    error_message = "The managed topic must retain its SNS envelope when delivering to the exact queue."
  }

  assert {
    condition = alltrue([
      for queue_policy in aws_sqs_queue_policy.network_incident_queues : (
        jsondecode(queue_policy.policy).Statement[0].Principal.Service == "sns.amazonaws.com"
        && jsondecode(queue_policy.policy).Statement[0].Action == "sqs:SendMessage"
        && jsondecode(queue_policy.policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
        && jsondecode(queue_policy.policy).Statement[0].Condition.ArnEquals["aws:SourceArn"] == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
        && jsondecode(queue_policy.policy).Statement[1].Principal.AWS == "arn:aws:iam::123456789012:role/network-incident-consumer"
        && !contains(jsondecode(queue_policy.policy).Statement[1].Action, "sqs:SendMessage")
        && jsondecode(queue_policy.policy).Statement[2].Condition.StringNotLike["aws:PrincipalArn"] == "arn:aws:iam::123456789012:role/network-incident-consumer"
        && jsondecode(queue_policy.policy).Statement[3].Effect == "Deny"
        && jsondecode(queue_policy.policy).Statement[4].Condition.Bool["aws:SecureTransport"] == "false"
      )
    ])
    error_message = "Queue policies must separate exact-topic delivery from TLS-only consumer access."
  }

  assert {
    condition = (
      jsondecode(aws_sqs_queue_policy.network_incident_queues[0].policy).Statement[3].Condition.ArnNotLike["aws:SourceArn"] == ["arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"]
      && jsondecode(aws_sqs_queue_policy.network_incident_queues[1].policy).Statement[3].Condition.ArnNotLike["aws:SourceArn"] == [
        "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents",
        "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer",
      ]
    )
    error_message = "The main queue must admit only SNS while the DLQ also admits its exact redrive source."
  }

  assert {
    condition = (
      jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Principal.Service == "sns.amazonaws.com"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Condition.StringEquals["aws:SourceAccount"] == "123456789012"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[2].Condition.ArnEquals["aws:SourceArn"] == "arn:aws:sns:eu-central-1:123456789012:ml-platform-network-incidents"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[3].Principal.AWS == "arn:aws:iam::123456789012:role/network-incident-consumer"
      && jsondecode(aws_kms_key.network_incidents[0].policy).Statement[3].Action == "kms:Decrypt"
      && length(jsondecode(aws_kms_key.network_incidents[0].policy).Statement[3].Condition.ArnEquals["kms:EncryptionContext:aws:sqs:arn"]) == 2
    )
    error_message = "KMS access must separate scoped SNS production from queue-bound consumer decryption."
  }

  assert {
    condition = (
      output.managed_network_incident_route.queue_arn == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer"
      && output.managed_network_incident_route.dead_letter_queue_arn == "arn:aws:sqs:eu-central-1:123456789012:ml-platform-network-incidents-consumer-dlq"
    )
    error_message = "The route output must expose both durable subscriber queue ARNs."
  }
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
