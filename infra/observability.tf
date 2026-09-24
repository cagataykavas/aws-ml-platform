locals {
  vpc_flow_log_format = join(" ", [
    "$${version}",
    "$${account-id}",
    "$${interface-id}",
    "$${srcaddr}",
    "$${dstaddr}",
    "$${srcport}",
    "$${dstport}",
    "$${protocol}",
    "$${packets}",
    "$${bytes}",
    "$${start}",
    "$${end}",
    "$${action}",
    "$${log-status}",
    "$${flow-direction}",
    "$${traffic-path}",
  ])
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/ml-platform/vpc-flow"
  retention_in_days = var.vpc_flow_log_retention_days

  tags = {
    Workload = "ml-platform"
    Signal   = "network-flow"
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name_prefix = "ml-vpc-flow-logs-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteFlowLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = ["${aws_cloudwatch_log_group.vpc_flow.arn}:*"]
      },
      {
        Sid    = "DescribeFlowLogDestination"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_flow_log" "vpc" {
  iam_role_arn             = aws_iam_role.vpc_flow_logs.arn
  log_destination          = aws_cloudwatch_log_group.vpc_flow.arn
  log_destination_type     = "cloud-watch-logs"
  log_format               = local.vpc_flow_log_format
  max_aggregation_interval = 60
  traffic_type             = "ALL"
  vpc_id                   = aws_vpc.main.id

  tags = {
    Name = "ml-platform-vpc-flow"
  }
}

resource "aws_cloudwatch_log_metric_filter" "rejected_packets" {
  name           = "ml-platform-rejected-packets"
  log_group_name = aws_cloudwatch_log_group.vpc_flow.name
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action = REJECT, log_status, flow_direction, traffic_path]"

  metric_transformation {
    name          = "RejectedPackets"
    namespace     = "MLPlatform/Network"
    value         = "$packets"
    default_value = 0
    unit          = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "skipped_flow_records" {
  name           = "ml-platform-skipped-flow-records"
  log_group_name = aws_cloudwatch_log_group.vpc_flow.name
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, log_status = SKIPDATA, flow_direction, traffic_path]"

  metric_transformation {
    name          = "SkippedFlowRecords"
    namespace     = "MLPlatform/Network"
    value         = "1"
    default_value = 0
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "rejected_packets" {
  alarm_name          = "ml-platform-rejected-packets"
  alarm_description   = "Rejected VPC packets exceeded the calibrated operational threshold."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = aws_cloudwatch_log_metric_filter.rejected_packets.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.rejected_packets.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = var.rejected_packet_alarm_threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.network_alarm_actions
  ok_actions          = var.network_alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "flow_log_delivery" {
  alarm_name          = "ml-platform-flow-log-delivery-health"
  alarm_description   = "VPC Flow Logs emitted SKIPDATA records; network evidence may be incomplete."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = aws_cloudwatch_log_metric_filter.skipped_flow_records.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.skipped_flow_records.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.network_alarm_actions
  ok_actions          = var.network_alarm_actions
}

output "vpc_flow_log_id" {
  value       = aws_flow_log.vpc.id
  description = "VPC Flow Log capturing accepted and rejected traffic."
}

output "vpc_flow_log_group" {
  value       = aws_cloudwatch_log_group.vpc_flow.name
  description = "CloudWatch log group retaining structured VPC network evidence."
}
