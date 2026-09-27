locals {
  availability_slo = 0.999

  # Multi-window, multi-burn-rate alerting. The paired windows must both
  # breach before the related composite alarm changes state.
  slo_burn_windows = {
    page_short = {
      period_seconds   = 300
      minimum_requests = 100
      burn_rate        = 14.4
    }
    page_long = {
      period_seconds   = 3600
      minimum_requests = 1200
      burn_rate        = 14.4
    }
    ticket_short = {
      period_seconds   = 1800
      minimum_requests = 600
      burn_rate        = 6.0
    }
    ticket_long = {
      period_seconds   = 21600
      minimum_requests = 7200
      burn_rate        = 6.0
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "slo_burn_window" {
  for_each = local.slo_burn_windows

  alarm_name          = "ml-inference-slo-${replace(each.key, "_", "-")}"
  alarm_description   = "ALB target 5xx error-budget burn for the ${each.key} window."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 100 * (1 - local.availability_slo) * each.value.burn_rate
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "error_rate"
    expression  = "IF(requests >= ${each.value.minimum_requests}, 100 * errors / requests, 0)"
    label       = "Target 5xx error rate (%)"
    return_data = true
  }

  metric_query {
    id          = "errors"
    return_data = false

    metric {
      metric_name = "HTTPCode_Target_5XX_Count"
      namespace   = "AWS/ApplicationELB"
      period      = each.value.period_seconds
      stat        = "Sum"

      dimensions = {
        LoadBalancer = var.alb_dimension
      }
    }
  }

  metric_query {
    id          = "requests"
    return_data = false

    metric {
      metric_name = "RequestCount"
      namespace   = "AWS/ApplicationELB"
      period      = each.value.period_seconds
      stat        = "Sum"

      dimensions = {
        LoadBalancer = var.alb_dimension
      }
    }
  }
}

resource "aws_cloudwatch_composite_alarm" "slo_page" {
  alarm_name        = "ml-inference-slo-page"
  alarm_description = "Page when both 5-minute and 1-hour fast-burn windows breach."
  alarm_rule = format(
    "ALARM(%s) AND ALARM(%s)",
    aws_cloudwatch_metric_alarm.slo_burn_window["page_short"].alarm_name,
    aws_cloudwatch_metric_alarm.slo_burn_window["page_long"].alarm_name,
  )
}

resource "aws_cloudwatch_composite_alarm" "slo_ticket" {
  alarm_name        = "ml-inference-slo-ticket"
  alarm_description = "Create a ticket when both 30-minute and 6-hour slow-burn windows breach."
  alarm_rule = format(
    "ALARM(%s) AND ALARM(%s)",
    aws_cloudwatch_metric_alarm.slo_burn_window["ticket_short"].alarm_name,
    aws_cloudwatch_metric_alarm.slo_burn_window["ticket_long"].alarm_name,
  )
}

output "slo_alarm_arns" {
  description = "Composite ALB availability SLO alarms; action routing is intentionally external."
  value = {
    page   = aws_cloudwatch_composite_alarm.slo_page.arn
    ticket = aws_cloudwatch_composite_alarm.slo_ticket.arn
  }
}
