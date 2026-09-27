mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-central-1a", "eu-central-1b"]
      state = "available"
    }
  }
}

variables {
  aws_region       = "eu-central-1"
  ecs_cluster_name = "portfolio-cluster"
  ecs_service_name = "inference-api"
  alb_dimension    = "app/portfolio-alb/0123456789abcdef"
}

run "availability_slo_alarm_contract" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.slo_burn_window) == 4
    error_message = "The SLO must retain both page and ticket window pairs."
  }

  assert {
    condition     = abs(aws_cloudwatch_metric_alarm.slo_burn_window["page_short"].threshold - 1.44) < 0.000001
    error_message = "The page windows must use a 14.4x burn rate for a 99.9% SLO."
  }

  assert {
    condition     = abs(aws_cloudwatch_metric_alarm.slo_burn_window["page_long"].threshold - 1.44) < 0.000001
    error_message = "The long page window must confirm the same fast burn rate."
  }

  assert {
    condition     = abs(aws_cloudwatch_metric_alarm.slo_burn_window["ticket_short"].threshold - 0.6) < 0.000001
    error_message = "The ticket windows must use a 6x burn rate for a 99.9% SLO."
  }

  assert {
    condition     = abs(aws_cloudwatch_metric_alarm.slo_burn_window["ticket_long"].threshold - 0.6) < 0.000001
    error_message = "The long ticket window must confirm the same slow burn rate."
  }

  assert {
    condition = alltrue([
      for alarm in aws_cloudwatch_metric_alarm.slo_burn_window :
      alarm.treat_missing_data == "notBreaching" &&
      alarm.evaluation_periods == 1 &&
      alarm.datapoints_to_alarm == 1
    ])
    error_message = "Window alarms must keep explicit missing-data and evaluation semantics."
  }

  assert {
    condition = alltrue([
      for alarm in aws_cloudwatch_metric_alarm.slo_burn_window :
      length([for query in alarm.metric_query : query if query.id == "errors"]) == 1 &&
      length([for query in alarm.metric_query : query if query.id == "requests"]) == 1 &&
      length([for query in alarm.metric_query : query if query.id == "error_rate" && query.return_data]) == 1
    ])
    error_message = "Every burn window must compute one request-normalized 5xx error rate."
  }

  assert {
    condition = aws_cloudwatch_composite_alarm.slo_page.alarm_rule == format(
      "ALARM(%s) AND ALARM(%s)",
      aws_cloudwatch_metric_alarm.slo_burn_window["page_short"].alarm_name,
      aws_cloudwatch_metric_alarm.slo_burn_window["page_long"].alarm_name,
    )
    error_message = "Paging must require both fast-burn windows."
  }

  assert {
    condition = aws_cloudwatch_composite_alarm.slo_ticket.alarm_rule == format(
      "ALARM(%s) AND ALARM(%s)",
      aws_cloudwatch_metric_alarm.slo_burn_window["ticket_short"].alarm_name,
      aws_cloudwatch_metric_alarm.slo_burn_window["ticket_long"].alarm_name,
    )
    error_message = "Ticketing must require both slow-burn windows."
  }
}
