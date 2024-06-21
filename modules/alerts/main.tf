provider "aws" {
  region = "eu-central-1" # Replace with your AWS region
}

locals {
  org_alerts_final          = var.org_alerts || var.high_volume
  get_tokens_final          = var.get_tokens || var.high_volume
  idp_alerts_final          = var.idp_alerts || var.high_volume
  sso_alerts_final          = var.sso_alerts || var.high_volume
  cloudtrail_alerts_final   = var.cloudtrail_alerts || var.high_volume
  guardduty_alerts_final    = var.guardduty_alerts || var.high_volume
  config_alerts_final       = var.config_alerts || var.high_volume
  kms_alerts_final          = var.kms_alerts || var.high_volume
  root_alerts_final         = var.root_alerts || var.high_volume
  no_mfa_login_alerts_final = var.no_mfa_login_alerts || var.high_volume
  failed_login_final        = var.failed_login || var.high_volume

  destroy_data_events_final          = var.destroy_data_events || var.medium_volume
  compute_not_main_region_final      = var.compute_not_main_region || var.medium_volume
  invoke_model_not_main_region_final = var.invoke_model_not_main_region || var.medium_volume
  gateway_events_final               = var.gateway_events || var.medium_volume

  iam_events_final            = var.iam_events || var.high_volume
  nacl_events_final           = var.nacl_events || var.high_volume
  route_table_events_final    = var.route_table_events || var.high_volume
  security_group_events_final = var.security_group_events || var.high_volume
  vpc_events_final            = var.vpc_events || var.high_volume
}


resource "aws_sns_topic" "cloudtrail_alerts" {
  name = "cloudtrail-alert-topic"
}

resource "aws_sns_topic_subscription" "cloudtrail_email_subscription" {
  topic_arn = aws_sns_topic.cloudtrail_alerts.arn
  protocol  = "email"       # Change to your preferred protocol
  endpoint  = var.sns_email # Replace with your email or endpoint
}

resource "aws_cloudwatch_log_metric_filter" "org_events_filter" {
  count          = local.org_alerts_final ? 1 : 0
  name           = "orgEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = CloseAccount) || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdatePolicy\") || ($.eventName = \"UpdateOrganizationalUnit\")) }"

  metric_transformation {
    name      = "orgEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "org_events_alerts" {
  count               = local.org_alerts_final ? 1 : 0
  alarm_name          = "orgEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.org_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.org_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors organizational events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "get_tokens_filter" {
  count          = local.org_alerts_final ? 1 : 0
  name           = "getTokensFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ ($.eventName = GetFederationToken)|| ($.eventName = GetSessionToken) }"

  metric_transformation {
    name      = "getTokensFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "get_tokens_alerts" {
  count               = local.get_tokens_final ? 1 : 0
  alarm_name          = "getTokensAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.get_tokens_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.get_tokens_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors get token events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "idp_events_filter" {
  count          = local.idp_alerts_final ? 1 : 0
  name           = "idpEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ ($.eventName = CreateSAMLProvider) || ($.eventName = CreateOIDCProvider) || ($.eventName = StartSSO)}"

  metric_transformation {
    name      = "idpEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "idp_events_alerts" {
  count               = local.idp_alerts_final ? 1 : 0
  alarm_name          = "idpEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.idp_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.idp_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors IDP Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "sso_events_filter" {
  count          = local.sso_alerts_final ? 1 : 0
  name           = "ssoEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ (($.eventSource = sso.amazonaws.com) && ($.eventName = CreateAccountAssignment)) || (($.eventSource = sso-directory.amazonaws.com) && (($.eventName = CreateGroup)|| ($.eventName = CreateUser) || ($.eventName = AddMemberToGroup) || ($.eventName = CreatePermissionSet) || ($.eventName = AttachManagedPolicyToPermissionSet)))}"

  metric_transformation {
    name      = "ssoEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sso_events_alerts" {
  count               = local.sso_alerts_final ? 1 : 0
  alarm_name          = "ssoEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.sso_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.sso_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors sso Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}


resource "aws_cloudwatch_log_metric_filter" "cloudtrail_events_filter" {
  count          = local.cloudtrail_alerts_final ? 1 : 0
  name           = "cloudtrailEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ ($.eventName = PutEventSelectors) || ($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"

  metric_transformation {
    name      = "cloudtrailEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_events_alerts" {
  count               = local.cloudtrail_alerts_final ? 1 : 0
  alarm_name          = "cloudtrailEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cloudtrail_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.cloudtrail_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors cloudtrail Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}


resource "aws_cloudwatch_log_metric_filter" "guardduty_events_filter" {
  count          = local.guardduty_alerts_final ? 1 : 0
  name           = "guardutyEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ (($.eventName = PutAccountSettingDefault) && ($.requestParameters.name = guardDutyActivate) && ($.requestParameters.value = disabled)) || ($.eventName = DeleteDetector)}"

  metric_transformation {
    name      = "guarddutyEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "guardduty_events_alerts" {
  count               = local.guardduty_alerts_final ? 1 : 0
  alarm_name          = "guarddutyEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.guardduty_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.guardduty_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors guardduty Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "config_events_filter" {
  count          = local.config_alerts_final ? 1 : 0
  name           = "configEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}"

  metric_transformation {
    name      = "configEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "config_events_alerts" {
  count               = local.config_alerts_final ? 1 : 0
  alarm_name          = "configEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.config_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.config_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors config Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "kms_events_filter" {
  count          = local.kms_alerts_final ? 1 : 0
  name           = "kmsEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}"

  metric_transformation {
    name      = "kmsEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_events_alerts" {
  count               = local.kms_alerts_final ? 1 : 0
  alarm_name          = "kmsEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.kms_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.kms_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors kms Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "root_events_filter" {
  count          = local.root_alerts_final ? 1 : 0
  name           = "rootEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"

  metric_transformation {
    name      = "rootEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_events_alerts" {
  count               = local.root_alerts_final ? 1 : 0
  alarm_name          = "rootEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.root_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors root Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "no_mfa_logins_filter" {
  count          = local.no_mfa_login_alerts_final ? 1 : 0
  name           = "noMFALoginFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"

  metric_transformation {
    name      = "noMFALoginFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_login_alerts" {
  count               = local.no_mfa_login_alerts_final ? 1 : 0
  alarm_name          = "noMFALoginAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.no_mfa_logins_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.no_mfa_logins_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors logins without MFA."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "failed_login_events_filter" {
  count          = local.failed_login_final ? 1 : 0
  name           = "failedLoginEventsFilter"
  log_group_name = var.cloudtrail_log_group_name

  pattern = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"

  metric_transformation {
    name      = "failedLoginEventsFilter"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "failed_login_events_alerts" {
  count               = local.failed_login_final ? 1 : 0
  alarm_name          = "failedLoginEventsAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.failed_login_events_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.failed_login_events_filter[0].metric_transformation[0].namespace
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"

  alarm_description = "This alarm monitors failed Login Events."
  alarm_actions     = [aws_sns_topic.cloudtrail_alerts.arn]
  ok_actions        = [aws_sns_topic.cloudtrail_alerts.arn]
}
