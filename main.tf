module "cloudtrail_alerts" {
  source = "./modules/alerts"

  sns_email                 = "patrick.hoffmann@sva.de"         # Replace with your email
  cloudtrail_log_group_name = "aws-controltower/CloudTrailLogs" # Replace with your CloudTrail log group name
  high_volume     = true
}
