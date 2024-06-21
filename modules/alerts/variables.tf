variable "sns_email" {
  description = "The email address to receive SNS notifications"
  type        = string
}

variable "cloudtrail_log_group_name" {
  description = "The name of the CloudTrail log group"
  type        = string
}

variable "low_volume" {
  description = "Enable all low volume alerts - there should not be too much noise in these alerts but each noise should be investigated and accounted for"
  type        = bool
  default     = false
}

variable "medium_volume" {
  description = "Enable all medium volume alerts"
  type        = bool
  default     = false
}

variable "high_volume" {
  description = "Enable all high volume alerts"
  type        = bool
  default     = false
}

variable "org_alerts" {
  description = "Enable alerts for potentially malicious organization events"
  type        = bool
  default     = false
}

variable "get_tokens" {
  description = "Enable alerts for potentially malicious get token events"
  type        = bool
  default     = false
}

variable "idp_alerts" {
  description = "Enable alerts for creation of new idps"
  type        = bool
  default     = false
}

variable "sso_alerts" {
  description = "Enable alerts for potentially malicious sso events"
  type        = bool
  default     = false
}

variable "cloudtrail_alerts" {
  description = "Enable alerts for potentially malicious cloudtrail management events"
  type        = bool
  default     = false
}

variable "guardduty_alerts" {
  description = "Enable alerts for potentially malicious guardduty management events"
  type        = bool
  default     = false
}

variable "config_alerts" {
  description = "Enable alerts for potentially malicious config management events"
  type        = bool
  default     = false
}

variable "kms_alerts" {
  description = "Enable alerts for potentially malicious kms management events"
  type        = bool
  default     = false
}

variable "root_alerts" {
  description = "Enable alerts for potentially malicious root usage events"
  type        = bool
  default     = false
}

variable "no_mfa_login_alerts" {
  description = "Enable alerts for logins without mfa - should never be the case"
  type        = bool
  default     = false
}

variable "failed_login" {
  description = "Enable alerts for failed logins"
  type        = bool
  default     = false
}

variable "destroy_data_events" {
  description = "Enable alerts for potentially malicious data desctruction events"
  type        = bool
  default     = false
}

variable "main_region" {
  description = "Main region used for business and compute. Potentially change into a list and adjust subsequent logic"
  type        = string
  default     = "eu-central-1"
}

#these alerts can be extended, alert in case of big machine size etc.

variable "compute_not_main_region" {
  description = "Enable alerts for compute events not in the main region"
  type        = bool
  default     = false
}

variable "invoke_model_not_main_region" {
  description = "Enable alerts for invoke model events not in the main region"
  type        = bool
  default     = false
}

variable "gateway_events" {
  description = "Enable alerts for potentially malicious network gateway events"
  type        = bool
  default     = false
}

variable "iam_events" {
  description = "Enable alerts for potentially malicious iam events - high volume warning"
  type        = bool
  default     = false
}

variable "nacl_events" {
  description = "Enable alerts for potentially malicious nacl events - either never triggered or very frequently depending on design philosophy"
  type        = bool
  default     = false
}

variable "route_table_events" {
  description = "Enable alerts for potentially malicious route table events - high volume warning"
  type        = bool
  default     = false
}

variable "s3_events" {
  description = "Enable alerts for potentially malicious s3 events - high volume warning - overlap with destroy data events"
  type        = bool
  default     = false
}

variable "security_group_events" {
  description = "Enable alerts for potentially malicious security group events - high volume warning"
  type        = bool
  default     = false
}

variable "vpc_events" {
  description = "Enable alerts for potentially malicious vpc events - high volume warning"
  type        = bool
  default     = false
}