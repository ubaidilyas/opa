# U-OPA: Proactive Compliance Tool for Cloud Services
U-OPA is designed for static code analysis of the IaC scripts for automated compliance with security checks configured as PaC. Currently, it scans Terraform IaC script managing resources on Azure Cloud for possible security threats explained in CIS Benchmark.

**Note: All the tools are available as open source, U-OPA is integration of tools using jenkins.**

- [Introduction](#introduction)
- [Automatable Rules](#automatable-rules)


## Introduction

U-OPA is designed for static code analysis of the IaC scripts for automated compliance with security checks configured as PaC. Currently, it scans Terraform IaC script managing resources on Azure Cloud for possible security threats explained in CIS Benchmark.

Following is the complete workflow of U-OPA:  

<img src="https://github.com/ubaidilyas/opa/blob/main/docs/img/workflow_git.png" width="40%">

Following steps are followed in the workflow:
- IaC script is converted to JSON by Terraform
- JSON plan is passed onto OPA as input
- OPA runs queries stored as PaC
- OPA forwards human-readable response to Jenkins
- Jenkins prompts with the response from OPA
- Jenkins proceeds to deployment or aborts according to the response


## Automatble Rules

Following rules have been found out to be automatable:

| CIS Microsoft Azure Foundations Benchmark v 1.3.1                                    | Reasons            |
|--------------------------------------------------------------------------------------|--------------------|
| 2.14, 2.15, 3.1, 3.3,4.3.1, 4.3.2, 8.4, 8.5,9.1, 9.2, 9.4, 9.9                       | Boolean Check      |
| 2.11, 2.13, 3.5 to 3.7, 4.1.1, 4.2.1, 4.3.3 to 4.3.6, 4.3.8, 4.4, 8.1,8.2, 9.5, 9.10 | String Match       |
| 3.8, 4.1.3, 4.3.7, 6.4,9.3, 9.6 to 9.8                                               | Numeric Comparison |
| 1.21, 6.1 to 6.3, 6.6                                                                | Helper Function    |

