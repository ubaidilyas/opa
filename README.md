# U-OPA: Proactive Compliance Tool for Cloud Services
U-OPA is designed for static code analysis of the IaC scripts for automated compliance with security checks configured as PaC. Currently, it scans Terraform IaC script managing resources on Azure Cloud for possible security threats explained in CIS Benchmark.

**Note: All the tools are available as open source, U-OPA is integration of tools using jenkins.**

- [Introduction](#introduction)
- [Automatable Rules](#automatable-rules)
- [General Policy Structure](#general-policy-structure)
- [Policy Enforcement](#policy-enforcement)


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

## General Policy Structure

The policy is basically divided into “data” and “policy” sections. The purpose of this division is to make policy management easier and avoid unnecessary repetitions. The data section is referred into policy section using import keyword. Data is where all the resources of some type which pass the check are compiled into a list using comprehensions.
Let us take rule number 3.1 of CIS benchmark for the sake of understanding the general structure.

```
#3.1 Ensure that 'Secure transfer required' is set to 'Enabled'
sa_secure_transfer := { sa |    #name of the rule
    resource := input.resource_changes[_]   #data filtering
    resource.type == "azurerm_storage_account"  #data filtering
    resource.change.after.enable_https_traffic_only == true #applying checks
    sa := resource.change.after.name    #returning the name
}
```

The general structure of data section comprises mainly of following:
- Name of the rule
- Data filtering
- Applying checks
- Returning name

The name of the rule is just a string which can be set as per the will of the practitioner, data filtering is performed according to the resource under consideration for example, in the snippet above, resource type is "azurerm\_storage\_account", checks are applied accordingly and in the end the names of the resources passing the checks are returned and stored as a list. 

The policy section is where the list of total resources is compared with the resources that passed the check. If all the resources pass the defined check in data directory than there is no deny message and the flag is “true” otherwise the resource/s failing the checks are mentioned in the deny message. The code for policy section of rule 3.1 is shown in the Snippet \ref{code:policy}.

```
secure_transfer_enabled {   #name of the flag
    count_total_storage_account != 0    #checking count
    count_total_storage_account == count(d.sa_secure_transfer)  #comparing the lists
}
deny[msg] {                                                                 
    sa_failed := d.sa_total - d.sa_secure_transfer  #list of failed resources
    count(sa_failed) != 0   #no deny message if all pass
    msg := sprintf("'%v'failed to pass pre-defined 'secure_transfer_enabled' policy", [sa_failed])  #returning deny message  
}
```

In the snippet above, name of the flag is just a string which can be anything as per the will of the practitioner, count is checked to be not equal to zero to avoid false positives and then lists are compared. Furthermore, in the deny section the names of the failed resources are extracted, count is verified to be not equal to zero to avoid false deny message and in the end deny message is returned with the names of the resource/s that failed.

## Policy Enforcement
U-OPA extends a public Jenkinsfile which is a general way of running Terraform on Jenkins. The extended pipeline consists mainly of four sections.

- Stages and steps for creating Terraform plan in JSON format.
- “Query” stage where the plan from the previous stages is passed on to OPA.
- “Approval” stage where the output of OPA is presented for approval.
- Stages and steps for deployment on the cloud as per approval.

A suitable automated way is running OPA as a docker container. The policies are stored in a version control system which are pulled in the Jenkins workspace in “Checkout” stage. Futhermore, the “Query” stage is configured using the command below.

```
docker run -v <jenkins_workspace>:<container_directory> \
openpolicyagent/opa:0.37.1 eval \
-d <container_directory> <policy_to_evaluate> \
 -i <JSON_plan >
```
In the general command above
- -v flag is used for volume mounting.
- “openpolicyagent/opa:0.37.1” is the official docker image of OPA.
- “eval” is a sub-command to evaluate Rego query.
- -d flag is used to load policy into OPA.
- -i flag is used to load input data i.e., the Terraform plan.

The result from the “Query” stage is passed on to “Approval” stage. The “Approval” stage prompts with the results from previous stage which is shown in figure below and waits for a response. The job proceeds according to the response provided and either deploys on the cloud or aborts the job. 

<img src="https://github.com/ubaidilyas/opa/blob/main/docs/img/jenkins_job.png" width="80%">

