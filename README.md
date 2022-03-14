# U-OPA: Proactive Compliance Tool for Cloud Services
U-OPA is designed for static code analysis of the IaC scripts for automated compliance with security checks configured as PaC. Currently, it scans Terraform IaC script managing resources on Azure Cloud for possible security threats explained in CIS Benchmark.

**Note: All the tools are available as open source, U-OPA is integration of tools using jenkins.**

- [Introduction](#introduction)
- [Automatable Rules](#automatable-rules)
- [Future Goals](#future-goals)


## Introduction

U-OPA is designed for static code analysis of the IaC scripts for automated compliance with security checks configured as PaC. Currently, it scans Terraform IaC script managing resources on Azure Cloud for possible security threats explained in CIS Benchmark.

Following is the complete workflow of U-OPA:
[[https://github.com/ubaidilyas/opa/blob/main/docs/images/workflow_final.png|width=400px]]
![U-OPA](https://github.com/ubaidilyas/opa/blob/main/docs/images/workflow_final.png)

Following steps are followed in the workflow:
- IaC script is converted to JSON by Terraform
- JSON plan is passed onto OPA as input
- OPA runs queries stored as PaC
- OPA forwards human-readable response to Jenkins
- Jenkins prompts with the response from OPA
- Jenkins proceeds to deployment or aborts according to the response


## Automatble Rules

Following rules have been found out to be automatable:

### Optimal Access Control Model

For research over optimal ACM following two points are required:

1. Gathering Authorization Requirements

The cloud resource should be secure and as per Organizational Requirements. For now I have found CIS Microsoft Azure Foundations Benchmark and CIS AWS Foundations Bencmark which are recommended for a secure resource creation on the cloud. As far as Organizational Requirements are concerned, there are not enough policies being shared by the Company, maybe they donot have them for now and it matures over time.

2. Finding a Reasonable PIP/PDP/PEP

For PIP and PDP, the tool I selected is Open Policy Agent(OPA) due to following reasons:
- It is one tool for complete cloud stack, currently focusing on only Terraform (IaaC) scripts.
- It is interoperable and is working fine after testing with multiple policies and roles.

For defining policies following has been achieved:

- Azure Benchmark implementation for Storage Accounts (SA) , Virtual Machines (VM) and Network Security Groups (NSG) making the deployment secure.
- Basic implementaion of roles to verify the working of the tool for storage accounts and virtual machines.


#### Open Policy Agent (OPA)

The selected tool is successfully able to respond with the query. Currently, it is working as server on local machine with exposed ***port 8081***. Following steps could be followed to reproduce the results.

1. Define(copy the opa folder in the git) in your local environment and initialize OPA as follows:
```
./opa run --server ./learn-terraform-azure/azure
```
This command ***run*** OPA existing in the current directory with External Data (Policies) which are in ***learn-terraform-azure/azure*** directory.

2. Once it is up and running you can simply curl your query using the following command against some input. 

Firstly, we try authorization decisions using following two plans:
- ***vmdelete-storage-update-not-secure*** : Deleting a VM and updating a SA but one of the benchmarks is not met.
- ***vmcreate-storage-update-and-secure*** : Creating a VM and updating a SA and making it secure.

Please note that the ```jq .``` is just to make the result human readable. Secondly, the ***oauth*** section shows an arbitrary user.


```
curl localhost:8181/v1/data/azure/authz -d @vmdelete-storage-update-not-secure.json | jq .

{
  "result": {
    "network": {
      "deny": [
        "No authorization rules for 'azurerm_network_security_group'"
      ]
    },
    "storage": {
      "authz": true,
      "deny": []
    },
    "vmlinux": {
      "authz": false,
      "deny": [
        "'ubaid'is not allowed to delete virtual machine"
      ]
    }
  }
}

```
As we can see ***ubaid*** is not allowed to delete a VM but can update a SA but his configurations for SA are insecure which can be seen below. If the same configurations are run with input as role ***manager***, there would be no deny message.
```
curl localhost:8181/v1/data/azure/secure -d @vmdelete-storage-update-not-secure.json | jq .

{
  "result": {
    "network": {
      "deny": [],
      "rdp_disable": true,
      "ssh_disable": true,
      "standard_name": true,
      "udp_disable": true
    },
    "storage": {
      "deny": [
        "'{\"mytfsaccount\"}'failed to pass pre-defined 'microsoft_services' policy"
      ],
      "deny_default": true,
      "microsoft_services": false,
      "private_blob": true,
      "secure_transfer": true,
      "soft_delete": true,
      "standard_name": true
    },
    "vmlinux": {
      "deny": [],
      "managed_disks": true,
      "size_accept": true,
      "standard_name": true,
      "version_latest": true
    }
  }
}
```
Now let us provide the second plan as a input:
```
curl localhost:8181/v1/data/azure/authz -d @vmcreate-storage-update-and-secure.json | jq .

{
  "result": {
    "network": {
      "deny": [
        "No authorization rules for 'azurerm_network_security_group'"
      ]
    },
    "storage": {
      "authz": true,
      "deny": []
    },
    "vmlinux": {
      "authz": true,
      "deny": []
    }
  }
}
``````
As we can see ***ubaid*** is allowed to create a VM , update a SA and his configurations for SA are secure which can be seen below.
```
curl localhost:8181/v1/data/azure/secure -d @vmcreate-storage-update-and-secure.json | jq .

{
  "result": {
    "network": {
      "deny": [],
      "rdp_disable": true,
      "ssh_disable": true,
      "standard_name": true,
      "udp_disable": true
    },
    "storage": {
      "deny": [],
      "deny_default": true,
      "microsoft_services": true,
      "private_blob": true,
      "secure_transfer": true,
      "soft_delete": true,
      "standard_name": true
    },
    "vmlinux": {
      "deny": [],
      "managed_disks": true,
      "size_accept": true,
      "standard_name": true,
      "version_latest": true
    }
  }
}
```
Above is a basic example of RBAC considering following two rules.

- Ubaid can only update storage accounts
- Ubaid can create and update vmlinux.
- Ubaid cannot perform delete action.

Secondly, we try security related decisions with default values and some exceptions using the following two plans:
- ***tfplan_rdp_retention_ms*** : Multiple benchmarks are violated.
- ***tfplan_no_default_two_exeptions*** : Two exceptions configured. Exceptions can be seen in exceptions subdirectory.
- ***tfplan_secure*** : Secure according to the CIS Microsoft Azure Foundations Benchmark

Following is the result for ***tfplan_rdp_retention_ms***:
```
curl localhost:8181/v1/data/azure/secure -d @tfplan_rdp_retention_ms.json | jq .

{
  "result": {
    "network": {
      "deny": [
        "'{\"mytfnsgroup\"}'failed to pass pre-defined 'rdp_disable' policiy"
      ],
      "rdp_disable": false,
      "ssh_disable": true,
      "standard_name": true,
      "udp_disable": true
    },
    "storage": {
      "deny": [
        "'{\"mytfsaccount\"}'failed to pass pre-defined 'microsoft_services' policy",
        "'{\"mytfsaccount\"}'failed to pass pre-defined 'soft_delete' policy"
      ],
      "deny_default": true,
      "microsoft_services": false,
      "private_blob": true,
      "secure_transfer": true,
      "soft_delete": false,
      "standard_name": true
    },
    "vmlinux": {
      "deny": [],
      "managed_disks": true,
      "size_accept": true,
      "standard_name": true,
      "version_latest": true
    }
  }
}
```

Above we can can seen that whichever policies fail their respective flag is ***false*** and the resource causing the failure is printed in the ***deny[]*** field. This can help in troubleshooting when the solution is scaled upto hundreds of resources.

Now by changing the input to ***tfplan_no_default_two_exeptions***:
```
curl localhost:8181/v1/data/azure/secure -d @tfplan_no_default_two_exeptions.json | jq .

{
  "result": {
    "network": {
      "deny": [],
      "rdp_disable": true,
      "ssh_disable": true,
      "standard_name": true,
      "udp_disable": true
    },
    "storage": {
      "deny": [],
      "deny_default": true,
      "microsoft_services": true,
      "private_blob": true,
      "secure_transfer": true,
      "soft_delete": true,
      "standard_name": true
    },
    "vmlinux": {
      "deny": [
        "'{\"exceptionsvm\", \"exceptionsvm2\"}'failed to pass pre-defined 'standard_name' policy",
        "'{\"exceptionsvm2\"}'failed to pass pre-defined 'size_accept' policy"
      ],
      "managed_disks": true,
      "size_accept": false,
      "standard_name": false,
      "version_latest": true
    }
  }
}
```
This plan has its problems when it comes to ***vmlinux***. There are two exceptions which first of all donot follow the standard naming convention. Secondly ***exceptionsvm2*** size is not accordng to the exceptions table. This is a good example and shows the level of fine grained control we can have over our terraform plans.

Lastly with ***tfplan_secure*** it can be seen that there are no errors and everything is according to the benchmark.

```
{
  "result": {
    "network": {
      "deny": [],
      "rdp_disable": true,
      "ssh_disable": true,
      "standard_name": true,
      "udp_disable": true
    },
    "storage": {
      "deny": [],
      "deny_default": true,
      "microsoft_services": true,
      "private_blob": true,
      "secure_transfer": true,
      "soft_delete": true,
      "standard_name": true
    },
    "vmlinux": {
      "deny": [],
      "managed_disks": true,
      "size_accept": true,
      "standard_name": true,
      "version_latest": true
    }
  }
}
```

For PEP, Jenkins which is a CI/CD tool seems reasonable but enforcement would be worked upon once some set of rules in natural language have been defined and futhermore converted to some policies in digital language.


### Stake-Holders View
This is pending until end of the Project.


## Challenges

Following challenges are being currently faced:

1. Organization is either reluctant or they really donot have policies in place.
- For now they have only shared one abstract scenario which interests them. This is although not enough but it gave me an idea what might they require.

2. Would assuming some reasonable policies be acceptable from Academic POV?
- If yes than what should be in general number of roles/attribbutes/policies etc.

3. Finding parameters which can be used for performance evaluation. For now, the ***decision delay*** makes sense but further parameters to consider depends on the model and policies.


## Future Goals

In future following would be acheived:

1. A detailed list of policies.
2. Optimal access control model.
- ABAC or RBAC or some hybrid model.
- Set of permissions/operations.
4. Parsing of information (JWT, attributes) securely between OPA and Cloud Providers.

