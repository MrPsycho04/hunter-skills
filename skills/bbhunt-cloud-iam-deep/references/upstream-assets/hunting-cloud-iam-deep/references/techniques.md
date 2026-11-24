# cloud-iam-deep — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## AWS privesc patterns (24+ documented — `iam_privesc` techniques)



Quick lookup — if you have any of these IAM actions, escalate via the listed technique:



| You have | Escalate via |

|---|---|

| `iam:CreateAccessKey` | Create access key on any user → impersonate |

| `iam:CreateLoginProfile` | Set a console password on a user → login |

| `iam:UpdateLoginProfile` | Reset console password on a user |

| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |

| `iam:AttachGroupPolicy` | Attach AdministratorAccess to a group you're in |

| `iam:AttachRolePolicy` + sts:AssumeRole | Attach to a role you can assume |

| `iam:PutUserPolicy` | Inline AdministratorAccess to self |

| `iam:PutGroupPolicy` | Inline policy on a group |

| `iam:PutRolePolicy` | Inline on a role you can assume |

| `iam:AddUserToGroup` | Add self to admin group |

| `iam:UpdateAssumeRolePolicy` + sts:AssumeRole | Modify trust to allow self |

| `iam:CreatePolicyVersion` | Create v2 of an attached policy with admin |

| `iam:SetDefaultPolicyVersion` | Switch attached policy to admin version |

| `iam:PassRole` + ec2:RunInstances | Launch EC2 as admin role → use instance creds |

| `iam:PassRole` + lambda:CreateFunction/InvokeFunction | Run code as admin role |

| `iam:PassRole` + cloudformation:CreateStack | CF stack creates resources as admin |

| `iam:PassRole` + glue:CreateDevEndpoint | Notebook runs as admin role |

| `iam:PassRole` + datapipeline | Pipeline runs as admin role |

| `iam:PassRole` + codestar:CreateProject | New project gets admin role |

| `ec2:RunInstances` (with admin instance profile already on the AMI) | Spin instance, exfil creds from IMDS |

| `lambda:UpdateFunctionCode` (function has admin role) | Replace code → exfil creds |

| `lambda:UpdateFunctionConfiguration` | Add layer / env var that exfils |

| `cloudformation:UpdateStack` | Modify stack to grant self admin |

| `sts:AssumeRole` (where trust allows you) | Direct privilege jump |



Many of the destructive ones are out-of-scope for an external red-team; document the path, don't always execute.



---
