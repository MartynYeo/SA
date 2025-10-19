import { IAMPolicy } from './types';

export interface SecurityFlag {
  id: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  recommendation: string;
  affectedStatements: number[];
}

export interface PolicyAnalysisResult {
  policyId: string;
  policyName: string;
  flags: SecurityFlag[];
  isHighRisk: boolean;
}

// Define dangerous permission patterns
const DANGEROUS_PATTERNS = {
  // Global/wildcard risks
  WILDCARD_PERMISSION: {
    pattern: /^\*$/,
    severity: 'HIGH' as const,
    title: 'Wildcard Permission',
    description: 'Policy grants wildcard permissions (*)',
    recommendation: 'Replace with specific permissions following the principle of least privilege'
  },

  WILDCARD_IAM: {
    pattern: /^iam:\*$/,
    severity: 'HIGH' as const,
    title: 'Wildcard IAM Permission',
    description: 'Policy grants wildcard IAM permissions (iam:*)',
    recommendation: 'Replace with specific IAM permissions following the principle of least privilege'
  },

  // Wildcard resource usage
  WILDCARD_RESOURCE: {
    severity: 'HIGH' as const,
    title: 'Wildcard Resource',
    description: 'Policy allows all resources ("*")',
    recommendation: 'Restrict resources to specific ARNs and scopes'
  },

  // Treat CreatePolicyVersion alone as high risk (can set as default on creation)
  CREATE_POLICY_VERSION: {
    pattern: 'iam:CreatePolicyVersion',
    severity: 'HIGH' as const,
    title: 'Create Policy Version',
    description: 'Policy allows creating a new policy version that can be set as default to escalate privileges',
    recommendation: 'Restrict iam:CreatePolicyVersion; limit which policies can be versioned and require approvals'
  },

  // Policy version manipulation (also keep combined bucket)
  POLICY_VERSION_MANIPULATION: {
    patterns: ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'],
    severity: 'HIGH' as const,
    title: 'Policy Version Manipulation',
    description: 'Policy allows creation or activation of policy versions',
    recommendation: 'Restrict policy version management to administrative roles only'
  },

  // NEW: Any iam:PassRole should be flagged
  PASSROLE_ANY: {
    pattern: 'iam:PassRole',
    severity: 'HIGH' as const,
    title: 'PassRole Permission Present',
    description: 'Policy allows passing roles to AWS services, a common prerequisite for privilege escalation',
    recommendation: 'Scope iam:PassRole with resource ARNs and conditions (iam:PassedToService, aws:ResourceTag) and apply permission boundaries'
  },

  // Service-specific PassRole paths
  PASSROLE_EC2: {
    patterns: ['iam:PassRole', 'ec2:RunInstances'],
    severity: 'HIGH' as const,
    title: 'Privilege Escalation via EC2',
    description: 'Policy allows passing roles to EC2 instances, enabling privilege escalation',
    recommendation: 'Restrict PassRole to specific roles or remove ec2:RunInstances permission'
  },

  // Direct IAM mutation/escalation actions
  ACCESS_KEY_CREATION: {
    pattern: 'iam:CreateAccessKey',
    severity: 'HIGH' as const,
    title: 'Access Key Creation',
    description: 'Policy allows creation of access keys',
    recommendation: 'Restrict access key creation to administrative users only'
  },

  LOGIN_PROFILE_MANIPULATION: {
    patterns: ['iam:CreateLoginProfile', 'iam:UpdateLoginProfile'],
    severity: 'HIGH' as const,
    title: 'Login Profile Manipulation',
    description: 'Policy allows manipulation of user login profiles',
    recommendation: 'Restrict login profile management to administrative roles'
  },

  POLICY_ATTACHMENT: {
    patterns: ['iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy'],
    severity: 'HIGH' as const,
    title: 'Policy Attachment Permissions',
    description: 'Policy allows attaching policies to users, groups, or roles',
    recommendation: 'Restrict policy attachment to administrative roles only'
  },

  INLINE_POLICY_MANIPULATION: {
    patterns: ['iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy'],
    severity: 'HIGH' as const,
    title: 'Inline Policy Manipulation',
    description: 'Policy allows creation/modification of inline policies',
    recommendation: 'Restrict inline policy management to administrative roles'
  },

  GROUP_MEMBERSHIP: {
    pattern: 'iam:AddUserToGroup',
    severity: 'MEDIUM' as const,
    title: 'Group Membership Modification',
    description: 'Policy allows adding users to groups',
    recommendation: 'Restrict group membership changes to administrative roles'
  },

  ASSUME_ROLE_POLICY_UPDATE: {
    pattern: 'iam:UpdateAssumeRolePolicy',
    severity: 'HIGH' as const,
    title: 'Assume Role Policy Modification',
    description: 'Policy allows modification of assume role policies',
    recommendation: 'Restrict assume role policy updates to administrative roles'
  },

  // Lambda privilege escalation patterns
  LAMBDA_PRIVILEGE_ESCALATION: {
    patterns: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    severity: 'HIGH' as const,
    title: 'Lambda Privilege Escalation',
    description: 'Policy allows creating Lambda functions with arbitrary roles',
    recommendation: 'Restrict PassRole to specific roles or remove Lambda creation permissions'
  },

  LAMBDA_EVENT_SOURCE_MANIPULATION: {
    patterns: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:CreateEventSourceMapping'],
    severity: 'HIGH' as const,
    title: 'Lambda Event Source Manipulation',
    description: 'Policy allows creating Lambda functions and event source mappings',
    recommendation: 'Restrict Lambda event source management to specific roles'
  },

  LAMBDA_CODE_UPDATE: {
    pattern: 'lambda:UpdateFunctionCode',
    severity: 'MEDIUM' as const,
    title: 'Lambda Code Modification',
    description: 'Policy allows updating Lambda function code',
    recommendation: 'Restrict Lambda code updates to authorized developers'
  },

  // Glue privilege escalation
  GLUE_PRIVILEGE_ESCALATION: {
    patterns: ['iam:PassRole', 'glue:CreateDevEndpoint', 'glue:GetDevEndpoint'],
    severity: 'HIGH' as const,
    title: 'Glue Privilege Escalation',
    description: 'Policy allows creating Glue development endpoints with arbitrary roles',
    recommendation: 'Restrict PassRole to specific Glue roles or remove dev endpoint creation'
  },

  GLUE_ENDPOINT_MANIPULATION: {
    patterns: ['glue:UpdateDevEndpoint', 'glue:GetDevEndpoint'],
    severity: 'MEDIUM' as const,
    title: 'Glue Endpoint Manipulation',
    description: 'Policy allows modification of Glue development endpoints',
    recommendation: 'Restrict Glue endpoint management to authorized users'
  },

  // CloudFormation privilege escalation
  CLOUDFORMATION_PRIVILEGE_ESCALATION: {
    patterns: ['iam:PassRole', 'cloudformation:CreateStack', 'cloudformation:DescribeStacks'],
    severity: 'HIGH' as const,
    title: 'CloudFormation Privilege Escalation',
    description: 'Policy allows creating CloudFormation stacks with arbitrary roles',
    recommendation: 'Restrict PassRole to specific CloudFormation roles'
  },

  // Data Pipeline privilege escalation
  DATAPIPELINE_PRIVILEGE_ESCALATION: {
    patterns: ['iam:PassRole', 'datapipeline:CreatePipeline', 'datapipeline:PutPipelineDefinition', 'datapipeline:ActivatePipeline'],
    severity: 'HIGH' as const,
    title: 'Data Pipeline Privilege Escalation',
    description: 'Policy allows creating and managing data pipelines with arbitrary roles',
    recommendation: 'Restrict PassRole to specific Data Pipeline roles'
  }
};

export function analyzePolicy(policy: IAMPolicy): PolicyAnalysisResult {
  const flags: SecurityFlag[] = [];

  // Get the default policy version document
  const defaultVersion = policy.PolicyVersionList.find(v => v.VersionId === policy.DefaultVersionId);
  if (!defaultVersion || !defaultVersion.Document) {
    return {
      policyId: policy.PolicyId,
      policyName: policy.PolicyName,
      flags: [],
      isHighRisk: false
    };
  }

  const document = defaultVersion.Document;

  // Normalize statements to array safely
  const statements = Array.isArray(document.Statement)
    ? document.Statement
    : document.Statement
      ? [document.Statement]
      : [];

  statements.forEach((statement: any, statementIndex: number) => {
    if (statement.Effect !== 'Allow') return;

    const actionsRaw = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const actions: string[] = actionsRaw.filter((a: any): a is string => typeof a === 'string');

    // Wildcard resource ("*") detection
    const resourceRaw = statement.Resource;
    const resources = Array.isArray(resourceRaw)
      ? resourceRaw
      : resourceRaw !== undefined
        ? [resourceRaw]
        : [];
    if (resources.some((r: any) => typeof r === 'string' && r === '*')) {
      flags.push({
        id: 'wildcard-resource',
        severity: DANGEROUS_PATTERNS.WILDCARD_RESOURCE.severity,
        title: DANGEROUS_PATTERNS.WILDCARD_RESOURCE.title,
        description: DANGEROUS_PATTERNS.WILDCARD_RESOURCE.description,
        recommendation: DANGEROUS_PATTERNS.WILDCARD_RESOURCE.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Wildcard ("*") action detection
    if (actions.some(a => DANGEROUS_PATTERNS.WILDCARD_PERMISSION.pattern.test(a))) {
      flags.push({
        id: 'wildcard-permission',
        severity: DANGEROUS_PATTERNS.WILDCARD_PERMISSION.severity,
        title: DANGEROUS_PATTERNS.WILDCARD_PERMISSION.title,
        description: DANGEROUS_PATTERNS.WILDCARD_PERMISSION.description,
        recommendation: DANGEROUS_PATTERNS.WILDCARD_PERMISSION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Wildcard IAM permissions
    if (actions.some(action => DANGEROUS_PATTERNS.WILDCARD_IAM.pattern.test(action))) {
      flags.push({
        id: 'wildcard-iam',
        severity: DANGEROUS_PATTERNS.WILDCARD_IAM.severity,
        title: DANGEROUS_PATTERNS.WILDCARD_IAM.title,
        description: DANGEROUS_PATTERNS.WILDCARD_IAM.description,
        recommendation: DANGEROUS_PATTERNS.WILDCARD_IAM.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // CreatePolicyVersion alone is high risk (can set default on creation)
    if (actions.includes(DANGEROUS_PATTERNS.CREATE_POLICY_VERSION.pattern)) {
      flags.push({
        id: 'create-policy-version',
        severity: DANGEROUS_PATTERNS.CREATE_POLICY_VERSION.severity,
        title: DANGEROUS_PATTERNS.CREATE_POLICY_VERSION.title,
        description: DANGEROUS_PATTERNS.CREATE_POLICY_VERSION.description,
        recommendation: DANGEROUS_PATTERNS.CREATE_POLICY_VERSION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Policy version manipulation (either action present)
    if (actions.some(action => DANGEROUS_PATTERNS.POLICY_VERSION_MANIPULATION.patterns.includes(action))) {
      flags.push({
        id: 'policy-version-manipulation',
        severity: DANGEROUS_PATTERNS.POLICY_VERSION_MANIPULATION.severity,
        title: DANGEROUS_PATTERNS.POLICY_VERSION_MANIPULATION.title,
        description: DANGEROUS_PATTERNS.POLICY_VERSION_MANIPULATION.description,
        recommendation: DANGEROUS_PATTERNS.POLICY_VERSION_MANIPULATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // NEW: Flag any iam:PassRole occurrence
    if (actions.includes(DANGEROUS_PATTERNS.PASSROLE_ANY.pattern)) {
      flags.push({
        id: 'passrole-any',
        severity: DANGEROUS_PATTERNS.PASSROLE_ANY.severity,
        title: DANGEROUS_PATTERNS.PASSROLE_ANY.title,
        description: DANGEROUS_PATTERNS.PASSROLE_ANY.description,
        recommendation: DANGEROUS_PATTERNS.PASSROLE_ANY.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // PassRole + EC2 pattern
    if (actions.includes('iam:PassRole') && actions.includes('ec2:RunInstances')) {
      flags.push({
        id: 'passrole-ec2',
        severity: DANGEROUS_PATTERNS.PASSROLE_EC2.severity,
        title: DANGEROUS_PATTERNS.PASSROLE_EC2.title,
        description: DANGEROUS_PATTERNS.PASSROLE_EC2.description,
        recommendation: DANGEROUS_PATTERNS.PASSROLE_EC2.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Access key creation
    if (actions.includes('iam:CreateAccessKey')) {
      flags.push({
        id: 'access-key-creation',
        severity: DANGEROUS_PATTERNS.ACCESS_KEY_CREATION.severity,
        title: DANGEROUS_PATTERNS.ACCESS_KEY_CREATION.title,
        description: DANGEROUS_PATTERNS.ACCESS_KEY_CREATION.description,
        recommendation: DANGEROUS_PATTERNS.ACCESS_KEY_CREATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Login profile manipulation
    if (actions.some(action => DANGEROUS_PATTERNS.LOGIN_PROFILE_MANIPULATION.patterns.includes(action))) {
      flags.push({
        id: 'login-profile-manipulation',
        severity: DANGEROUS_PATTERNS.LOGIN_PROFILE_MANIPULATION.severity,
        title: DANGEROUS_PATTERNS.LOGIN_PROFILE_MANIPULATION.title,
        description: DANGEROUS_PATTERNS.LOGIN_PROFILE_MANIPULATION.description,
        recommendation: DANGEROUS_PATTERNS.LOGIN_PROFILE_MANIPULATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Policy attachment permissions
    if (actions.some(action => DANGEROUS_PATTERNS.POLICY_ATTACHMENT.patterns.includes(action))) {
      flags.push({
        id: 'policy-attachment',
        severity: DANGEROUS_PATTERNS.POLICY_ATTACHMENT.severity,
        title: DANGEROUS_PATTERNS.POLICY_ATTACHMENT.title,
        description: DANGEROUS_PATTERNS.POLICY_ATTACHMENT.description,
        recommendation: DANGEROUS_PATTERNS.POLICY_ATTACHMENT.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Inline policy manipulation
    if (actions.some(action => DANGEROUS_PATTERNS.INLINE_POLICY_MANIPULATION.patterns.includes(action))) {
      flags.push({
        id: 'inline-policy-manipulation',
        severity: DANGEROUS_PATTERNS.INLINE_POLICY_MANIPULATION.severity,
        title: DANGEROUS_PATTERNS.INLINE_POLICY_MANIPULATION.title,
        description: DANGEROUS_PATTERNS.INLINE_POLICY_MANIPULATION.description,
        recommendation: DANGEROUS_PATTERNS.INLINE_POLICY_MANIPULATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Group membership modification
    if (actions.includes('iam:AddUserToGroup')) {
      flags.push({
        id: 'group-membership',
        severity: DANGEROUS_PATTERNS.GROUP_MEMBERSHIP.severity,
        title: DANGEROUS_PATTERNS.GROUP_MEMBERSHIP.title,
        description: DANGEROUS_PATTERNS.GROUP_MEMBERSHIP.description,
        recommendation: DANGEROUS_PATTERNS.GROUP_MEMBERSHIP.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Assume role policy updates
    if (actions.includes('iam:UpdateAssumeRolePolicy')) {
      flags.push({
        id: 'assume-role-policy-update',
        severity: DANGEROUS_PATTERNS.ASSUME_ROLE_POLICY_UPDATE.severity,
        title: DANGEROUS_PATTERNS.ASSUME_ROLE_POLICY_UPDATE.title,
        description: DANGEROUS_PATTERNS.ASSUME_ROLE_POLICY_UPDATE.description,
        recommendation: DANGEROUS_PATTERNS.ASSUME_ROLE_POLICY_UPDATE.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Lambda privilege escalation patterns
    if (actions.includes('iam:PassRole') && actions.includes('lambda:CreateFunction') && actions.includes('lambda:InvokeFunction')) {
      flags.push({
        id: 'lambda-privilege-escalation',
        severity: DANGEROUS_PATTERNS.LAMBDA_PRIVILEGE_ESCALATION.severity,
        title: DANGEROUS_PATTERNS.LAMBDA_PRIVILEGE_ESCALATION.title,
        description: DANGEROUS_PATTERNS.LAMBDA_PRIVILEGE_ESCALATION.description,
        recommendation: DANGEROUS_PATTERNS.LAMBDA_PRIVILEGE_ESCALATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    if (actions.includes('iam:PassRole') && actions.includes('lambda:CreateFunction') && actions.includes('lambda:CreateEventSourceMapping')) {
      flags.push({
        id: 'lambda-event-source-manipulation',
        severity: DANGEROUS_PATTERNS.LAMBDA_EVENT_SOURCE_MANIPULATION.severity,
        title: DANGEROUS_PATTERNS.LAMBDA_EVENT_SOURCE_MANIPULATION.title,
        description: DANGEROUS_PATTERNS.LAMBDA_EVENT_SOURCE_MANIPULATION.description,
        recommendation: DANGEROUS_PATTERNS.LAMBDA_EVENT_SOURCE_MANIPULATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Lambda code update
    if (actions.includes('lambda:UpdateFunctionCode')) {
      flags.push({
        id: 'lambda-code-update',
        severity: DANGEROUS_PATTERNS.LAMBDA_CODE_UPDATE.severity,
        title: DANGEROUS_PATTERNS.LAMBDA_CODE_UPDATE.title,
        description: DANGEROUS_PATTERNS.LAMBDA_CODE_UPDATE.description,
        recommendation: DANGEROUS_PATTERNS.LAMBDA_CODE_UPDATE.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Glue privilege escalation
    if (actions.includes('iam:PassRole') && actions.includes('glue:CreateDevEndpoint') && actions.includes('glue:GetDevEndpoint')) {
      flags.push({
        id: 'glue-privilege-escalation',
        severity: DANGEROUS_PATTERNS.GLUE_PRIVILEGE_ESCALATION.severity,
        title: DANGEROUS_PATTERNS.GLUE_PRIVILEGE_ESCALATION.title,
        description: DANGEROUS_PATTERNS.GLUE_PRIVILEGE_ESCALATION.description,
        recommendation: DANGEROUS_PATTERNS.GLUE_PRIVILEGE_ESCALATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Glue endpoint manipulation
    if (actions.includes('glue:UpdateDevEndpoint') && actions.includes('glue:GetDevEndpoint')) {
      flags.push({
        id: 'glue-endpoint-manipulation',
        severity: DANGEROUS_PATTERNS.GLUE_ENDPOINT_MANIPULATION.severity,
        title: DANGEROUS_PATTERNS.GLUE_ENDPOINT_MANIPULATION.title,
        description: DANGEROUS_PATTERNS.GLUE_ENDPOINT_MANIPULATION.description,
        recommendation: DANGEROUS_PATTERNS.GLUE_ENDPOINT_MANIPULATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // CloudFormation privilege escalation
    if (actions.includes('iam:PassRole') && actions.includes('cloudformation:CreateStack') && actions.includes('cloudformation:DescribeStacks')) {
      flags.push({
        id: 'cloudformation-privilege-escalation',
        severity: DANGEROUS_PATTERNS.CLOUDFORMATION_PRIVILEGE_ESCALATION.severity,
        title: DANGEROUS_PATTERNS.CLOUDFORMATION_PRIVILEGE_ESCALATION.title,
        description: DANGEROUS_PATTERNS.CLOUDFORMATION_PRIVILEGE_ESCALATION.description,
        recommendation: DANGEROUS_PATTERNS.CLOUDFORMATION_PRIVILEGE_ESCALATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }

    // Data Pipeline privilege escalation
    if (
      actions.includes('iam:PassRole') &&
      actions.includes('datapipeline:CreatePipeline') &&
      actions.includes('datapipeline:PutPipelineDefinition') &&
      actions.includes('datapipeline:ActivatePipeline')
    ) {
      flags.push({
        id: 'datapipeline-privilege-escalation',
        severity: DANGEROUS_PATTERNS.DATAPIPELINE_PRIVILEGE_ESCALATION.severity,
        title: DANGEROUS_PATTERNS.DATAPIPELINE_PRIVILEGE_ESCALATION.title,
        description: DANGEROUS_PATTERNS.DATAPIPELINE_PRIVILEGE_ESCALATION.description,
        recommendation: DANGEROUS_PATTERNS.DATAPIPELINE_PRIVILEGE_ESCALATION.recommendation,
        affectedStatements: [statementIndex]
      });
    }
  });

  return {
    policyId: policy.PolicyId,
    policyName: policy.PolicyName,
    flags,
    isHighRisk: flags.some(flag => flag.severity === 'HIGH')
  };
}

export function analyzeAllPolicies(policies: Record<string, IAMPolicy>): PolicyAnalysisResult[] {
  return Object.values(policies).map(policy => analyzePolicy(policy));
}

export function getHighRiskPolicies(policies: Record<string, IAMPolicy>): PolicyAnalysisResult[] {
  const analysisResults = analyzeAllPolicies(policies);
  return analysisResults.filter(result => result.isHighRisk);
}

export function getSecuritySummary(policies: Record<string, IAMPolicy>) {
  const analysisResults = analyzeAllPolicies(policies);
  const highRiskCount = analysisResults.filter(r => r.isHighRisk).length;
  const totalFlags = analysisResults.reduce((sum, r) => sum + r.flags.length, 0);
  const highSeverityFlags = analysisResults.reduce((sum, r) =>
    sum + r.flags.filter(f => f.severity === 'HIGH').length, 0);

  return {
    totalPolicies: analysisResults.length,
    highRiskPolicies: highRiskCount,
    totalSecurityFlags: totalFlags,
    highSeverityFlags
  };
}