/**
 * Example Jenkinsfile — mirrors the gitlab infrastructure repo.
 *
 * Expected repo structure:
 *   ├── state.tf                          <-- copied into component dir by shared lib
 *   ├── ec2/
 *   │   ├── main.tf
 *   │   ├── variables.tf
 *   │   ├── data.tf
 *   │   └── ...
 *   ├── rds/
 *   │   ├── main.tf
 *   │   └── ...
 *   ├── s3/
 *   │   ├── main.tf
 *   │   └── ...
 *   ├── policies/                         <-- OPA rego rules (what to enforce)
 *   │   ├── general.rego
 *   │   ├── s3.rego
 *   │   ├── rds.rego
 *   │   ├── ec2.rego
 *   │   └── exceptions.rego               <-- shared exception helper
 *   ├── environments/
 *   │   ├── global/                       <-- policy exceptions (what to skip)
 *   │   │   ├── policy-exceptions.json    <-- OPA/Conftest exceptions
 *   │   │   ├── .checkov.yaml             <-- Checkov skip-checks
 *   │   │   ├── .trivyignore              <-- Trivy ignored findings
 *   │   │   ├── .tflint.hcl               <-- TFLint disabled rules
 *   │   │   └── .gitleaks.toml            <-- Gitleaks false-positive allowlist
 *   │   ├── dev/
 *   │   │   └── us-east-1/
 *   │   │       ├── ec2/terraform.tfvars
 *   │   │       ├── rds/terraform.tfvars
 *   │   │       └── s3/terraform.tfvars
 *   │   └── dsop/
 *   │       └── us-east-1/
 *   │           ├── ec2/terraform.tfvars
 *   │           ├── rds/terraform.tfvars
 *   │           └── s3/terraform.tfvars
 *   └── Jenkinsfile
 *
 * The shared library handles everything:
 *   - Copies state.tf into the component dir
 *   - Runs all security scans, linting, plan
 *   - Posts scan reports to GitLab MR (if MR_ID provided, feature branches only)
 *   - Approval gate on ALL branches
 *   - Apply only on main
 *   - Backend config is hardcoded in the shared library
 */

@Library('jenkins-shared-library') _

properties([
    buildDiscarder(logRotator(
        daysToKeepStr: '600',
        numToKeepStr: '500'
    )),
    parameters([
        choice(
            name: 'APPLICATION',
            choices: ['gitlab'],
            description: 'Project Name.'
        ),
        choice(
            name: 'ENVIRONMENT',
            choices: ['dev', 'dsop'],
            description: 'Environment for terraform deploy.'
        ),
        choice(
            name: 'REGION',
            choices: ['us-east-1'],
            description: 'AWS region you want to deploy the code to.'
        ),
        choice(
            name: 'COMPONENT',
            choices: ['rds', 's3', 'ec2'],
            description: 'Infrastructure component to deploy. Corresponds to a top-level directory in this repo.'
        ),
        string(
            name: 'MR_ID',
            defaultValue: '',
            description: 'GitLab Merge Request ID. If provided, scan results and plan output will be posted as MR comments (feature branches only).',
            trim: true
        ),
        string(
            name: 'JIRA_ID',
            defaultValue: '',
            description: 'Jira ticket ID (e.g. INFRA-1234). Included in MR comments and build summary for traceability.',
            trim: true
        ),
        booleanParam(
            name: 'DESTROY',
            defaultValue: false,
            description: 'Destroy terraform infrastructure instead of create/modify it. USE WITH CAUTION!'
        ),
        booleanParam(
            name: 'DEBUG_LOGGING',
            defaultValue: false,
            description: 'Enable debug logging.'
        ),
    ])
])

terraform(
    application : params.APPLICATION,
    environment : params.ENVIRONMENT,
    region      : params.REGION,
    component   : params.COMPONENT,
    auditMode   : true,              // set to false to enforce (scans block the build)
    destroy     : params.DESTROY,
    debug       : params.DEBUG_LOGGING,
    mrId        : params.MR_ID,
    jiraId      : params.JIRA_ID,
)
