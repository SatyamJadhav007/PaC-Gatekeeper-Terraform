import fs from 'fs';
import * as core from '@actions/core';
import * as github from '@actions/github';

const SIGNATURE = '<!-- gatekeeper-drift-id -->';
const LABEL_NAME = 'drift-detected';
const LABEL_COLOR = 'e11d48'; // Red
const LABEL_DESCRIPTION = 'Infrastructure has drifted from Terraform code';

/**
 * Parse terraform plan output to extract a human-readable drift summary.
 * Looks for lines like: "Plan: X to add, Y to change, Z to destroy."
 * and individual resource change lines like: "# module.vpc.aws_subnet.public[0] will be updated in-place"
 */
function parsePlanOutput(planText) {
  const lines = planText.split('\n');
  const driftedResources = [];
  let planSummaryLine = '';

  for (const line of lines) {
    // Match the final summary line
    const summaryMatch = line.match(/Plan:\s+(\d+)\s+to add,\s+(\d+)\s+to change,\s+(\d+)\s+to destroy/);
    if (summaryMatch) {
      planSummaryLine = line.trim();
    }

    // Match individual resource drift lines
    const resourceMatch = line.match(/^[\s]*#\s+([\w\.\[\]_-]+)\s+(will be|must be|has been)/);
    if (resourceMatch) {
      driftedResources.push({
        resource: resourceMatch[1],
        action: line.trim().replace(/^#\s*/, ''),
      });
    }
  }

  return { driftedResources, planSummaryLine };
}

/**
 * Ensure the 'drift-detected' label exists in the repository.
 * Creates it if it doesn't exist.
 */
async function ensureLabelExists(octokit, owner, repo) {
  try {
    await octokit.rest.issues.getLabel({ owner, repo, name: LABEL_NAME });
  } catch (error) {
    if (error.status === 404) {
      await octokit.rest.issues.createLabel({
        owner,
        repo,
        name: LABEL_NAME,
        color: LABEL_COLOR,
        description: LABEL_DESCRIPTION,
      });
      core.info(`Created label '${LABEL_NAME}'`);
    }
  }
}

/**
 * Find an existing open drift issue by our hidden HTML signature.
 */
async function findExistingDriftIssue(octokit, owner, repo) {
  const { data: issues } = await octokit.rest.issues.listForRepo({
    owner,
    repo,
    state: 'open',
    labels: LABEL_NAME,
    per_page: 50,
  });

  return issues.find(issue => issue.body && issue.body.includes(SIGNATURE));
}

async function run() {
  try {
    const token = process.env.INPUT_GITHUB_TOKEN;
    const driftStatus = process.env.DRIFT_STATUS;
    const driftOutputPath = process.env.DRIFT_OUTPUT_PATH || '';
    const repoFullName = process.env.DRIFT_REPO_NAME || '';

    if (!token) {
      core.setFailed('INPUT_GITHUB_TOKEN is required');
      return;
    }

    const octokit = github.getOctokit(token);
    const { owner, repo } = github.context.repo;

    // ────────────────────────────────────
    // DRIFT RESOLVED — close existing issue
    // ────────────────────────────────────
    if (driftStatus === 'resolved') {
      const existingIssue = await findExistingDriftIssue(octokit, owner, repo);

      if (existingIssue) {
        await octokit.rest.issues.createComment({
          owner,
          repo,
          issue_number: existingIssue.number,
          body: `✅ **Drift Resolved** — Infrastructure now matches the Terraform code on \`main\`.\n\n_Automatically closed by the Gatekeeper Drift Detection workflow._`,
        });

        await octokit.rest.issues.update({
          owner,
          repo,
          issue_number: existingIssue.number,
          state: 'closed',
          state_reason: 'completed',
        });

        core.info(`Closed drift issue #${existingIssue.number} — drift resolved.`);
      } else {
        core.info('No existing drift issue found. Nothing to close.');
      }

      return;
    }

    // ────────────────────────────────────
    // DRIFT DETECTED — create or update issue
    // ────────────────────────────────────
    if (driftStatus !== 'true') {
      core.info(`Drift status is '${driftStatus}'. No action needed.`);
      return;
    }

    // Read and parse the plan output
    let planText = '';
    if (driftOutputPath && fs.existsSync(driftOutputPath)) {
      planText = fs.readFileSync(driftOutputPath, 'utf8');
    }

    const { driftedResources, planSummaryLine } = parsePlanOutput(planText);
    const timestamp = new Date().toISOString();
    const repoLabel = repoFullName || `${owner}/${repo}`;
    const runUrl = `https://github.com/${owner}/${repo}/actions/runs/${github.context.runId}`;

    // Build issue body
    let body = `${SIGNATURE}\n`;
    body += `## ⚠️ Infrastructure Drift Detected\n\n`;
    body += `The scheduled drift detection scan found that the **live AWS environment** has diverged from the Terraform code on \`main\`.\n\n`;

    body += `| Detail | Value |\n`;
    body += `|--------|-------|\n`;
    body += `| 📦 Repository | \`${repoLabel}\` |\n`;
    body += `| 🕐 Detected At | ${timestamp} |\n`;
    body += `| 🔗 Workflow Run | [View Logs](${runUrl}) |\n`;

    if (planSummaryLine) {
      body += `| 📊 Summary | \`${planSummaryLine}\` |\n`;
    }

    body += `\n`;

    if (driftedResources.length > 0) {
      body += `### 🔍 Drifted Resources\n\n`;
      driftedResources.forEach(r => {
        body += `- \`${r.resource}\` — ${r.action}\n`;
      });
      body += `\n`;
    }

    // Collapsible raw plan output
    if (planText.length > 0) {
      // Truncate if extremely long (GitHub has a 65536 char limit on issue bodies)
      const maxLen = 50000;
      const truncatedPlan = planText.length > maxLen
        ? planText.substring(0, maxLen) + '\n\n... (truncated, see full output in workflow logs)'
        : planText;

      body += `<details>\n<summary>📋 Full Terraform Plan Output</summary>\n\n`;
      body += `\`\`\`\n${truncatedPlan}\n\`\`\`\n\n</details>\n\n`;
    }

    body += `---\n\n`;
    body += `### 🛠️ Remediation\n\n`;
    body += `1. **If intentional** — Run \`terraform apply\` to update the code to match the new state, or update your \`.tf\` files to reflect the desired configuration.\n`;
    body += `2. **If unauthorized** — Investigate who made the manual change and revert it by running \`terraform apply\` to enforce the code-defined state.\n`;
    body += `3. **If a false positive** — Check if a recent PR was merged but not yet applied.\n\n`;
    body += `_This issue is automatically managed by the [PaC-Gatekeeper](https://github.com/SatyamJadhav007/PaC-Gatekeeper-Terraform) Drift Detection workflow. It will be auto-closed when drift is resolved._\n`;

    // Ensure label exists
    await ensureLabelExists(octokit, owner, repo);

    // Find existing issue
    const existingIssue = await findExistingDriftIssue(octokit, owner, repo);

    if (existingIssue) {
      await octokit.rest.issues.update({
        owner,
        repo,
        issue_number: existingIssue.number,
        body: body,
      });
      core.info(`Updated existing drift issue #${existingIssue.number}`);
    } else {
      const { data: newIssue } = await octokit.rest.issues.create({
        owner,
        repo,
        title: '⚠️ Infrastructure Drift Detected',
        body: body,
        labels: [LABEL_NAME],
      });
      core.info(`Created new drift issue #${newIssue.number}`);
    }

    // Also write to step summary
    core.summary.addRaw(body).write();

  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
