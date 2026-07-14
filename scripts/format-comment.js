import fs from 'fs';
import * as core from '@actions/core';
import * as github from '@actions/github';

const SIGNATURE = '<!-- gatekeeper-comment-id -->';

async function run() {
  try {
    // 1. Read input parameters
    const resultsPath = core.getInput('results_path', { required: true });
    const token = core.getInput('github_token', { required: true });

    // 2. Read and parse Conftest results
    if (!fs.existsSync(resultsPath)) {
      core.warning(`Results file not found at ${resultsPath}. Skipping comment generation.`);
      return;
    }

    const rawData = fs.readFileSync(resultsPath, 'utf8');
    const results = JSON.parse(rawData);

    // Conftest outputs an array of files. We'll aggregate all failures and warnings.
    let totalFailures = [];
    let totalWarnings = [];

    results.forEach(fileResult => {
      if (fileResult.failures) totalFailures.push(...fileResult.failures);
      if (fileResult.warnings) totalWarnings.push(...fileResult.warnings);
    });

    const failureCount = totalFailures.length;
    const warningCount = totalWarnings.length;

    // 3. Generate Markdown content
    let markdown = `${SIGNATURE}\n`;
    markdown += `## 🛡️ Policy Gatekeeper Results\n\n`;

    if (failureCount === 0 && warningCount === 0) {
      markdown += `✅ **All infrastructure policies passed!**\n`;
    } else {
      markdown += `| Metric | Count |\n`;
      markdown += `|--------|-------|\n`;
      markdown += `| ❌ Deny (failures) | **${failureCount}** |\n`;
      markdown += `| ⚠️ Warn | **${warningCount}** |\n\n`;

      if (failureCount > 0) {
        markdown += `### ❌ Denied Violations\n\n`;
        totalFailures.forEach(f => {
          markdown += `- **${f.metadata?.query || 'Rule'}**: ${f.msg}\n`;
        });
        markdown += `\n*Merge is blocked until these are resolved.*\n\n`;
      }

      if (warningCount > 0) {
        markdown += `### ⚠️ Warnings\n\n`;
        totalWarnings.forEach(w => {
          markdown += `- **${w.metadata?.query || 'Rule'}**: ${w.msg}\n`;
        });
        markdown += `\n*Warnings are recommended best practices but do not block the merge.*\n\n`;
      }
    }

    // 4. Output to GitHub Step Summary
    core.summary.addRaw(markdown).write();

    // 5. Update or Create PR Comment
    const context = github.context;
    // The pull_request event provides context.payload.pull_request
    if (context.eventName !== 'pull_request') {
      core.info('Not a pull request event. Skipping PR comment creation.');
      return;
    }

    const octokit = github.getOctokit(token);
    const { owner, repo } = context.repo;
    const issue_number = context.payload.pull_request.number;

    // Find existing comment
    const { data: comments } = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number,
    });

    const existingComment = comments.find(comment => 
      comment.user.type === 'Bot' && comment.body.includes(SIGNATURE)
    );

    if (existingComment) {
      // Update existing comment
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: markdown,
      });
      core.info(`Updated existing PR comment ${existingComment.id}`);
    } else {
      // Create new comment
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number,
        body: markdown,
      });
      core.info('Created new PR comment');
    }

  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
