import { api } from 'sdk';

const REPOSITORY = 'dabelstech-creator/microsoft-authentication-library-for-objc';
const IMPLEMENTATION_PR = 25;
const API_HEADERS = {
  accept: 'application/vnd.github+json',
  'x-github-api-version': '2022-11-28',
  'user-agent': 'AuthPlatform-Telegram-Coordinator',
};

async function github(path) {
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/${path}`, {
    headers: API_HEADERS,
  });
  if (!response.ok) {
    throw new Error(`GitHub API returned HTTP ${response.status}`);
  }
  return response.json();
}

async function reply(chatId, text) {
  await api.sendMessage({ chat_id: chatId, text, disable_web_page_preview: true });
}

function helpText() {
  return [
    'AuthPlatform Project Coordinator',
    '',
    '/start — introduce this bot',
    '/help — show commands',
    '/status — inspect implementation PR #25',
    '/github — show repository and PR links',
    '/deploy — show recent GitHub Actions runs',
    '',
    'This bot reports public GitHub information. It does not merge PRs, change repository settings, or deploy code.',
  ].join('\n');
}

export default async function (message) {
  if (!message?.chat?.id || typeof message.text !== 'string') return;

  const chatId = message.chat.id;
  const command = message.text.trim().split(/\s+/, 1)[0].split('@')[0].toLowerCase();

  if (command === '/start' || command === '/help') {
    await reply(chatId, helpText());
    return;
  }

  if (command === '/github') {
    await reply(
      chatId,
      [
        'AuthPlatform repository:',
        `https://github.com/${REPOSITORY}`,
        '',
        `Implementation PR #${IMPLEMENTATION_PR}:`,
        `https://github.com/${REPOSITORY}/pull/${IMPLEMENTATION_PR}`,
      ].join('\n'),
    );
    return;
  }

  if (command === '/status') {
    try {
      const pr = await github(`pulls/${IMPLEMENTATION_PR}`);
      const runs = await github(`actions/runs?head_sha=${encodeURIComponent(pr.head.sha)}&per_page=10`);
      const latest = runs.workflow_runs?.slice(0, 5) ?? [];
      const runLines = latest.length
        ? latest.map((run) => `• ${run.name}: ${run.status}${run.conclusion ? ` / ${run.conclusion}` : ''}`).join('\n')
        : '• No workflow runs found for the current PR head.';
      await reply(
        chatId,
        [
          `PR #${pr.number}: ${pr.title}`,
          `State: ${pr.state}${pr.draft ? ' (draft)' : ''}`,
          `Head: ${pr.head.sha.slice(0, 12)}`,
          `Merge status: ${pr.mergeable_state ?? 'unknown'}`,
          '',
          'Recent checks:',
          runLines,
          '',
          pr.html_url,
        ].join('\n'),
      );
    } catch (error) {
      await reply(chatId, `Unable to retrieve project status: ${error.message}`);
    }
    return;
  }

  if (command === '/deploy') {
    try {
      const runs = await github('actions/runs?per_page=8');
      const lines = (runs.workflow_runs ?? []).slice(0, 8).map((run) => {
        const conclusion = run.conclusion ? ` — ${run.conclusion}` : '';
        return `• ${run.name}: ${run.status}${conclusion}\n  ${run.html_url}`;
      });
      await reply(chatId, lines.length ? `Recent GitHub Actions runs:\n\n${lines.join('\n')}` : 'No GitHub Actions runs were returned.');
    } catch (error) {
      await reply(chatId, `Unable to retrieve workflow status: ${error.message}`);
    }
    return;
  }

  if (command.startsWith('/')) {
    await reply(chatId, 'Unknown command. Send /help to see available commands.');
  }
}
