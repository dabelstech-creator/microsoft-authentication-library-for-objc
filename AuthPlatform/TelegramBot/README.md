# AuthPlatform Telegram Coordinator

A Telegram Serverless bot project for read-only coordination of the AuthPlatform GitHub work.

## Commands

- `/start`, `/help` — show bot help.
- `/status` — inspect AuthPlatform implementation PR #25 and recent checks for its current head.
- `/github` — show repository and pull-request links.
- `/deploy` — show recent GitHub Actions runs.

The initial bot uses GitHub's public API and does not require a GitHub token. It is deliberately read-only: it cannot merge pull requests, change repository settings, or deploy the AuthPlatform application.

## Create and link the Telegram bot

1. In Telegram, open [@BotFather](https://t.me/BotFather) and run `/newbot`.
2. Choose a display name such as **AuthPlatform Project Coordinator** and an available username.
3. In BotFather, open the new bot's **Serverless → CLI Access → Access token** section.
4. From a terminal, enter this directory and install dependencies:

   ```sh
   npm install
   ```

5. Authenticate interactively. The CLI access token is separate from the Telegram Bot API token:

   ```sh
   npx tgcloud login
   ```

   The CLI stores credentials in `.tgcloud/`, which is ignored by Git. Never commit or paste the token into source files, issues, or chat.

## Validate and deploy

Run these from this directory:

```sh
npx tgcloud status
npx tgcloud run handlers/message '{ chat: { id: 1 }, text: "/help" }'
npx tgcloud push
npx tgcloud webhook
```

After deploying, inspect webhook synchronization. If the CLI reports it is out of sync, run:

```sh
npx tgcloud webhook sync
```

Do not use `--force` unless a cloud/local concurrency conflict has been investigated. Do not run database migrations for this initial bot; it has no database schema.

## CI authentication

For a trusted CI environment, configure the Serverless CLI access token as a protected secret named `TGCLOUD_TOKEN`. The CLI reads it from the environment and does not write it to disk. Never place the token in workflow YAML or repository files.

## Runtime and security boundaries

- Runtime: Telegram Serverless JavaScript modules under `tgcloud/`.
- GitHub data: public repository and workflow metadata only.
- No GitHub write token, bot API token, or CLI token is stored in this repository.
- No webhook URL is configured manually; Telegram Serverless manages the webhook.
- This bot is a status/reporting interface, not an authentication authority. Device binding and OAuth device authorization remain implemented and tested in the AuthPlatform service.
