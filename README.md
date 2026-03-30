# Passmark

Passmark is an open-source AI framework for regression testing. Most AI testing tools focus on testing a single PR. Passmark is designed for continuous regression testing of applications, where the goal is to catch regressions as soon as they occur, without needing to update AI prompts or retrain models.

Passmark uses AI models to execute natural language steps via Playwright, with intelligent caching, auto-healing, and multi-model assertion verification.

## Quick Start

```bash
npm init playwright@latest
cd <your-project>
npm install passmark
```

We need at least one model from Anthropic and one from Google to use Passmark's multi-model consensus features. Set the required environment variables:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_GENERATIVE_AI_API_KEY=AIza...
```

Basic usage with Playwright:

```typescript
import { test } from "@playwright/test";
import { runSteps } from "passmark";

test("user signup flow", async ({ page }) => {
  await runSteps({
    page,
    userFlow: "User Signup",
    steps: [
      { description: "Navigate to the signup page" },
      { description: "Fill in the email field", data: { value: "test@example.com" } },
      { description: "Click the submit button" },
    ],
    assertions: [{ assertion: "A welcome message is displayed" }],
    test,
    expect
  });
});
```

## Features

- **Core Execution** — `runSteps()` and `runUserFlow()` for flexible test orchestration in natural language, with smart caching and auto-healing
- **Multi-Model Assertion Engine** — Consensus-based validation using Claude and Gemini, with an arbiter model to resolve disagreements
- **Redis-Based Step Caching** — Cache-first execution with AI fallback and automatic self-healing when cached steps fail
- **Configurable AI Models** — 8 dedicated model slots for step execution, assertions, extraction, and more
- **AI Gateway Support** — Route requests through Vercel AI Gateway or connect directly to provider SDKs
- **Dynamic Placeholders** — Inject values at runtime with `{{run.*}}`, `{{global.*}}`, `{{data.*}}`, and `{{email.*}}` expressions for repeatable and data-driven tests
- **Email Extraction** — Pluggable email provider interface with a built-in emailsink provider
- **AI-Powered Data Extraction** — Extract structured values from page snapshots and URLs using AI
- **Smart Wait Conditions** — AI-evaluated wait conditions with exponential backoff. No rigid selectors or time-based waits needed.
- **Secure Script Runner** — AST-validated Playwright script execution with an allowlisted API surface
- **Telemetry** — Optional Axiom and OpenTelemetry tracing via environment variables
- **Structured Logging** — Pino-based logger with configurable log levels
- **Global Configuration** — Single `configure()` entry point for models, gateway, email provider, and upload path

## Core Functions

### `runSteps(options: RunStepsOptions)`

Executes a sequence of steps using AI with caching. Each step is described in natural language and executed via Playwright.

```typescript
await runSteps({
  page,
  userFlow: "Checkout Flow",
  steps: [
    { description: "Add item to cart" },
    { description: "Go to checkout" },
    { description: "Fill in shipping details", data: { value: "123 Main St" } },
  ],
  assertions: [{ assertion: "Order confirmation is displayed" }],
  test,
  expect,
});
```

### `runUserFlow(options: UserFlowOptions)`

Runs a complete user flow as a single AI agent call. Best for exploratory testing where exact steps are flexible.

```typescript
const result = await runUserFlow({
  page,
  userFlow: "Complete a purchase",
  steps: "Navigate to store, add an item, checkout with test card",
  effort: "high", // by default "low" uses gemini-3-flash for faster execution; "high" uses gemini-3.1-pro-preview for deeper thinking
});
```

### `assert(options: AssertionOptions)`

Multi-model consensus assertion. Runs Claude and Gemini in parallel; if they disagree, a third model arbitrates.

```typescript
const result = await assert({
  page,
  assertion: "The dashboard shows 3 active projects",
  expect,
});
```

## Configuration

Call `configure()` once before using any functions:

```typescript
import { configure } from "passmark";

configure({
  ai: {
    gateway: "none", // "none" (default) or "vercel"
    models: {
      stepExecution: "google/gemini-3-flash",
      utility: "google/gemini-2.5-flash",
    },
  },
  uploadBasePath: "./uploads",
});
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | Yes | - | Redis connection URL for step caching and global state |
| `ANTHROPIC_API_KEY` | Yes | - | Anthropic API key for Claude models |
| `GOOGLE_GENERATIVE_AI_API_KEY` | Yes | - | Google API key for Gemini models |
| `AI_GATEWAY_API_KEY` | If gateway=vercel | - | Vercel AI Gateway API key |
| `AXIOM_TOKEN` | No | - | Axiom token for OpenTelemetry tracing |
| `AXIOM_DATASET` | No | - | Axiom dataset for trace storage |
| `PASSMARK_LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error`, `silent` |

## Model Configuration

All models are configurable via `configure({ ai: { models: { ... } } })`:

| Key | Default | Used For |
|-----|---------|----------|
| `stepExecution` | `google/gemini-3-flash` | Executing individual steps |
| `userFlowLow` | `google/gemini-3-flash-preview` | User flow execution (low effort) |
| `userFlowHigh` | `google/gemini-3.1-pro-preview` | User flow execution (high effort) |
| `assertionPrimary` | `anthropic/claude-4.5-haiku` | Primary assertion model (Claude) |
| `assertionSecondary` | `google/gemini-3-flash` | Secondary assertion model (Gemini) |
| `assertionArbiter` | `google/gemini-3.1-pro-preview` | Arbiter for assertion disagreements |
| `utility` | `google/gemini-2.5-flash` | Data extraction, wait conditions |

## Caching

Passmark caches successful step actions in Redis. On subsequent runs, cached steps execute directly without AI calls, dramatically reducing latency and cost.

- Steps are cached by `userFlow` + `step.description`
- Set `bypassCache: true` on individual steps or the entire run to force AI execution
- Cache is automatically bypassed on Playwright retries
- Caching only applies to `runSteps`. As of now, only those AI executions that are single-step are cached as multi-step actions can vary widely and are less likely to be identical on subsequent runs. We're exploring ways to safely cache multi-step flows.

## Telemetry

Telemetry is opt-in. Set `AXIOM_TOKEN` and `AXIOM_DATASET` to enable OpenTelemetry tracing via Axiom. All AI calls are wrapped with `withSpan` for observability.

Without these env vars, telemetry is a no-op.

## Email Extraction

Configure an email provider for testing flows that involve email verification. By default, you can use the `emailsink` provider, which provides disposable email addresses and an API to fetch received emails. The free tier doesn't need any credentials, but for more reliability and flexible rate limits, you can sign up for an account and use your `EMAILSINK_API_KEY`. Reach out to us if you want to get an API key.

```typescript
import { configure } from "passmark";
import { emailsinkProvider } from "passmark/providers/emailsink";

configure({
  email: emailsinkProvider({ apiKey: process.env.EMAILSINK_API_KEY }),
});
```

Or implement a custom provider:

```typescript
configure({
  email: {
    domain: "my-test-mail.com",
    extractContent: async ({ email, prompt }) => {
      // Fetch and extract content from your email service
      return extractedValue;
    },
  },
});
```

Use in steps with the `{{email.*}}` placeholder pattern:

```typescript
{
  description: "Enter the verification code",
  data: { value: "{{email.otp:get the 6 digit verification code:{{run.dynamicEmail}}}}" }
}
```

## Placeholder System

Dynamic values can be injected into step data using placeholders:

| Pattern | Scope | Description |
|---------|-------|-------------|
| `{{run.email}}` | Per run | Random email (faker) |
| `{{run.dynamicEmail}}` | Per run | Email using configured domain |
| `{{run.fullName}}` | Per run | Random full name |
| `{{run.shortid}}` | Per run | Short unique ID |
| `{{run.phoneNumber}}` | Per run | Random phone number |
| `{{global.email}}` | Per execution | Shared across runSteps calls with same `executionId` |
| `{{global.dynamicEmail}}` | Per execution | Shared dynamic email |
| `{{data.key}}` | Per project | Stored in Redis, managed via project settings |
| `{{email.type:prompt}}` | Resolved lazily | Extract content from received email |

## Architecture Overview

```
Step Request
    |
    v
[Cache Check] --hit--> [Execute Cached Action] --success--> Done
    |                          |
    miss                     fail (auto-heal)
    |                          |
    v                          v
[AI Execution] ---------> [Cache Result]
    |
    v
[Assertions] (Claude + Gemini consensus)
```

## Known Limitations

Uses Playwright's private `_snapshotForAI()` API for accessibility snapshots. This API is not part of Playwright's public contract and may change in future versions.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, code style, and PR workflow.

## License

[FSL-1.1-Apache-2.0](./LICENSE.md) - Functional Source License, Version 1.1, with Apache 2.0 future license.
