# Project Instructions

## Code Quality and Formatting

- Always run `cargo fmt` to format all changes before committing any Rust code change.
- Ensure all Rust code changes are free of clippy warnings. Always run `cargo clippy --workspace --all-targets -- -D warnings` to verify.
- `samloader-web` only compiles for WebAssembly, so the command above does not lint it. When changing `web/`, also run `cargo clippy -p samloader-web --target wasm32-unknown-unknown -- -D warnings`.

## Code Commit Instructions

- **NEVER** commit changes or amend an existing git commit without the user's explicit request or approval.
- Do not stage or commit files automatically as part of automated steps or task conclusions unless explicitly instructed by the user.

### Commit Message Formatting

When explicitly requested to commit changes, format commit messages according to the following rules:

1. **50/72 Rule:**
   - **Subject line:** At most 50 characters. Keep it concise, descriptive, and written in the imperative mood (e.g., `Fix build failure on macOS`, `Add support for WASM`).
   - **Blank line:** Always include a blank line between the subject line and the commit body.
   - **Body text:** Wrap body lines at 72 characters maximum. Explain the *what* and *why* behind the change.

2. **Assisted-by Trailer:**
   - Include an `Assisted-by: <Friendly Name of Current Model>` trailer in the commit message body (e.g., `Assisted-by: Gemini 3.8 Flash`, `Assisted-by: GPT-4o`, `Assisted-by: Claude Opus 5.5`).
   - **Note:** Always specify the underlying LLM model name, NOT the agent framework, runner, or harness name (such as Antigravity, AGY, etc.).

### Example Commit Message

```text
Short summary of changes in 50 characters or less

Detailed explanation of why this change was made and what problems
it solves. Wrap all lines in the message body to at most 72
characters.

Assisted-by: <Friendly Name of Current Model>
```
