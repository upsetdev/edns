# Contributing

Thanks for your interest in improving edns! Bug reports, fixes, and
documentation improvements are all welcome.

## Before you start

- For anything beyond a small fix, open an issue first so we can agree on the
  approach before you spend time on it.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Development setup

You need Rust (version in [`rust-toolchain.toml`](rust-toolchain.toml); rustup
installs it on first use) and optionally Docker. The tests need no external
services; `make test-redis` also runs the Redis-backed ones against a
throwaway Redis in Docker:

```bash
make check    # rustfmt, clippy, tests, cargo audit
```

CI runs the same checks plus a Docker build on every pull request.
See the [README](README.md#development) for how to run the server locally.

## Pull requests

- Keep each PR focused on one change, and explain *why* in the description.
- Add or update tests for behaviour changes. The end-to-end test in
  `src/http.rs` (mint → capture → report) is a good model.
- Keep the code dependency-light and in the style of the surrounding code;
  `cargo fmt` and `cargo clippy -D warnings` are enforced.
- Update the README when you change behaviour or configuration.
- Use clear commit messages. A prefix such as `fix:`, `feat:`, or `docs:` is
  appreciated.

## Design constraints

Some behaviour is deliberate, so keep these in mind:

- **Source IP fidelity is the product.** Changes must not put a proxy or
  address translation between resolvers and the DNS listener.
- **Redis calls cost money** on per-command hosting such as Upstash. Avoid adding
  Redis round-trips to the lookup path, and reject junk input before calling
  Redis.
- **Any instance may serve any step.** Don't keep lookup state in process
  memory.

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
