# Working Instructions

## Project plan

Before changing `xhttp-rs`, read [PLANS.md](PLANS.md). It is the source of
truth for:

- the scope of the Rust sing-box-compatible implementation;
- capabilities already implemented;
- known unsupported behavior;
- verification requirements; and
- the ordered roadmap.

Keep `PLANS.md` and `README.md` synchronized with runtime behavior. A parsed
sing-box JSON field is not implemented unless it is converted, validated,
executed, and tested.

Before any ShadowQUIC/JLS work, also read
[doc/shadowquic-jls-investigation.md](doc/shadowquic-jls-investigation.md).

## Required verification

Protocol-level changes should pass:

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
tests/interop.sh
```

If a check cannot run, record the exact reason and do not describe it as
passing.

## Git branch naming

- Do not use `agent/xxx` or any branch name that advertises AI/agent
  authorship.
- For issue fixes, use `fix-issue-xxxx`, replacing `xxxx` with the issue
  number or a concise issue identifier.
- For new features, use `feat-xxx-xxx`, replacing the `xxx` segments with a
  concise kebab-case feature description.
- Before creating a branch, classify the work as an issue fix or a new feature
  and apply the corresponding pattern.
