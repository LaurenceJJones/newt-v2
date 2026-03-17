# DO NOT USE

`newt-v2` is an in-progress rewrite of `newt`.

This repository is not ready for production use, not API-stable, and not release-ready.

## Status

- Work in progress
- Behavior is still being parity-checked against legacy `newt`
- Internal structure is being actively refactored
- Interfaces, runtime behavior, and configuration may change without notice

## Warning

Do not deploy this as a supported replacement for legacy `newt`.

If you are looking for a stable/runtime-safe version, use the current supported legacy implementation instead.

## Development

Build locally:

```bash
make local
```

Run tests:

```bash
make test
```

Example local command template:

```bash
cp .test.cmd.example .test.cmd
```
