# Security Policy

## Supported versions

Only the latest commit on `main`, which is what runs at
[edns.upset.dev](https://edns.upset.dev), receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report them privately through GitHub's
[private vulnerability reporting](https://github.com/upsetdev/edns/security/advisories/new)
for this repository. Include:

- a description of the issue and its impact,
- steps or a proof of concept to reproduce it,
- any suggested fix, if you have one.

You can expect an acknowledgement within a few days. Please give us reasonable
time to release a fix before disclosing the issue publicly.

## Recognition

edns is a small project, and we're grateful to everyone who takes the time to
look for problems and report them responsibly. With your permission, we'll
credit you by name or handle in the published security advisory and in the
notes for the fix.

## Scope

In scope: the code in this repository and the service at `edns.upset.dev`, for
example cache poisoning, ACME challenge manipulation, token prediction or
leakage, and denial of service through a single cheap request.

Out of scope: volumetric DDoS, and reports that only show that the service
reveals your resolver's IP or ECS subnet to you, since that is what it is for.
