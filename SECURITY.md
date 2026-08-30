# Security Policy

NeuronEdge Enclave is a security- and privacy-focused runtime, so we take
vulnerability reports seriously. This policy explains how to report a security
issue and what to expect.

## Reporting a vulnerability

**Do not open a public GitHub issue** for a suspected vulnerability.

Instead, please report it privately:

- **Email:** security@mindpool.io (preferred)
- **GitHub:** use the
  [private vulnerability reporting](https://github.com/Mindpool-Labs/ne-enclave/security/advisories/new)
  feature on this repository.

Please include:

1. A description of the issue and its security impact.
2. The affected version(s) and how you reproduced it.
3. Any proof-of-concept, crash logs, or relevant output.
4. Whether you have already disclosed it elsewhere.

We aim to acknowledge receipt within **2 business days** and to send an
initial assessment within **7 days**.

## Coordinated disclosure

- We will work with you to understand and reproduce the issue, and to agree
  on a remediation timeline proportional to the severity.
- We credit reporters in the advisory unless you prefer to remain anonymous.
- Please give us reasonable time to fix and release before publishing details.
  As a default, we target **90 days** from acknowledgment to public advisory,
  following the industry-standard coordinated-disclosure window. This is
  flexible for actively-exploited issues.

## Scope

In scope:

- The NeuronEdge Enclave runtime, guest agent, privacy router, and seal
  crate in this repository.
- The reference deployment artifacts (`deploy/`).
- The Python and TypeScript SDKs.

Out of scope (but welcome as standard issues):

- Vulnerabilities in upstream dependencies — report these to the upstream
  project; we will track and bump pins as fixes are released.
- Theoretical issues without a plausible attack path.
- Issues requiring an already-compromised operator on the confidential tier
  (the confidential tier's trust model explicitly excludes a malicious host;
  see the threat-model docs).
- Social engineering, phishing, or physical attacks against Mindpool
  infrastructure.

## Supported versions

Only the latest minor release line receives security fixes. We encourage
operators to run the current release.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Hardening the runtime in production

Operators self-hosting NeuronEdge Enclave should follow the hardening
guidance in [`deploy/README.md`](deploy/README.md), including: running the
privileged supervisor under its own service user with a focused `sudoers`
fragment, deny-by-default egress, and the least-privilege image build.

## Acknowledgements

We are grateful to the security researchers who report issues responsibly.
Contributors to past advisories are named in the individual advisories.
