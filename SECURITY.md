# Security policy

Report vulnerabilities privately with GitHub private vulnerability reporting when
available. Do not include real private keys or sensitive evidence in a public issue.

The validator reads untrusted JSON and ZIP archives under file-count, depth, member,
and aggregate limits. It rejects duplicate JSON keys, unsafe numbers, unsafe paths,
symlinks, special files, duplicate archive names, non-profile compression, stale
bindings, duplicate signatures, algorithm confusion, expiry, revocation, and
insufficient trust thresholds. It does not execute evidence or access the network.

Residual risks include compromised trusted keys, dishonest evaluators, weak policy,
ZIP/parser defects, denial of service below configured limits, and filesystem races
between path inspection and opening on platforms without descriptor-level no-follow.
