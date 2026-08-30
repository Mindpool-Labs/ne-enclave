#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Reject private-repository references and internal delivery terminology from
# tracked public source. This script intentionally does not scan itself because
# its built-in test corpus contains forbidden examples.

set -u

pattern='docs/(superpowers|aegisvm-artifacts)|(prd|arch|standards|spec|design)[[:space:]]*§|prd[[:space:]]*(fr|nfr)-[0-9]+|(^|[^[:alnum:]_])(per[[:space:]]+)?(fr|nfr)-[0-9]+(\.[0-9]+)?|(^|[^[:alnum:]])phase[-_[:space:]]*[0-9]+([^[:alnum:]]|$)|(^|[^[:alnum:]])p[0-9]([^[:alnum:]]|$)|(^|[^[:alnum:]_])spike([^[:alnum:]_]|$)|(^|[^[:alnum:]])bring[-_[:space:]]*ups?([^[:alnum:]]|$)|phase0[-_]spike|research[[:space:]]+note[[:space:]]*§|audit[[:space:]-]*finding[[:space:]-]*(id[[:space:]-]*)?#[[:space:]]*[0-9]+|audit[[:space:]-]*finding[[:space:]-]*(id[[:space:]-]*)?[a-z]+-?[0-9]+|audit[[:space:]]+[a-z][0-9]+(-[a-z]?[0-9]+)?|task[[:space:]-]*[0-9]+|risk[[:space:]]+[a-z]?[0-9]+|[(]r[12][)]|r[12]_single_cvm_direct\.rs|bsl-1\.1|separate[[:space:]]+(private[[:space:]]+)?control[-[:space:]]+plane[[:space:]]+(repository|repo)|typescript[[:space:]]+control[-[:space:]]+plane[[:space:]]+worker|(^|[^[:alnum:]])cp[[:space:]-]+repo([^[:alnum:]]|$)|vitest.*cross[-[:space:]]+repo|cross[-[:space:]]+repo.*vitest|(^|[^[:alnum:]_])wedge([^[:alnum:]_]|$)|neuronedge\.ai|design[[:space:]-]+partners?|joined[[:space:]]+mindpool|premium[[:space:]-]+tier|/users/[^/]+/(development|desktop|documents|downloads)/|commercial/ne-control-plane'

matches_pattern() {
    printf '%s\n' "$1" | grep -E -i "$pattern" >/dev/null
}

expect_match() {
    if ! matches_pattern "$2"; then
        echo "public-boundary self-test failed: expected match: $1" >&2
        exit 2
    fi
}

expect_no_match() {
    if matches_pattern "$2"; then
        echo "public-boundary self-test failed: unexpected match: $1" >&2
        exit 2
    fi
}

run_self_test() {
    # Positive corpus: case and spelling variants that must fail the guard.
    expect_match 'private document path' 'DOCS/SUPERPOWERS/specs/internal.md'
    expect_match 'private artifact path' 'docs/aegisvm-artifacts/design.md'
    expect_match 'private PRD citation' 'PRD §9.2'
    expect_match 'private architecture citation' 'arch §6.4'
    expect_match 'private standards citation' 'STANDARDS §8'
    expect_match 'private design citation' 'Design §4.2'
    expect_match 'private functional requirement' 'PRD FR-4.5'
    expect_match 'private nonfunctional requirement' 'PRD NFR-5.1'
    expect_match 'bare functional requirement' 'Per FR-11.3'
    expect_match 'bare nonfunctional requirement' 'NFR-5.1'
    expect_match 'private spike outcome' 'spike outcome summary'
    expect_match 'standalone delivery spike' 'standalone spike'
    expect_match 'numbered delivery phase' 'Phase 1 P0 first cut'
    expect_match 'numbered phase with dev mode' 'Phase 1 / dev mode'
    expect_match 'numbered phase compatibility promise' 'Phase 2 without breaking existing clients'
    expect_match 'phase-zero delivery spike' 'Phase 0 spike'
    expect_match 'phase-zero delivery scope' 'Phase 0 scope'
    expect_match 'compact phase-zero scope' 'Phase0 scope'
    expect_match 'hyphenated phase-zero scope' 'Phase-0 scope'
    expect_match 'underscored phase-zero scope' 'Phase_0_scope'
    expect_match 'numbered future phase' 'Phase 2 can add fields'
    expect_match 'numbered phase deliverable' 'Phase 2 deliverable'
    expect_match 'delivery shorthand scope' 'P0 cleartext scope'
    expect_match 'underscored delivery shorthand' 'foo_P0_bar'
    expect_match 'delivery shorthand arrival' 'arrive in P1'
    expect_match 'hyphenated delivery spike' 'concurrent-fork spike'
    expect_match 'silicon validation diagnostic' 'silicon bring-up diagnostic'
    expect_match 'validation fingerprint label' 'bring-up fingerprints'
    expect_match 'compact validation label' 'bringup'
    expect_match 'underscored validation label' 'bring_up'
    expect_match 'plural validation label' 'bring-ups'
    expect_match 'internal phase-zero identifier' 'ne_phase0-spike_defconfig'
    expect_match 'internal bring-up report' 'bring-up report'
    expect_match 'private research citation' 'research note §6'
    expect_match 'audit finding identifier' 'Audit-Finding AF-12'
    expect_match 'compact audit identifier' 'audit S3-F2'
    expect_match 'compact audit identifier' 'audit O3'
    expect_match 'compact audit identifier' 'audit C2'
    expect_match 'internal task label' 'Task 12 acceptance notes'
    expect_match 'internal risk label' 'risk R3 remains open'
    expect_match 'parenthesized internal risk label' '(R1)'
    expect_match 'parenthesized internal risk label' '(R2)'
    expect_match 'internal e2e path' 'crates/ne-e2e/tests/r1_single_cvm_direct.rs'
    expect_match 'internal wedge label' 'Wedge-6.8 implementation'
    expect_match 'licensed control-plane disclosure' 'BSL-1.1 control plane'
    expect_match 'separate private control-plane repository' 'separate private control-plane repo'
    expect_match 'implementation-specific worker disclosure' 'TypeScript control-plane Worker'
    expect_match 'private control-plane repository attribution' 'CP repo test coverage'
    expect_match 'cross-repository test attribution' 'cross-repo Vitest coverage'
    expect_match 'product-site reference' 'https://neuronedge.ai'
    expect_match 'product-domain email' 'security@neuronedge.ai'
    expect_match 'partner-recruitment language' 'We are looking for design partners'
    expect_match 'acquisition-history language' 'NeuronEdge joined Mindpool'
    expect_match 'commercial tier language' 'the v2 premium tier'
    expect_match 'author-local path' '/Users/example/Development/private-notes.md'
    expect_match 'private control-plane path' 'Commercial/ne-control-plane/docs/PRD.md'

    # Negative corpus: public terminology and normal English must remain valid.
    expect_no_match 'public repository link' 'https://github.com/Mindpool-Labs/ne-enclave'
    expect_no_match 'ordinary API path' '/api/v2/users/42'
    expect_no_match 'ordinary blocked-state word' 'the child process is wedged'
    expect_no_match 'ordinary hexadecimal token' 'p384 is a supported curve'
    expect_no_match 'public technical documentation' 'the runtime API is versioned'
}

run_self_test

# Scan all tracked text content. `git grep` reports 1 for no matches and
# greater than 1 for a scanner error. Preserve scanner errors so the check
# fails closed rather than passing silently.
git grep -n -I -i -E "$pattern" -- . ':(exclude)scripts/check-public-boundary.sh'
content_status=$?
case "$content_status" in
    0)
        echo 'public-boundary check failed: remove private references or internal delivery terminology' >&2
        exit 1
        ;;
    1)
        :
        ;;
    *)
        echo "public-boundary check failed: git grep exited with $content_status" >&2
        exit "$content_status"
        ;;
esac

# File names are public data too. Check every tracked path after content has
# passed. Include untracked paths so a pending rename is checked before staging,
# but omit paths deleted from the working tree. Preserve `git ls-files` failures
# instead of treating them as clean.
tracked_paths=$(git ls-files)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files exited with $paths_status" >&2
    exit "$paths_status"
fi

deleted_paths=$(git ls-files --deleted)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files --deleted exited with $paths_status" >&2
    exit "$paths_status"
fi

untracked_paths=$(git ls-files --others --exclude-standard)
paths_status=$?
if [ "$paths_status" -ne 0 ]; then
    echo "public-boundary check failed: git ls-files --others exited with $paths_status" >&2
    exit "$paths_status"
fi

active_paths=$(printf '%s\n%s\n' "$tracked_paths" "$untracked_paths" | while IFS= read -r path; do
    if ! printf '%s\n' "$deleted_paths" | grep -F -x "$path" >/dev/null; then
        printf '%s\n' "$path"
    fi
done)

printf '%s\n' "$active_paths" | grep -E -i "$pattern"
path_status=$?
case "$path_status" in
    0)
        echo 'public-boundary check failed: remove private references or internal delivery terminology from tracked paths' >&2
        exit 1
        ;;
    1)
        :
        ;;
    *)
        echo "public-boundary check failed: path scanner exited with $path_status" >&2
        exit "$path_status"
        ;;
esac
