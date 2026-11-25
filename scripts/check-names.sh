#!/usr/bin/env bash
# check-names.sh: refuse private names (clients, companies, people, servers)
# in this public repo. The list of names is private and never lives in the
# repo: it is read from $NAMES_GUARD_FILE, else ~/.config/names-guard/terms.txt
# (one name per line, matched as a whole word, case-insensitive). Without the
# list the check prints one warning and passes.
#
# Words that are legitimate in this repo go in .github/names-allow.txt, one
# per line (generic words only).
#
# Usage:
#   scripts/check-names.sh              tracked files + every commit message on HEAD
#   scripts/check-names.sh --staged     added lines of the staged diff (pre-commit)
#   scripts/check-names.sh --msg FILE   a commit message file (commit-msg)
#   scripts/check-names.sh --push       commits about to be pushed, read from the
#                                       pre-push hook's stdin (messages and diffs)
set -euo pipefail
list=${NAMES_GUARD_FILE:-$HOME/.config/names-guard/terms.txt}
if [ ! -r "$list" ]; then
  echo "check-names: warning: no private name list at $list, check skipped" >&2
  exit 0
fi
root=$(git rev-parse --show-toplevel)
cd "$root"
allow=.github/names-allow.txt

# scan LABEL: read text on stdin, report "LABEL:line: name" for each hit.
scan() {
  LIST="$list" ALLOW="$allow" LABEL="$1" perl -e '
    my %allow;
    if (open(my $a, "<", $ENV{ALLOW})) { while (<$a>) { s/#.*//; s/^\s+|\s+$//g; $allow{lc $_}=1 if length } close $a }
    open(my $l, "<", $ENV{LIST}) or exit 0;
    my @t = grep { length && !$allow{lc $_} } map { s/^\s+|\s+$//gr } <$l>; close $l;
    exit 0 unless @t;
    my $alt = join "|", map { quotemeta } sort { length $b <=> length $a } @t;
    my $re = qr/(?<![A-Za-z0-9])($alt)(?![A-Za-z0-9])/i;
    my $bad = 0; my $label = $ENV{LABEL}; my $file = $label; my $n = 0;
    while (my $line = <STDIN>) {
      if ($line =~ /^\x01FILE (.*)$/) { $file = $1; $n = 0; next }
      $n++;
      while ($line =~ /$re/g) { print STDERR "check-names: $file:$n: private name \"$1\"\n"; $bad = 1 }
    }
    exit $bad;'
}

# files TEXT: emit tracked text files with file markers (binary files skipped).
tracked() {
  git ls-files -z | while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    [ "$f" = "$allow" ] && continue
    if perl -e 'read(STDIN, my $b, 8000); exit($b =~ /\0/ ? 0 : 1)' < "$f"; then continue; fi
    printf '\001FILE %s\n' "$f"; cat "$f"; echo
  done
}

added_lines() { perl -ne 'if (/^\+\+\+ b\/(.*)/) { print "\x01FILE $1\n"; next } print substr($_,1) if /^\+/ && !/^\+\+\+/'; }

rc=0
case "${1:-}" in
  "")
    tracked | scan files || rc=1
    git log --format='%x01FILE commit %h%n%B' HEAD 2>/dev/null | scan messages || rc=1 ;;
  --staged)
    git diff --cached --diff-filter=ACMRT -U0 -- . ":(exclude)$allow" | added_lines | scan staged || rc=1 ;;
  --msg)
    scan "commit message" < "$2" || rc=1 ;;
  --push)
    zero=0000000000000000000000000000000000000000
    while read -r _lref lsha _rref rsha; do
      [ "$lsha" = "$zero" ] && continue
      if [ "$rsha" = "$zero" ] || ! git cat-file -e "$rsha^{commit}" 2>/dev/null; then range=("$lsha" --not --remotes); else range=("$rsha..$lsha"); fi
      git log --format='%x01FILE commit %h%n%an <%ae>%n%cn <%ce>%n%B' "${range[@]}" | scan push || rc=1
      git log -p --format='%x01FILE commit %h' "${range[@]}" -- . ":(exclude)$allow" | added_lines | scan push || rc=1
    done ;;
  *) echo "usage: $0 [--staged | --msg FILE | --push]" >&2; exit 2 ;;
esac
if [ "$rc" -ne 0 ]; then
  echo "check-names: private names found; replace them with synthetic ones (acme, example-co, alice)" >&2
  exit 1
fi
echo "check-names: ok"
