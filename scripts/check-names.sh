#!/usr/bin/env bash
# check-names.sh: fail when a tracked file holds a word whose sha256 is in
# .github/denyhash.txt (private names that must never reach this public repo).
# The list holds hashes only, never the words. Hashes a repo may legitimately
# contain (a common word that only collides with a listed name) go in
# .github/denyhash-allow.txt, one per line, with a "# why" comment after it.
# Usage: scripts/check-names.sh            (all tracked files)
#        scripts/check-names.sh FILE...    (only these files)
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
deny=.github/denyhash.txt
allow=.github/denyhash-allow.txt
[ -f "$deny" ] || { echo "check-names: $deny missing" >&2; exit 1; }
if [ "$#" -gt 0 ]; then files=("$@"); else
  files=(); while IFS= read -r -d '' f; do files+=("$f"); done < <(git ls-files -z)
fi
[ "${#files[@]}" -gt 0 ] || exit 0
printf '%s\0' "${files[@]}" | DENY="$deny" ALLOW="$allow" perl -0 -MDigest::SHA=sha256_hex -e '
  my %deny; { local $/ = "\n"; open(my $d, "<", $ENV{DENY}) or die; while (<$d>) { s/\s*#.*//; s/\s+//g; $deny{$_}=1 if length } close $d;
  if (open(my $a, "<", $ENV{ALLOW})) { while (<$a>) { s/\s*#.*//; s/\s+//g; delete $deny{$_} if length } close $a } }
  my $bad = 0; local $/ = "\0";
  while (my $f = <STDIN>) { chomp $f; next if $f eq $ENV{DENY} || $f eq $ENV{ALLOW}; next unless -f $f;
    open(my $h, "<", $f) or next; binmode $h; my $head = ""; read($h, $head, 8000); if ($head =~ /\0/) { close $h; next } seek($h, 0, 0); local $/ = "\n"; my $n = 0;
    while (my $line = <$h>) { $n++; next if $line =~ /\0/; my $l = lc $line; my %c;
      my @w = $l =~ /[a-z0-9]+/g; $c{$_}=1 for @w;
      while ($l =~ /([a-z0-9]+)[ \t]+(?=([a-z0-9]+))/g) { $c{"$1 $2"}=1 }
      for my $t ($l =~ /[a-z0-9_.@-]+/g) { $t =~ s/^[._@-]+|[._@-]+$//g; $c{$t}=1;
        $c{$_}=1 for split /[.@]/, $t; $c{$_}=1 for split /[._@]/, $t; $c{$_}=1 for split /[-.@]/, $t; }
      for my $k (keys %c) { if ($deny{sha256_hex($k)}) { print STDERR "check-names: $f:$n holds a denied name\n"; $bad = 1 } } }
    close $h }
  exit $bad;' || { echo "check-names: private names found (see above); replace them with synthetic ones" >&2; exit 1; }
echo "check-names: ok"
