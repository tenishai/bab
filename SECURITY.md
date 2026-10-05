# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem.

Report it privately to **security@tenish.ai**.

If this repository's **Security** tab shows a **Report a vulnerability**
button, you can use that instead. GitHub offers it only on public
repositories where it has been turned on.

Include what you can of:

- what the problem is and what an attacker could do with it;
- the version, commit, or tag you tested;
- steps to reproduce, or a proof of concept;
- any configuration it depends on.

You don't need a complete write-up to report. A clear description of the
problem is enough to start.

## What happens next

- We acknowledge your report within **14 days**.
- We tell you whether we've confirmed the problem as soon as we know.
- We fix confirmed problems in the next release, or sooner for serious ones,
  and tell you before the fix is public.
- We credit you in the release notes unless you'd rather we didn't.

We ask that you give us a reasonable chance to fix a problem before disclosing
it publicly, and that you don't access or change data that isn't yours while
testing.

## Supported versions

bab is pre-1.0. Security fixes go into the **latest release** only; older
releases are not patched. If you're running an older version, upgrade to get
fixes.

## Scope

bab is a door: it decides whether an actor may take an action on an object.
It fails closed for anything above read: when OpenFGA is unreachable or errors,
read-tier actions degrade to allow by design (`bab/door.py`), and every other
action is denied or routed to fallback approvers. In scope:

- the decision: `check` returning allow for a request the catalogue and stored
  tuples do not grant, or returning allow for a non-read action when OpenFGA is
  unreachable or errors;
- ceilings: `bab.ceiling.permitted`, or the generated ceiling relations,
  accepting a grant the team's ceiling does not cover. bab does not write
  grants itself; a caller that writes tuples without consulting the ceiling is
  that caller's issue;
- the generated model: a catalogue that produces a model granting more than the
  catalogue says;
- the syncs (Okta, topology): input that makes a sync write tuples for
  principals or objects it was not given.

**Out of scope:** vulnerabilities in third-party dependencies, OpenFGA included
(please report those upstream, and tell us if we ship an affected version), and
problems that require an attacker to already control the OpenFGA store, the
identity provider, or the account bab runs under.
