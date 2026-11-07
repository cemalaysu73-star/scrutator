## What and why

<!-- One logical change. What does it do, and why? Link the issue if there is one. -->

## How it was checked

- [ ] I wrote the failing test first and it now passes
- [ ] `python -m pytest -q -p no:cacheprovider` passes (no network is used)
- [ ] `scrutator bench --out /tmp/bench` exits 0

## The project's rules

- [ ] Every claim this change makes cites evidence ids (absence is evidence; a timeout is not)
- [ ] Nothing outside the scope file is looked up; anything active is opt-in and authorised
- [ ] Text from sources is treated as data, never as instructions
- [ ] No secret can reach an output, a log, a bundle or an error
- [ ] Numbers in the docs come from a run I did, and known limits are written down
- [ ] For a new source: its terms are recorded in `docs/sources.md` and its host is in `egress.SOURCE_HOSTS`

## Notes for the reviewer

<!-- Anything surprising, anything you are unsure about. -->
