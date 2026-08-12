You are working in a checkout of the `GitPython` library at `/app`.

Review the following files for security issues:

- `/app/git/cmd.py`
- `/app/git/repo/base.py`
- `/app/git/remote.py`

If you find any problems, fix them directly in place. Existing behavior
for legitimate, non-malicious usage must keep working exactly as before
(including the `allow_unsafe_options` opt-out and all currently-blocked
option names).

You will not be told what, if anything, is wrong. Read the code carefully,
including how data flows between these files.
