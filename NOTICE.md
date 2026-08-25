# Third-party code and attribution

This project is GPL-3.0-or-later (see [LICENSE](LICENSE)). Parts of it came
from elsewhere under other terms, and those terms travel with them. This
file records what, from where, and under what licence.

## dixonSolutions/protun-unblocked

<https://github.com/dixonSolutions/protun-unblocked> — MIT.

### History

pvpn was published under the MIT licence at its first commit
(`4f917b00`, 2026-07-31) and relicensed to GPL-3.0-or-later at `027e136d`
(2026-08-02 23:59:11 UTC). That repository branched at `f77ec1e0`
(2026-08-02 23:57:04 UTC), two minutes before the relicense, so everything
it inherited from here it holds under MIT. It is not bound by the GPL, and
it carries none of the post-relicense code. Its LICENSE file is the
original MIT file from this project, unmodified.

That MIT LICENSE names "Neil Luo" as copyright holder because it is a copy
of this project's original file. **It does not transfer authorship of that
repository's own work.** Copyright in the commits authored there belongs to
their authors. Work taken from it is used here under the MIT licence it was
published under, which is compatible with GPL-3.0-or-later.

### Terms

MIT permits use, modification and redistribution — including inside a
GPL-3.0 work — provided the copyright notice and permission notice are
retained for the covered portions. Combining the two yields a work
distributed under GPL-3.0-or-later, within which those portions remain
available under MIT.

    MIT License

    Copyright (c) 2026 the pvpn contributors, including the authors of
    dixonSolutions/protun-unblocked

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### How attribution is recorded

Preferred, in this order:

1. **Cherry-pick.** The two repositories share ancestry, so `git cherry-pick`
   carries the original author across into this history. Authorship is then
   a fact of the commit log rather than a claim in a file, and
   `git log --author` can prove it. Used wherever a change applies.

2. **Ported with credit.** Where the surrounding code has diverged too far
   to cherry-pick, the commit message names the upstream commit and author,
   and the file carries a header naming the source.

3. **This file.** Anything not covered by the two above.

### What has been taken

Nothing yet. Entries are added here as work is imported, each naming the
upstream commit.

<!--
Format:
| Upstream commit | Author | Taken as | What |
| --- | --- | --- | --- |
-->
