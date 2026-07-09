# Contributing

### License

MigTD is licensed under the terms in [LICENSE](LICENSE.md). By contributing to the project, you agree to the license and copyright terms therein and release your contribution under these terms.

## Commit messages

When you create a commit, please write a clear and concise commit message that describes the change.
A good commit message should explain the "what" and "why" of the change, not just the "how".
This helps other contributors understand the purpose of the change and makes it easier to review and maintain the codebase.

## Commit titles

All commit titles should follow the format (all fields are required):

    <type>(<crate/module>): <subject>

    body (required)

Where:

- `<type>` is a noun describing the type of change (e.g., `fix`, `feat`, `docs`, `refactor`, etc.),
- `<crate/module>` is the name of the crate / module affected by the change (e.g., `migtd/spdm`), `crate` is required, `module` is optional.
- `<subject>` is a brief description of the change

For example:

```
feat(migtd): verify SERVTD_ATTR using SERVTD.RD API

This change adds verification of SERVTD_ATTR fields using the
SERVTD.RD API, ensuring attributes are validated during the
migration and rebinding flows.
```

This is a common convention used in many open-source projects and helps maintain a consistent commit history. See [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for more details and examples.

### Repository-scoped changes

When a change affects the repository as a whole rather than a specific crate or module (e.g., changes to CI configuration, build scripts, documentation at the root level, or tooling), use `migtd` as the crate name. For example:

```
docs(migtd): add commit message and title conventions

Add sections describing the required commit message format,
including the conventional commit title structure and the
mandatory body field. This aligns contribution guidelines with
the project's existing commit history and the Conventional
Commits specification.
```

### Sign your work

Please use the sign-off line at the end of the patch. Your signature certifies that you wrote the patch or otherwise have the right to pass it on as an open-source patch. The rules are pretty simple: if you can certify
the below (from [developercertificate.org](http://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

If you set your `user.name` and `user.email` git configs, you can sign your
commit automatically with `git commit -s`.

### AI assistance

Contributions may be developed with the help of AI coding assistants. When they
are, three rules apply. They follow from the fact that the DCO is a
certification that **only a human** can make. Generative-AI assistance must be
declared with the name and version of the tool used.
This mirrors the [Linux kernel policy on AI coding assistants](https://docs.kernel.org/process/coding-assistants.html).

#### 1. Do NOT attribute AI in `Signed-off-by`

An AI tool **must not** be named in a `Signed-off-by` line, and a contributor
must never sign off on behalf of an AI tool. The `Signed-off-by` line is the DCO
certification described above: it is a legal statement that a human makes and
takes responsibility for. A human contributor remains fully responsible for an
AI-assisted contribution, including:

- reviewing and understanding all AI-generated code;
- confirming it is correct and complies with the project's license; and
- certifying the DCO with their own `Signed-off-by` line.

#### 2. Do NOT attribute AI in `Co-authored-by`

An AI tool **must not** be named in a `Co-authored-by` line. That trailer marks
a co-author of the commit, and authorship of a contribution to this project
rests with the human contributors who are responsible for it, not with the AI
tool that assisted them. Record AI involvement with `Assisted-by` instead (see
below).

#### 3. DO attribute AI in `Assisted-by`

If a commit was generated or assisted by an AI tool, **declare it** with an
`Assisted-by` trailer that includes the tool's name and the model version.
Use the format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

- `AGENT_NAME` — the name of the AI tool or agent.
- `MODEL_VERSION` — the specific model and version used.
- `[TOOL1] [TOOL2]` — optional; additional specialized analysis tools.
  Everyday utilities (git, the compiler, make, editors, etc.) should be omitted.

Example commit trailer block:

```
Signed-off-by: Jane Developer <jane.developer@example.com>
Assisted-by: Claude Code:claude-opus-4-8
```

The `Signed-off-by` line is still required and is still the human contributor's
own certification; the `Assisted-by` line is added in addition to it, never
instead of it.
