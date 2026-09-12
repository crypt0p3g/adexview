# adexview origin and third-party notices

This project started as an extended derivative of
[`takito1812/adx-query`](https://github.com/takito1812/adx-query), written by
Víctor García and distributed under the MIT License. The upstream project
provided the original offline AD Explorer snapshot reader, LDAP filter engine,
query engine, command-line interface, and output formatters.

Version 2.0 restructured the code into the `adexview` package. The following
modules are derived from the upstream files named next to them; the reader
and filter engine were substantially rewritten in the process, while the
query engine, formatters and query CLI remain close to the originals:

| This project | Upstream file | Relationship |
| --- | --- | --- |
| `src/adexview/snapshot.py` | `dat_reader.py` | rewritten around memory-mapped decoding with bounds checks; same format knowledge |
| `src/adexview/ldapfilter.py` | `filter_engine.py` | extended with ordering/approximate matches and SID/GUID text comparison |
| `src/adexview/query.py` | `query_engine.py` | retained |
| `src/adexview/formatters.py` | `formatters.py` | retained |
| `src/adexview/querycli.py` | `adx_query.py` | retained |

The audit engine, attribute decoders, SQLite index, browser viewer, library
administration, authentication, HTTPS support, and tests were developed for
this project. It is independent of, and not endorsed by, the upstream author.

The original copyright and permission notice are preserved in `LICENSE`:

> Copyright (c) 2025 Víctor García

The snapshot format knowledge also builds on the published work in
[`c3c/ADExplorerSnapshot.py`](https://github.com/c3c/ADExplorerSnapshot.py)
(MIT licensed). That project is not bundled as a dependency.

AD Explorer is a Microsoft Sysinternals product. This project is an
independent offline parser of files it produces and is not affiliated with or
endorsed by Microsoft.
