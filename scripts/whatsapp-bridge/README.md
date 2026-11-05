# WhatsApp bridge dependencies

The lockfile retains `qs` 6.16.2, including the already installed fix for
[GHSA-w4cr-vjpx-p82q](https://github.com/ljharb/qs/security/advisories/GHSA-w4cr-vjpx-p82q).
Both existing Express and body-parser `~6.16.0` constraints accept this patch;
their versions and the bridge's package manifest remain unchanged.

The regression test covers empty-array keys during query and URL serialization.
Run the bridge's helper tests with `node --test *.test.mjs` after installing the
frozen lockfile. These tests import pure helpers; running `bridge.js` starts the
HTTP listener and WhatsApp connection and is a separate operational action.
