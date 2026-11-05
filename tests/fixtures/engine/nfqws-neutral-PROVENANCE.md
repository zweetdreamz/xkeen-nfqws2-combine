# Version-neutral nfqws payload vectors

These nfqws configuration/list/Lua/blob bytes were extracted unchanged from the
sanitized historical `router-xkeen20/opt/etc/nfqws2` fixture. They are payload
vectors, not an XKeen 2.1 capture or evidence about a live device. They contain
no XKeen init, hook, metadata, snapshot or version claim.

Positive operation tests combine these vectors with explicitly synthetic XKeen
2.1 roots and freshly captured snapshots. The original 2.0 capture and its
checksums remain untouched for historical/offline and rejection tests.

The shared `engine-root-fixture.sh` and `engine-mocks-fixture.sh` are synthetic
2.1 contract doubles: foreground `S05xkeen start/restart on`, `stop`, actual
labelled version output. They are not a relabelled router capture.
