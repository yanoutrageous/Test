# M4 acceptance contract

`m4-acceptance-v1.json` records the accepted local backup, staged restore,
explicit activation and rollback revision. It contains only portable
project-relative references and compact hashes. Backup blobs, restored files,
activity pointers and full gate evidence remain local and are excluded from
Git.

The accepted active state is `STATE-M4-YANYAN-RESTORED-20260725`. The legacy
activity database remains byte-for-byte unchanged; runtime selection now uses
the atomic `data/db/active-state.json` pointer. M4 backups are on the same
volume as the product root and therefore do not claim whole-volume disaster
protection.
