# OSS-10w2: Follow-fork wiring part 2

Follow-fork wiring part 2 (OSS-10; GR26, WF3): agentosd builds `follow.New` with the store, the image's shipped root, the HOST-1b guard and the owner alert sender, registers `follow.Route(follower, applier)` as the `update` executor, and sets `localsrv.Config.DescribeRoot`/`Follow` (a fresh nonce per request into `grants.FollowIntent`); the local page's follow form and its UX wording; LocalUI on for this act. From the OSS-10w L3: retry an unsent follow alert, or show it pending on STATUS until delivered; `FollowID` or the gate refuses a nonce that is not hex (a `/` shifts the parse); decide whether the page shows a coarse reason (expired, signatures, not newer) for `RefusedRoot`

**Needs:** OSS-10w, P2-2w b, P2-2w d

**Gate:** lenses (security, UX)

