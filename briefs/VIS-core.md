# VIS-core: core vision for camera streams

Board section: Devices, hardware and image (SPEC §13-14). Work item #3515; SPEC DEV-7 (as amended by #3497, D-207), DEV-8, LOG-4, PLN-3, PLN-7, KRN-3, RES-2, RES-3, NET-2 (Cameras; Drones), A16, risk 23. Tier A: it handles raw capture and biometric templates, and its client parses an untrusted service's output. Authority: Mark, cameras thread, 2026-10-27:
- record faces as evidence of crimes, with "no name search or anything intrusive";
- household members are enrolled and recognised;
- detect people, animals and vehicles, with thermal;
- audio is used only for sound events and is never kept;
- 30-day retention.

Inputs come from CAM-clerk (#3514). Outputs feed owner rules (DEV-8) and the drone rows (#3516, #3517).

## Why

CAM-clerk delivers decoded frames and keeps raw capture under DEV-7, but nothing turns those frames into useful information: who or what is there, where, and whether it is someone the household enrolled. This row adds that, built so the #3497 rule holds by structure: an unknown face's encoding never leaves the process that made it.

## Design points (flagged for the reviews)

1. **A separate untrusted service.** The models run in `agentos-vision`, which is built like `agentos-infer` (INFER-SVC: a childproc-started process in the `inference` cgroup leaf, its own uid, no network, fd-passed socket, bounded line protocol, link guard of INFER-SVC's INF-5). It is a sibling of `agentos-infer`, not a new op on it, because it holds templates and `agentos-infer` must not. CPU first (RES-3); an accelerator lease comes later (budget R8).
2. **Closed-vocabulary output.** The service returns only structured detections:
   - a class from a fixed list (person, vehicle, a small set of animal kinds, unknown-animal);
   - a box, a confidence and a track id;
   - for a face, either `enrolled:<id>` or `unknown`;
   - for a plate, its text;
   - for audio, a label from a fixed list.

   There is no free-text description, no caption, no embedding and no attribute list ("red jacket"). So nothing downstream can match unknown people by their descriptions, which was a release finding on #3497. Plate text and labels are ordinary private data (DEV-7).

   The client checks every field before anything leaves it, because a compromised service could try to smuggle an encoding out:
   - plate text uses only `[A-Z0-9 -]`, is at most 10 characters, and is quoted as untrusted device-supplied text (DEV-8);
   - `<id>` in `enrolled:<id>` must be in the client's own list of enrolled ids, which comes from the sealed store, not the service;
   - boxes are integers inside the declared frame size, and confidences are quantised to two decimals;
   - a request may produce only a bounded number of detections.

   The covert channel that remains is a few bits per detection through box placement. [Risk: accepted; a stolen encoding needs hundreds of bytes per face, so leaking one would take sustained, visible garbage detections. (b) counts implausible detection rates as a service fault.]
3. **Faces and voices inside the service only.**
   - The service loads the enrolled templates, lent from the sealed store as the camera client key is.
   - For each face or voice it computes the encoding in memory, compares it only with those templates, returns `enrolled:<id>` or `unknown`, and then zeroes the buffer. No op returns, logs or stores an encoding.
   - Enrolment is the one op that produces a template. It runs only from the owner's tier-4 local-page step, which shows its own biometric consent notice ("enrolling someone else may need their consent", risk 23). The template goes straight into the sealed store.
   - Enrolment is the template's retention, until un-enrolment.
   - Each template is content sealed under the enrolled person's subject key (`broker/kernel/erase.go`, LOG-4). Un-enrolling erases the template. Erasing the subject destroys that key, so the template goes with it and there is no separate hook to forget.
4. **Where unknown faces live.** They stay only in the capture (CAM-clerk retention, 30 days for the first household). VIS-core records derived references (segment id, frame time, box, sharpness score) so the owner's page can show "clearest unknown face per visit". Crops of unknown people go only to the owner's own page or channel on the owner's request, never to a planner or guest. A planner request to find or match an unenrolled person across captures is refused with a closed reason.
5. **Tracks and zones.** ByteTrack-class tracking runs per camera. Tracks are fused across cameras on a ground plane from camera poses the owner sets once; the poses are owner data in the sealed store, never in git. Zone entries and dwell go onto the bus as private, untrusted, rate-limited events (DEV-8). Each camera node is verified (DEV-3), so owner rules may make an event urgent. Counts of distinct people come from tracking, never from comparing face encodings.
6. **Drone outputs.** These are display data and fixes only:
   - the zone of a track, shown on the owner's per-flight tap (DRONE-enforcer, NET-6);
   - camera position fixes of the drone itself, used for the GPS cross-check (DRONE-sim).

   VIS-core sends nothing that steers a flight. The only drone message the core sends is return to dock (NET-2 Drones, Mark's card on 2026-10-27 at 20:50Z).
7. **Sound.** Audio frames from any capture clerk go to an on-service classifier. Only the labels leave the service. No audio byte is stored, logged or sent anywhere. The audio source (a node microphone) is not in CAM-node yet; part (d) works with synthetic audio until it is.
8. **Labels, not a new router rule.** Templates, frames, crops and audio carry the raw-capture label (PLN-3), so DEV-7's existing routing applies unchanged. They stay on the box except to a compute host allowed private data (PLN-7) or a route the owner allowed capture for, and a frontier call carrying them is refused by the model router's existing check (A16). VIS-core adds no router code; it only labels what it produces.

## Open questions (asked on #3515; the brief builds on the recommendation)

1. **Model licences.** Recommended: YOLOX (Apache-2.0) or RT-DETR (Apache-2.0) for detection rather than Ultralytics YOLO (AGPL-3.0); ByteTrack (MIT); YAMNet (Apache-2.0) for sound; ONNX Runtime (MIT) as the runtime. The common face models (InsightFace SCRFD and ArcFace weights) are licensed for non-commercial use only. The builder finds a face detector and encoder whose weights allow redistribution, or the owner fetches the weights at setup and the image ships none. [Inference: from the projects' licence files as recalled; the builder confirms each one before (a).]
2. **Thermal detection.** Visible-light models do poorly on thermal frames. Recommended: a thermal-trained detector whose weights allow use, or person and animal detection by heat blobs and motion (no model), with classification left to the visible stream and the drone. Changes (e).
3. **Floor.** Continuous detection on several streams may not fit the N95 floor in 2 GB. Recommended: a declared frame rate per camera that the service lowers under admission (RES-2), with detection, not identification, as the floor guarantee. The floor figures are measured in (e).

## Split

- **(a) VIS-svc (about 110k):** `broker/vision` (protocol and client, standard library only), `broker/vision/supervise`, `broker/cmd/agentos-vision` with a fake runtime, the bounds, the closed vocabulary, and the ARC-2 guard entries.
- **(b) VIS-track (about 90k; after a and CAM-clerk a):** tracking, ground-plane fusion, zones, DEV-8 events, and the drone zone and fix outputs.
- **(c) VIS-faces (about 100k; after a):** templates in the sealed store, the in-service compare, the tier-4 enrolment step with its consent notice, un-enrolment, the LOG-4 erase hook, the planner refusal, and evidence references.
- **(d) VIS-plates-sound (about 70k; after a):** plate text and sound labels.
- **(e) VIS-models (about 90k; after a to d):** the real runtime and models, thermal (question 2), the synthetic scene and plate set, and the floor figures recorded in `broker/vision/ASSUMPTIONS.md`.
- **(f) VIS-wire (about 80k; after a, c and CAM-clerk d), the integration owner:**
  - agentosd starts the service through `broker/vision/supervise` in `broker/cmd/agentosd/vision.go`, as `infer.go` starts `agentos-infer`;
  - the `agentos-vision` uid in `image/mkosi/mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf` and `usr/lib/agentos/with-uids`, and its flag in `agentosd.service`;
  - the feed from `agentos-camera` (CAM-clerk d) into the service socket;
  - events onto the bus;
  - one end-to-end test (`broker/e2e`) running a synthetic node, CAM-clerk, VIS and an owner rule.

## Acceptance tests

- `TestUnenrolledEncodingNeverLeaves` (DEV-7, A16 as amended): run a synthetic capture holding a face and a voice that are not enrolled, then scan every store, log line, event, reply and output for a vector within a cosine bound of their reference encodings. Nothing is found. This catches a build that keeps or logs an unknown encoding. (c)
- `TestEnrolledRecognisedUnknownNot` (DEV-7): an enrolled synthetic face returns `enrolled:<id>` and an unknown face returns `unknown`, with no encoding in either reply. (c)
- `TestUnenrolDestroysTemplate` and `TestErasureUnenrols` (DEV-7, LOG-4): after un-enrolling or erasing a subject, the template slot is empty and the same face returns `unknown`. (c)
- `TestEnrolOnlyFromTierFour` (DEV-7): an enrol op from any other caller is refused, and the page shows the consent notice. (c)
- `TestPlannerCannotMatchUnknown` (DEV-7): a planner request to find or match an unenrolled person, by crop, by description or by track, is refused with a closed reason, and no crop of an unknown person reaches a planner. (c)
- `TestOutputsCarryCaptureLabel` (PLN-3, DEV-7): every template, frame reference, crop and audio buffer VIS-core produces carries the raw-capture label, so the router's existing A16 refusal applies. (c)
- `TestEnrolledIDMustBeKnown`: a reply naming an id not in the client's enrolled list is rejected as `unavailable`. (a)
- `TestPlateTextBounded` (DEV-8): plate text outside `[A-Z0-9 -]{1,10}` is rejected, and accepted text reaches events quoted. (a)
- `TestBoxesAndConfidenceBounded`: boxes outside the frame, non-integer boxes, unquantised confidences and over-count replies are rejected. (a)
- `TestRepliesAreClosedVocabulary`: a reply with a class outside the list, free text, or an extra field is rejected by the client as `unavailable`. (a)
- `TestClientRejectsMalformedReplies` (table: wrong counts, NaN boxes, over-long line, truncated JSON, deadline) and `TestServiceRejectsOversizeRequest`. (a)
- `TestVisionLinksNothingTrusted` (KRN-3 link guard, as INF-5): agentosd links no vision runtime, and `broker/vision` imports the standard library only. (a)
- `TestVisionRunsInInferenceLeaf` and `TestVisionOOMStaysInLeaf` (RES-2): the service runs in the inference leaf and its OOM kill stays there. (a)
- `TestRunsWithNoAccelerator` (RES-3): the service passes every (a)–(d) test on CPU only. (a)
- `TestFrameRateDropsUnderAdmission` (RES-2): when admission refuses headroom, the per-camera frame rate falls to the declared floor rate and detection continues. (b)
- `TestRealRuntimeDetect` (build tag `vision_real`, the image machine test): on the synthetic scene set (rendered people, vehicles and animals, visible and thermal), recall at or above the thresholds recorded in ASSUMPTIONS. (e)
- `TestThermalDetect`: heat-blob or thermal-model detection finds the synthetic thermal subjects. (e)
- `TestPlateReadOnSyntheticSet`: synthetic plates read at or above the recorded accuracy. (d)
- `TestFloorFigures`: RSS, cold start and per-frame latency are recorded at the floor and within the brief's limits. (e)
- `TestEndToEndCameraToRule`: a synthetic node's person in a zone reaches an owner rule as a verified event, and no capture byte is in the log. (f)
- `TestDistinctCountWithoutIdentity`: a count of distinct people comes from tracks, and the counting path has no access to face encodings. (b)
- `TestZoneEventsRateLimited` (DEV-8), `TestDroneOutputsAreDisplayAndFixesOnly` (NET-2 Drones: no output type carries a waypoint). (b)
- `TestSoundLabelsOnlyNoAudioStored`: after a run with a marker pattern in synthetic audio, no marker byte is on disk, in the log or in any event. (d)
- `FuzzVisionReply`. (a)

Failure path: an unknown face's encoding is kept or searched, a planner matches strangers across captures, a template leaves the box, or audio is kept.

## Scope

`broker/vision/` (with its `ASSUMPTIONS.md`), `broker/vision/supervise/`, `broker/cmd/agentos-vision/`, the enrolment step in `broker/localui`, the template sealing through `broker/kernel` subject keys (a call, not a change to `kernel/erase.go`), (f)'s files (`broker/cmd/agentosd/vision.go`, `agentosd.service`, `agentos-setup.conf`, `with-uids`, the feed in `broker/cmd/agentos-camera`, `broker/e2e`), `broker/loops/plainname.go` (one line per fuzz target; shared, so parts that edit it run serially, D-111), this brief.

**Guard files:**
- `tools/risk_tier.py` (`vision` and `vision/supervise` in `TIER_A_BROKER`; `tests/test_risk_tier.py` pins it).
- `broker/daemon/arc2_test.go`: import rules for `vision` and `vision/supervise`, and both added to the `cmd/agentosd` list.
- `broker/daemon/inference_test.go`: `cmd/agentos-vision` in `forbidden` and in its self-check; `vision` in `netOK` (unix only) and `unixDialers`.
- `tools/trusted_base_parsers.txt`: `parser github.com/ghbmrk/agentos/broker/vision -- replies from the untrusted vision service` and `inert github.com/ghbmrk/agentos/broker/vision/supervise -- starts the vision service; decodes nothing`.
- A one-line `exempt-pr N` companion PR in `tools/g1_scope_g2.txt` under D-198 for each part, since the G2 freeze (D-128) does not list `broker/vision/` or `broker/cmd/agentos-vision/`.

All are pre-approved here. `tools/risk_tier.py`, `tools/g1_scope_g2.txt` and the parser list are gate files, so each part's PR and each companion needs the separate Security accept. Each part runs `python3 tools/premerge.py --needs-mark` and owes a separate Security accept where it prints `mark` (D-137).

## Estimate

Six parts, about 540k tokens in total. Each part takes one session on the strongest model.
