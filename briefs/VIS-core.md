# VIS-core: core vision for camera streams

Board section: Devices, hardware and image (SPEC §13-14). Work item #3515; SPEC DEV-7 (as amended by #3497, D-207), DEV-8, LOG-4, PLN-7, ARC-2, RES-2, RES-3, REV-6, NET-2 (Cameras; Drones), A16, risk 23. Tier A: it handles raw capture and biometric templates, and its client parses an untrusted service's output. Authority: Mark, cameras thread, 2026-10-27:
- record faces as evidence of crimes, with "no name search or anything intrusive";
- household members are enrolled and recognised;
- detect people, animals and vehicles, with thermal;
- audio is used only for sound events and is never kept;
- 30-day retention.

Inputs come from CAM-clerk (#3514). Outputs feed owner rules (DEV-8) and the drone rows (#3516, #3517).

## Why

CAM-clerk delivers decoded frames and keeps raw capture under DEV-7, but nothing turns those frames into useful information: who or what is there, where, and whether it is someone the household enrolled. This row adds that, built so the #3497 rule holds by structure: an unknown face's encoding never leaves the process that made it.

## Design points (flagged for the reviews)

1. **A separate untrusted service.** The models run in `agentos-vision`, which is built like `agentos-infer` (INFER-SVC: a childproc-started process in the `inference` cgroup leaf, its own uid, no network, fd-passed socket, bounded line protocol, ARC-2 link guard). It is a sibling of `agentos-infer`, not a new op on it, because it holds templates and `agentos-infer` must not. CPU first (RES-3); an accelerator lease comes later (budget R8).
2. **Closed-vocabulary output.** The service returns only structured detections:
   - a class from a fixed list (person, vehicle, a small set of animal kinds, unknown-animal);
   - a box, a confidence and a track id;
   - for a face, either `enrolled:<id>` or `unknown`;
   - for a plate, its text;
   - for audio, a label from a fixed list.

   There is no free-text description, no caption, no embedding and no attribute list ("red jacket"). So nothing downstream can match unknown people by their descriptions, which was a release finding on #3497. Plate text and labels are ordinary private data (DEV-7).
3. **Faces and voices inside the service only.**
   - The service loads the enrolled templates, lent from the sealed store as the camera client key is.
   - For each face or voice it computes the encoding in memory, compares it only with those templates, returns `enrolled:<id>` or `unknown`, and then zeroes the buffer. No op returns, logs or stores an encoding.
   - Enrolment is the one op that produces a template. It runs only from the owner's tier-4 local-page step, which shows its own biometric consent notice ("enrolling someone else may need their consent", risk 23). The template goes straight into the sealed store.
   - Enrolment is the template's retention, until un-enrolment.
   - Un-enrolling destroys the template. So does erasing that person under LOG-4.
4. **Where unknown faces live.** They stay only in the capture (CAM-clerk retention, 30 days for the first household). VIS-core records derived references (segment id, frame time, box, sharpness score) so the owner's page can show "clearest unknown face per visit". Crops of unknown people go only to the owner's own page or channel on the owner's request, never to a planner or guest. A planner request to find or match an unenrolled person across captures is refused with a closed reason.
5. **Tracks and zones.** ByteTrack-class tracking runs per camera. Tracks are fused across cameras on a ground plane from camera poses the owner sets once; the poses are owner data in the sealed store, never in git. Zone entries and dwell go onto the bus as private, untrusted, rate-limited events (DEV-8). Each camera node is verified (DEV-3), so owner rules may make an event urgent. Counts of distinct people come from tracking, never from comparing face encodings.
6. **Drone outputs.** These are display data and fixes only:
   - the zone of a track, shown on the owner's per-flight tap (DRONE-enforcer, NET-6);
   - camera position fixes of the drone itself, used for the GPS cross-check (DRONE-sim).

   VIS-core sends nothing that steers a flight. The only drone message the core sends is return to dock (NET-2 Drones, Mark's card on 2026-10-27 at 20:50Z).
7. **Sound.** Audio frames from any capture clerk go to an on-service classifier. Only the labels leave the service. No audio byte is stored, logged or sent anywhere. The audio source (a node microphone) is not in CAM-node yet; part (d) works with synthetic audio until it is.
8. **No frontier path.** Templates, frames, crops and audio never go to a hosted route (REV-6, PLN-7). A frontier call carrying any of them is refused, as for raw capture.

## Open questions (asked on #3515; the brief builds on the recommendation)

1. **Model licences.** Recommended: YOLOX (Apache-2.0) or RT-DETR (Apache-2.0) for detection rather than Ultralytics YOLO (AGPL-3.0); ByteTrack (MIT); YAMNet (Apache-2.0) for sound; ONNX Runtime (MIT) as the runtime. The common face models (InsightFace SCRFD and ArcFace weights) are licensed for non-commercial use only. The builder finds a face detector and encoder whose weights allow redistribution, or the owner fetches the weights at setup and the image ships none. [Inference: from the projects' licence files as recalled; the builder confirms each one before (a).]
2. **Thermal detection.** Visible-light models do poorly on thermal frames. Recommended: a thermal-trained detector whose weights allow use, or person and animal detection by heat blobs and motion (no model), with classification left to the visible stream and the drone. Changes (e).
3. **Floor.** Continuous detection on several streams may not fit the N95 floor in 2 GB. Recommended: a declared frame rate per camera that the service lowers under admission (RES-2), with detection, not identification, as the floor guarantee. The floor figures are measured in (e).

## Split

- **(a) VIS-svc (about 110k):** `broker/vision` (protocol and client, standard library only), `broker/vision/supervise`, `broker/cmd/agentos-vision` with a fake runtime, the bounds, the closed vocabulary, and the ARC-2 guard entries.
- **(b) VIS-track (about 90k; after a and CAM-clerk a):** tracking, ground-plane fusion, zones, DEV-8 events, and the drone zone and fix outputs.
- **(c) VIS-faces (about 100k; after a):** templates in the sealed store, the in-service compare, the tier-4 enrolment step with its consent notice, un-enrolment, the LOG-4 erase hook, the planner refusal, and evidence references.
- **(d) VIS-plates-sound (about 70k; after a):** plate text and sound labels.
- **(e) VIS-models (about 90k; after a to d):** the real runtime and models, thermal (question 2), and the floor figures recorded in `broker/vision/ASSUMPTIONS.md`.

## Acceptance tests

- `TestUnenrolledEncodingNeverLeaves` (DEV-7, A16 as amended): run a synthetic capture holding a face and a voice that are not enrolled, then scan every store, log line, event, reply and output for a vector within a cosine bound of their reference encodings. Nothing is found. This catches a build that keeps or logs an unknown encoding. (c)
- `TestEnrolledRecognisedUnknownNot` (DEV-7): an enrolled synthetic face returns `enrolled:<id>` and an unknown face returns `unknown`, with no encoding in either reply. (c)
- `TestUnenrolDestroysTemplate` and `TestErasureUnenrols` (DEV-7, LOG-4): after un-enrolling or erasing a subject, the template slot is empty and the same face returns `unknown`. (c)
- `TestEnrolOnlyFromTierFour` (DEV-7): an enrol op from any other caller is refused, and the page shows the consent notice. (c)
- `TestPlannerCannotMatchUnknown` (DEV-7): a planner request to find or match an unenrolled person, by crop, by description or by track, is refused with a closed reason, and no crop of an unknown person reaches a planner. (c)
- `TestFrontierCallWithTemplateRefused` (REV-6, PLN-7): a hosted route call carrying a template, frame, crop or audio is refused. (c)
- `TestRepliesAreClosedVocabulary`: a reply with a class outside the list, free text, or an extra field is rejected by the client as `unavailable`. (a)
- `TestClientRejectsMalformedReplies` (table: wrong counts, NaN boxes, over-long line, truncated JSON, deadline) and `TestServiceRejectsOversizeRequest`. (a)
- `TestVisionLinksNothingTrusted` (ARC-2): agentosd links no vision runtime, and `broker/vision` imports the standard library only. (a)
- `TestDistinctCountWithoutIdentity`: a count of distinct people comes from tracks, and the counting path has no access to face encodings. (b)
- `TestZoneEventsRateLimited` (DEV-8), `TestDroneOutputsAreDisplayAndFixesOnly` (NET-2 Drones: no output type carries a waypoint). (b)
- `TestSoundLabelsOnlyNoAudioStored`: after a run with a marker pattern in synthetic audio, no marker byte is on disk, in the log or in any event. (d)
- `FuzzVisionReply`. (a)

Failure path: an unknown face's encoding is kept or searched, a planner matches strangers across captures, a template leaves the box, or audio is kept.

## Scope

`broker/vision/` (with its `ASSUMPTIONS.md`), `broker/vision/supervise/`, `broker/cmd/agentos-vision/`, the enrolment step in `broker/localui`, the LOG-4 erase hook where erasure lives, `broker/loops/plainname.go` (one line per fuzz target; shared, so parts that edit it run serially, D-111), this brief.

**Guard files:** `tools/risk_tier.py` (`broker/vision` → `TIER_A_BROKER`), `broker/daemon/inference_test.go` (`cmd/agentos-vision` added to `forbidden`), `broker/daemon/arc2_test.go` (the import rules for `broker/vision` and `supervise`), `tools/trusted_base_parsers.txt` (`parser .../broker/vision -- replies from the untrusted vision service`). All are pre-approved here. Each part runs `python3 tools/premerge.py --needs-mark` and owes a separate Security accept where it prints `mark` (D-137).

## Estimate

Five parts, about 460k tokens in total. Each part takes one session on the strongest model.
