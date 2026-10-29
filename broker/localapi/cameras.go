package localapi

// Camera ops (CAM-clerk part d, #3514; DEV-7, DEV-10, CH-3): the Cameras
// page lists the camera clerk's STATUS lines, the connected cameras and the
// nodes the enforcer lists, and relays the owner's tier-4 steps (connect,
// capture turn-on, retention, re-pin) and the disconnect. Each needs a
// session. A tier-4 step carries the code-generator code the owner typed
// on this page, which is its local confirmation; agentosd checks the code
// before it relays the step to the camera clerk's owner socket, and the
// page never sees a frame or a key but the node's fingerprint.
const (
	// OpCameras (Auth) answers a CameraList.
	OpCameras = "page_cameras"
	// OpCameraChange (CameraChange) answers Text{} once the camera clerk
	// has saved the change.
	OpCameraChange = "page_camera_change"
)

// CameraOps lists the camera ops, for the disjointness test.
var CameraOps = []string{OpCameras, OpCameraChange}

// The camera ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs and
// ErrLimited. No clerk text reaches the page.
const (
	// ErrCameraCode: the approval code is wrong or used (tier 4).
	ErrCameraCode = "camera code"
	// ErrCameraRefused: the clerk refused the settings: a name in use,
	// an address off the home network, a malformed key, or past the
	// number of cameras the core admits.
	ErrCameraRefused = "camera refused"
	// ErrCameraUnknown: no connected camera has that name.
	ErrCameraUnknown = "camera unknown"
	// ErrCameraUnavailable: the camera clerk could not be reached.
	ErrCameraUnavailable = "camera unavailable"
)

// CameraCodes is the closed set the camera ops refuse with past the
// session and argument checks.
var CameraCodes = []string{ErrCameraCode, ErrCameraRefused, ErrCameraUnknown, ErrCameraUnavailable}

// The camera steps a CameraChange names.
const (
	CameraConnect    = "connect"
	CameraCapture    = "capture"
	CameraRetention  = "retention"
	CameraRepin      = "repin"
	CameraDisconnect = "disconnect"
)

// CameraTier4 says whether a step needs the approval code (CH-3: connect,
// turning capture on and re-pinning are tier 4; a retention change is
// too, since it can lengthen what is kept). Disconnecting narrows.
func CameraTier4(step string) bool { return step != CameraDisconnect }

// Shape is a picture's width and height in pixels, from the node's bundle.
type Shape struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

// CameraNode is a node the enforcer lists: its address, its key's
// fingerprint (hex SHA-256 of its public key; the case label shows the
// first 8 characters) and its bundle's picture shapes.
type CameraNode struct {
	Addr    string `json:"addr"`
	Key     string `json:"key"`
	Video   Shape  `json:"video"`
	Thermal Shape  `json:"thermal"`
}

// Camera is one connected camera as the page shows it.
type Camera struct {
	ID      string `json:"id"`
	Addr    string `json:"addr"`
	Capture string `json:"capture"` // "off", "continuous" or "on-request"
	// RetentionDays is the owner's retention; 0 keeps capture in memory only.
	RetentionDays int `json:"retention_days"`
}

// CameraList is the Cameras page's list.
type CameraList struct {
	Lines   []string     `json:"lines"`
	Cameras []Camera     `json:"cameras"`
	Listed  []CameraNode `json:"listed"`
}

// CameraChange is one step on a camera. Node is the listed node a connect
// takes; Code is the approval code for a tier-4 step.
type CameraChange struct {
	Token         string     `json:"token"`
	Step          string     `json:"step"`
	ID            string     `json:"id"`
	Node          CameraNode `json:"node"`
	Capture       string     `json:"capture"`
	RetentionDays int        `json:"retention_days"`
	Code          string     `json:"code"`
}
