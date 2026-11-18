package monitor

// CatalogingProgressEvent is the stable event name emitted for cataloging progress snapshots.
const CatalogingProgressEvent = "cataloging-progress"

// CatalogingProgress is a point-in-time view of cataloging work. Stages contains one aggregated row
// per stage; Details contains one row for every time that stage was entered.
type CatalogingProgress struct {
	Event       string            `json:"event"`
	Sequence    uint64            `json:"sequence"`
	Expected    int64             `json:"expected"`
	Remaining   int64             `json:"remaining"`
	InFlight    int64             `json:"in_flight"`
	Failed      bool              `json:"failed"`
	Interrupted bool              `json:"interrupted"`
	Stages      []CatalogingStage `json:"stages"`
	Details     []CatalogingStage `json:"details"`
}

// CatalogingStage describes one stage, or one entry into a stage. Stage, Count, ElapsedMS, and
// Failed are always present so that consumers can aggregate snapshots without special cases.
type CatalogingStage struct {
	Stage     string `json:"stage"`
	Count     int64  `json:"count"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Elapsed   string `json:"elapsed"`
	Failed    bool   `json:"failed"`
	State     string `json:"state"`
	Layer     int    `json:"layer"`
	Parser    string `json:"parser"`
}
