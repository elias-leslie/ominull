package server

// Maintenance mode keeps a machine awake while maintenance runs. It is an
// ordinary package with role maintenance_mode (windows-maintenance-mode,
// linux-maintenance-mode): enforce turns it on until now + its hours setting,
// revert turns it off, audit reports. The machine ends it by itself at that
// time, so it cannot stick. Its state is its latest job, shown on the asset
// card apart from the scheduled packages and never scheduled itself.

import (
	"encoding/json"
	"strconv"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
)

// maintenanceModeView is the asset card's maintenance mode line.
type maintenanceModeView struct {
	ScriptID string      `json:"script_id"`
	Package  string      `json:"package"`
	On       bool        `json:"on"`
	Until    *time.Time  `json:"until,omitempty"`
	Pending  string      `json:"pending,omitempty"` // on | off | check while a run waits or runs
	Hours    int         `json:"hours"`             // what turning it on now would ask for
	Last     *packageRun `json:"last,omitempty"`
}

// maintenanceModeRunPending names what a waiting or running job will do.
var maintenanceModeRunPending = map[string]string{"enforce": "on", "revert": "off", "audit": "check"}

// maintenanceModeState reads on/until from the latest maintenance mode job.
// An end time already past reads as off: the machine has let go by then.
func maintenanceModeState(v *maintenanceModeView, job *response.JobRecord, now time.Time) {
	if job == nil {
		return
	}
	run := derivePackageRun(job, now)
	v.Last = run
	switch run.State {
	case "waiting", "running":
		v.Pending = maintenanceModeRunPending[run.Mode]
		return
	}
	var res response.JobResult
	if json.Unmarshal([]byte(job.ResultJSON), &res) != nil {
		return
	}
	pr, ok := scripts.ParsePackageResult(res.Stdout)
	if !ok {
		return
	}
	var d struct {
		MaintenanceMode *struct {
			On    bool   `json:"on"`
			Until string `json:"until"`
		} `json:"maintenance_mode"`
	}
	if json.Unmarshal(pr.Detail, &d) != nil || d.MaintenanceMode == nil || !d.MaintenanceMode.On {
		return
	}
	until, err := time.Parse(time.RFC3339, d.MaintenanceMode.Until)
	if err != nil || !until.After(now) {
		return
	}
	until = until.UTC()
	v.On, v.Until = true, &until
}

// maintenanceModeFor builds the view for one host from the tenant's live
// packages, or nil when no maintenance mode package fits the host.
func (s *Server) maintenanceModeFor(tenantID, endpointID, osText string, latest map[string]*response.JobRecord, now time.Time) *maintenanceModeView {
	defs, err := s.packageDefs(tenantID)
	if err != nil {
		return nil
	}
	settings, _ := s.maintenanceSettings(tenantID)
	for _, d := range defs {
		h := d.Header
		if h.Role != scripts.RoleMaintenanceMode || !h.RunsOn(osText) || d.Script.Interpreter != h.Interpreter() {
			continue
		}
		v := &maintenanceModeView{ScriptID: d.Script.ID, Package: h.Name}
		if n, err := strconv.Atoi(settings.Effective(h, endpointID).Params["hours"]); err == nil {
			v.Hours = n
		}
		maintenanceModeState(v, latest[d.Script.ID], now)
		return v
	}
	return nil
}
