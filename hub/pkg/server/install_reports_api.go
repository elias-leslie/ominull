package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// handleReportInstallError handles incoming error reports from the /install portal.
// It is unauthenticated by necessity because the machine submitting the error has
// not enrolled yet. Automatic system context (IP, User-Agent, platform) is recorded.
func (s *Server) handleReportInstallError(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	addr := clientIP(r)
	ua := r.Header.Get("User-Agent")

	var errorOutput string
	var platform string
	var windowID string
	sysInfo := map[string]interface{}{}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			ErrorOutput string                 `json:"error_output"`
			Platform    string                 `json:"platform"`
			WindowID    string                 `json:"window_id"`
			SystemInfo  map[string]interface{} `json:"system_info"`
		}
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512*1024))
		if err == nil {
			_ = json.Unmarshal(bodyBytes, &req)
			errorOutput = req.ErrorOutput
			platform = req.Platform
			windowID = req.WindowID
			if req.SystemInfo != nil {
				sysInfo = req.SystemInfo
			}
		}
	} else {
		_ = r.ParseForm()
		errorOutput = r.FormValue("error_output")
		platform = r.FormValue("platform")
		windowID = r.FormValue("window_id")
		if rawSys := r.FormValue("system_info"); rawSys != "" {
			_ = json.Unmarshal([]byte(rawSys), &sysInfo)
		}
	}

	errorOutput = strings.TrimSpace(errorOutput)
	if errorOutput == "" {
		writeJSONError(w, http.StatusBadRequest, "error_output is required")
		return
	}

	if platform == "" {
		platform = portalOSFromAgent(ua)
	}

	// Enrich system info with automatic server-side details
	sysInfo["client_ip"] = addr
	sysInfo["user_agent"] = ua
	sysInfo["detected_platform"] = platform
	sysInfo["received_at"] = time.Now().UTC().Format(time.RFC3339)
	sysInfo["hub_version"] = s.agentVersion
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		sysInfo["forwarded_proto"] = proto
	}
	if host := r.Header.Get("Host"); host != "" {
		sysInfo["request_host"] = host
	}

	report, err := s.store.CreateInstallReport(storage.InstallReport{
		ClientIP:    addr,
		Platform:    platform,
		UserAgent:   ua,
		SystemInfo:  sysInfo,
		ErrorOutput: errorOutput,
		WindowID:    windowID,
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to record error report: "+err.Error())
		return
	}

	// Also persist a file copy to disk for direct filesystem inspection
	reportDir := filepath.Join("/tmp", "ominull-install-reports")
	_ = os.MkdirAll(reportDir, 0755)
	if fileData, err := json.MarshalIndent(report, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(reportDir, report.ID+".json"), fileData, 0644)
	}

	snippet := errorOutput
	if len(snippet) > 120 {
		snippet = snippet[:120] + "..."
	}
	log.Printf("[!] Installation error reported from %s (%s, report %s): %s",
		addr, platform, report.ID, strings.ReplaceAll(snippet, "\n", " "))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"id":         report.ID,
		"created_at": report.CreatedAt.Format(time.RFC3339),
		"message":    "Installation error report recorded successfully.",
	})
}

// handleInstallReports allows operators to view, list, and delete submitted install error reports.
func (s *Server) handleInstallReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			report, err := s.store.GetInstallReport(id)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"status": "ok",
				"report": report,
			})
			return
		}
		limit := 100
		if limStr := r.URL.Query().Get("limit"); limStr != "" {
			if parsed, err := strconv.Atoi(limStr); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		reports, err := s.store.ListInstallReports(limit)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if reports == nil {
			reports = []storage.InstallReport{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"count":   len(reports),
			"reports": reports,
		})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "id parameter required")
			return
		}
		if err := s.store.DeleteInstallReport(id); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"message": "Report deleted",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
