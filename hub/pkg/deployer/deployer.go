package deployer

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"ominull/hub/pkg/storage"
)

type DeployRequest struct {
	TargetIP   string `json:"target_ip"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"` // "ssh", "winrm"
	OS         string `json:"os"`       // "linux", "windows", "macos", "auto"
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	TenantID   string `json:"tenant_id"`
	LocationID string `json:"location_id"`
	Role       string `json:"role"`
	HubURL     string `json:"hub_url"`
	APIKey     string `json:"api_key"`
}

type DeployJobStatus struct {
	JobID           string    `json:"job_id"`
	TargetIP        string    `json:"target_ip"`
	Status          string    `json:"status"` // "pending", "running", "success", "failed"
	Logs            []string  `json:"logs"`
	Error           string    `json:"error,omitempty"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time,omitempty"`
	AgentEndpointID string    `json:"agent_endpoint_id,omitempty"`
}

type Deployer struct {
	store    *storage.Store
	hubURL   string
	adminKey string
	jobs     map[string]*DeployJobStatus
	mu       sync.RWMutex
}

func New(store *storage.Store, hubURL, adminKey string) *Deployer {
	return &Deployer{
		store:    store,
		hubURL:   hubURL,
		adminKey: adminKey,
		jobs:     make(map[string]*DeployJobStatus),
	}
}

func (d *Deployer) DispatchPush(req DeployRequest) (string, error) {
	if req.TargetIP == "" {
		return "", fmt.Errorf("target_ip is required")
	}
	if req.Port <= 0 {
		req.Port = 22
	}
	if req.Username == "" {
		req.Username = "root"
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}
	if req.LocationID == "" {
		req.LocationID = "loc-home"
	}
	if req.Role == "" {
		req.Role = "workstation"
	}
	if req.HubURL == "" {
		req.HubURL = d.hubURL
	}
	if req.APIKey == "" {
		req.APIKey = d.adminKey
	}

	jobID := fmt.Sprintf("deploy-%d", time.Now().UnixNano()/1000000)
	status := &DeployJobStatus{
		JobID:     jobID,
		TargetIP:  req.TargetIP,
		Status:    "pending",
		Logs:      []string{fmt.Sprintf("[%s] Job queued for remote push deployment to %s:%d", time.Now().Format("15:04:05"), req.TargetIP, req.Port)},
		StartTime: time.Now().UTC(),
	}

	d.mu.Lock()
	d.jobs[jobID] = status
	d.mu.Unlock()

	go d.runDeployWorker(jobID, req)
	return jobID, nil
}

func (d *Deployer) runDeployWorker(jobID string, req DeployRequest) {
	d.updateJobStatus(jobID, "running", fmt.Sprintf("[%s] Connecting to %s@%s:%d via SSH...", time.Now().Format("15:04:05"), req.Username, req.TargetIP, req.Port))

	// 1. Establish SSH Client Configuration
	authMethods := make([]ssh.AuthMethod, 0)
	if req.Password != "" {
		authMethods = append(authMethods, ssh.Password(req.Password))
	}
	if req.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(req.PrivateKey))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}
	if len(authMethods) == 0 {
		// Fallback to empty keyboard-interactive
		authMethods = append(authMethods, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = req.Password
			}
			return answers, nil
		}))
	}

	sshConfig := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	targetAddr := fmt.Sprintf("%s:%d", req.TargetIP, req.Port)
	client, err := ssh.Dial("tcp", targetAddr, sshConfig)
	if err != nil {
		d.failJob(jobID, fmt.Sprintf("SSH connection failed to %s: %v", targetAddr, err))
		return
	}
	defer client.Close()

	d.appendLog(jobID, fmt.Sprintf("[%s] SSH connection established successfully.", time.Now().Format("15:04:05")))

	// 2. OS Probe & Command Construction
	targetOS := req.OS
	if targetOS == "" || targetOS == "auto" {
		d.appendLog(jobID, fmt.Sprintf("[%s] Detecting target operating system...", time.Now().Format("15:04:05")))
		unameOut, err := runSSHCmd(client, "uname -s 2>/dev/null || echo Windows")
		if err == nil {
			trimmed := strings.TrimSpace(unameOut)
			if strings.Contains(strings.ToLower(trimmed), "darwin") {
				targetOS = "macos"
			} else if strings.Contains(strings.ToLower(trimmed), "linux") {
				targetOS = "linux"
			} else if strings.Contains(strings.ToLower(trimmed), "windows") {
				targetOS = "windows"
			} else {
				targetOS = "linux"
			}
		} else {
			targetOS = "linux"
		}
	}

	d.appendLog(jobID, fmt.Sprintf("[%s] Target OS identified as [%s]. Constructing bootstrap payload...", time.Now().Format("15:04:05"), strings.ToUpper(targetOS)))

	var bootstrapCmd string
	switch targetOS {
	case "windows":
		bootstrapCmd = fmt.Sprintf(`powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iwr -UseBasicParsing '%s/bootstrap.ps1?role=%s&location=%s' | iex"`, req.HubURL, req.Role, req.LocationID)
	case "macos":
		bootstrapCmd = fmt.Sprintf(`curl -sSL "%s/bootstrap.mac.sh?role=%s&location=%s" | sudo bash`, req.HubURL, req.Role, req.LocationID)
	default: // Linux
		bootstrapCmd = fmt.Sprintf(`curl -sSL "%s/bootstrap.sh?role=%s&location=%s" | sudo bash`, req.HubURL, req.Role, req.LocationID)
	}

	d.appendLog(jobID, fmt.Sprintf("[%s] Executing bootstrap command on remote target...", time.Now().Format("15:04:05")))

	// 3. Execute Remote Bootstrap Command
	session, err := client.NewSession()
	if err != nil {
		d.failJob(jobID, fmt.Sprintf("Failed to create SSH session: %v", err))
		return
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	cmdErr := session.Run(bootstrapCmd)
	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()

	if stdoutStr != "" {
		for _, line := range strings.Split(stdoutStr, "\n") {
			if strings.TrimSpace(line) != "" {
				d.appendLog(jobID, "  [REMOTE] "+line)
			}
		}
	}
	if stderrStr != "" {
		for _, line := range strings.Split(stderrStr, "\n") {
			if strings.TrimSpace(line) != "" {
				d.appendLog(jobID, "  [STDERR] "+line)
			}
		}
	}

	if cmdErr != nil {
		d.failJob(jobID, fmt.Sprintf("Bootstrap execution returned non-zero exit code: %v", cmdErr))
		return
	}

	d.appendLog(jobID, fmt.Sprintf("[%s] Bootstrap script completed. Verifying live telemetry stream on Hub...", time.Now().Format("15:04:05")))

	// 4. Verify Live Telemetry Registration
	var verifiedEndpoint *storage.Endpoint
	for attempt := 1; attempt <= 15; attempt++ {
		time.Sleep(1 * time.Second)
		endpoints := d.store.GetEndpoints()
		for _, ep := range endpoints {
			if ep.IP == req.TargetIP || strings.EqualFold(ep.Hostname, req.TargetIP) {
				verifiedEndpoint = &ep
				break
			}
		}
		if verifiedEndpoint != nil {
			break
		}
	}

	d.mu.Lock()
	if st, ok := d.jobs[jobID]; ok {
		st.Status = "success"
		st.EndTime = time.Now().UTC()
		if verifiedEndpoint != nil {
			st.AgentEndpointID = verifiedEndpoint.ID
			st.Logs = append(st.Logs, fmt.Sprintf("[%s] 🚀 SUCCESS: Endpoint %s (%s, %s) is ONLINE and actively streaming kernel telemetry!", time.Now().Format("15:04:05"), verifiedEndpoint.Hostname, verifiedEndpoint.ID, verifiedEndpoint.OS))
		} else {
			st.Logs = append(st.Logs, fmt.Sprintf("[%s] 🟢 Bootstrap executed successfully. Telemetry pending first batch heartbeat.", time.Now().Format("15:04:05")))
		}
	}
	d.mu.Unlock()
}

func runSSHCmd(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

func (d *Deployer) updateJobStatus(jobID, status, logMsg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.jobs[jobID]; ok {
		st.Status = status
		st.Logs = append(st.Logs, logMsg)
	}
}

func (d *Deployer) appendLog(jobID, logMsg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.jobs[jobID]; ok {
		st.Logs = append(st.Logs, logMsg)
	}
}

func (d *Deployer) failJob(jobID, errMsg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.jobs[jobID]; ok {
		st.Status = "failed"
		st.Error = errMsg
		st.EndTime = time.Now().UTC()
		st.Logs = append(st.Logs, fmt.Sprintf("[%s] ❌ ERROR: %s", time.Now().Format("15:04:05"), errMsg))
	}
}

func (d *Deployer) GetJobStatus(jobID string) (*DeployJobStatus, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	st, ok := d.jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job %s not found", jobID)
	}
	return st, nil
}

func (d *Deployer) ListJobs() []*DeployJobStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	jobs := make([]*DeployJobStatus, 0, len(d.jobs))
	for _, j := range d.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}
