package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Event represents a simplified version of the Kubernetes audit.k8s.io Event.
// We only unmarshal the fields we need to keep parsing fast and memory usage low.
type Event struct {
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	SourceIPs []string         `json:"sourceIPs"`
	ObjectRef *ObjectReference `json:"objectRef,omitempty"`
}

type ObjectReference struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	APIGroup  string `json:"apiGroup"`
}

type EventList struct {
	Items []Event `json:"items"`
}

// TokenUsage holds data about how a ServiceAccount is being used
type TokenUsage struct {
	UsedPermissions []string
	SourceIpMap     map[string]bool
	LastSeen        time.Time
}

// Receiver runs the HTTP server for K8s Audit Webhooks
// It is designed to be injected into the Operator manager as a Runnable.
type Receiver struct {
	// SAUsageMap maps "namespace/serviceaccount" to its token usage
	SAUsageMap map[string]*TokenUsage
	addr       string
	mu         sync.RWMutex
}

func NewReceiver(addr string) *Receiver {
	return &Receiver{
		SAUsageMap: make(map[string]*TokenUsage),
		addr:       addr,
	}
}

// Start runs the HTTP server.
func (r *Receiver) Start(ctx context.Context) error {
	logger := log.FromContext(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/audit", r.handleAudit)

	server := &http.Server{
		Addr:    r.addr,
		Handler: mux,
	}

	// Wait for context cancellation to shut down gracefully
	go func() {
		<-ctx.Done()
		logger.Info("Shutting down audit webhook server")
		_ = server.Shutdown(context.Background())
	}()

	logger.Info("Starting Audit Webhook Receiver", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// GetUsage returns the current usage data for a given service account
func (r *Receiver) GetUsage(username string) *TokenUsage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.SAUsageMap[username]
}

func (r *Receiver) handleAudit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() {
		_ = req.Body.Close()
	}()

	var eventList EventList
	if err := json.Unmarshal(body, &eventList); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, event := range eventList.Items {
		username := event.User.Username

		// Only track Kubernetes native ServiceAccounts
		// Username format: system:serviceaccount:<namespace>:<name>
		if strings.HasPrefix(username, "system:serviceaccount:") {
			tu, exists := r.SAUsageMap[username]
			if !exists {
				tu = &TokenUsage{
					SourceIpMap: make(map[string]bool),
				}
				r.SAUsageMap[username] = tu
			}

			// Format the permission used
			var perm string
			if event.ObjectRef != nil && event.ObjectRef.Resource != "" {
				apiGrp := event.ObjectRef.APIGroup
				if apiGrp == "" {
					apiGrp = "core"
				}
				perm = fmt.Sprintf("%s /%s/%s", event.Verb, apiGrp, event.ObjectRef.Resource)
			} else {
				perm = fmt.Sprintf("%s %s", event.Verb, event.RequestURI)
			}

			// Add to set if not exists
			if !slices.Contains(tu.UsedPermissions, perm) {
				tu.UsedPermissions = append(tu.UsedPermissions, perm)
			}

			// Track source IPs to detect external token usage (supply chain leak)
			for _, ip := range event.SourceIPs {
				tu.SourceIpMap[ip] = true
			}

			tu.LastSeen = time.Now()
		}
	}

	// Always return 200 OK so the API server doesn't retry
	w.WriteHeader(http.StatusOK)
}
