package report

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/yadid/token-guard/api/v1"
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TokenGuard Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{background:#1a1d27;border-bottom:1px solid #2d3148;padding:20px 32px;display:flex;align-items:center;gap:12px}
  header h1{font-size:1.4rem;font-weight:700;color:#fff}
  header span{font-size:.8rem;color:#6b7280;background:#2d3148;padding:3px 8px;border-radius:4px}
  .updated{margin-left:auto;font-size:.75rem;color:#6b7280}
  main{padding:32px;max-width:1200px;margin:0 auto}
  .empty{text-align:center;padding:80px;color:#6b7280}
  .card{background:#1a1d27;border:1px solid #2d3148;border-radius:10px;margin-bottom:24px;overflow:hidden}
  .card-header{padding:16px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #2d3148}
  .card-header h2{font-size:1rem;font-weight:600}
  .card-header .ns{font-size:.75rem;color:#6b7280;background:#2d3148;padding:2px 8px;border-radius:4px}
  .score-badge{margin-left:auto;padding:4px 12px;border-radius:20px;font-size:.85rem;font-weight:700}
  .score-high{background:#064e3b;color:#34d399}
  .score-mid{background:#78350f;color:#fbbf24}
  .score-low{background:#7f1d1d;color:#f87171}
  .card-body{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:0}
  .section{padding:16px 20px;border-right:1px solid #2d3148}
  .section:last-child{border-right:none}
  .section h3{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;margin-bottom:10px}
  .perm-list{list-style:none;max-height:180px;overflow-y:auto}
  .perm-list li{font-size:.78rem;padding:3px 0;color:#94a3b8;border-bottom:1px solid #1e2130;font-family:'SF Mono',Monaco,monospace}
  .perm-list li:last-child{border-bottom:none}
  .anomaly{background:#450a0a;border:1px solid #7f1d1d;border-radius:6px;padding:8px 12px;font-size:.8rem;color:#fca5a5;margin-bottom:6px;font-family:'SF Mono',Monaco,monospace}
  .none{color:#4b5563;font-size:.8rem;font-style:italic}
  .score-bar-wrap{padding:12px 20px;border-top:1px solid #2d3148;display:flex;align-items:center;gap:12px}
  .score-bar-bg{flex:1;height:6px;background:#2d3148;border-radius:3px;overflow:hidden}
  .score-bar-fill{height:100%;border-radius:3px;transition:width .3s}
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; TokenGuard</h1>
  <span>Least Privilege Auditor</span>
  <div class="updated">Last rendered: {{.Now}}</div>
</header>
<main>
{{if not .Auditors}}
  <div class="empty">No SAAuditor resources found. Create one to start auditing.</div>
{{else}}
{{range .Auditors}}
  {{$score := 0}}{{if .Status.CurrentScore}}{{$score = deref .Status.CurrentScore}}{{end}}
  {{$badgeClass := "score-low"}}
  {{if ge $score 80}}{{$badgeClass = "score-high"}}{{else if ge $score 50}}{{$badgeClass = "score-mid"}}{{end}}
  <div class="card">
    <div class="card-header">
      <h2>{{.Name}}</h2>
      <span class="ns">{{.Namespace}}</span>
      <span class="ns" style="background:#1e2130">&#x2192; {{.Spec.TargetNamespace}}</span>
      <div class="score-badge {{$badgeClass}}">Score: {{$score}}%</div>
    </div>
    <div class="score-bar-wrap">
      <span style="font-size:.75rem;color:#6b7280;width:120px">Least Privilege</span>
      <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:{{$score}}%;background:{{scoreColor $score}}"></div>
      </div>
      <span style="font-size:.75rem;color:#6b7280">{{$score}}%</span>
    </div>
    <div class="card-body">
      <div class="section">
        <h3>&#x2705; Used Permissions ({{len .Status.UsedPermissions}})</h3>
        {{if .Status.UsedPermissions}}
        <ul class="perm-list">
          {{range .Status.UsedPermissions}}<li>{{.}}</li>{{end}}
        </ul>
        {{else}}<p class="none">No usage recorded yet</p>{{end}}
      </div>
      <div class="section">
        <h3>&#x26A0;&#xFE0F; Unused Permissions ({{len .Status.UnusedPermissions}})</h3>
        {{if .Status.UnusedPermissions}}
        <ul class="perm-list">
          {{range .Status.UnusedPermissions}}<li>{{.}}</li>{{end}}
        </ul>
        {{else}}<p class="none">No unused permissions</p>{{end}}
      </div>
      <div class="section">
        <h3>&#x1F6A8; Anomalies ({{len .Status.Anomalies}})</h3>
        {{if .Status.Anomalies}}
          {{range .Status.Anomalies}}<div class="anomaly">{{.}}</div>{{end}}
        {{else}}<p class="none">No anomalies detected</p>{{end}}
      </div>
    </div>
  </div>
{{end}}
{{end}}
</main>
</body>
</html>`

type auditRow struct {
	Name      string
	Namespace string
	Spec      securityv1.SAAuditorSpec
	Status    securityv1.SAAuditorStatus
}

type templateData struct {
	Now      string
	Auditors []auditRow
}

// Server serves the HTML report for all SAAuditor resources.
type Server struct {
	Client client.Client
	addr   string
	tmpl   *template.Template
}

func NewServer(c client.Client, addr string) *Server {
	funcMap := template.FuncMap{
		"deref": func(p *int32) int32 {
			if p == nil {
				return 0
			}
			return *p
		},
		"scoreColor": func(score int32) string {
			if score >= 80 {
				return "#34d399"
			} else if score >= 50 {
				return "#fbbf24"
			}
			return "#f87171"
		},
		"not": func(v interface{}) bool {
			switch val := v.(type) {
			case bool:
				return !val
			case []auditRow:
				return len(val) == 0
			case string:
				return val == ""
			}
			return false
		},
		"ge": func(a int32, b int) bool { return a >= int32(b) },
	}
	t := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTmpl))
	return &Server{Client: c, addr: addr, tmpl: t}
}

func (s *Server) Start(ctx context.Context) error {
	logger := log.FromContext(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/report", http.StatusFound)
	})
	mux.HandleFunc("/report", s.handleReport)

	server := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down report server")
		_ = server.Shutdown(context.Background())
	}()

	logger.Info("Starting Report Server", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var list securityv1.SAAuditorList
	if err := s.Client.List(ctx, &list); err != nil {
		http.Error(w, fmt.Sprintf("Failed to list SAAuditors: %v", err), http.StatusInternalServerError)
		return
	}

	rows := make([]auditRow, 0, len(list.Items))
	for _, a := range list.Items {
		rows = append(rows, auditRow{
			Name:      a.Name,
			Namespace: a.Namespace,
			Spec:      a.Spec,
			Status:    a.Status,
		})
	}

	data := templateData{
		Now:      time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Auditors: rows,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		// Template already started writing, log only
		_ = strings.NewReader(err.Error())
	}
}
