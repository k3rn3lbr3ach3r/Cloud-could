package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// -----------------------------------------------
//   ANSI COLOR CODES
// -----------------------------------------------

var (
	Silent   bool
	Verbose  bool
	Debug    bool
	Reset    = "\033[0m"
	Bold     = "\033[1m"
	Dim      = "\033[2m"
	Italic   = "\033[3m"
	Red      = "\033[91m"
	Green    = "\033[92m"
	Yellow   = "\033[93m"
	Blue     = "\033[94m"
	Magenta  = "\033[95m"
	Cyan     = "\033[96m"
	White    = "\033[97m"
	Gray     = "\033[90m"
	BRed     = "\033[41m"
	BGreen   = "\033[42m"
	BYellow  = "\033[43m"
	BBlue    = "\033[44m"
	BCyan    = "\033[46m"
	BMagenta = "\033[45m"
)

func disableColors() {
	Reset = ""
	Bold = ""
	Dim = ""
	Italic = ""
	Red = ""
	Green = ""
	Yellow = ""
	Blue = ""
	Magenta = ""
	Cyan = ""
	White = ""
	Gray = ""
	BRed = ""
	BGreen = ""
	BYellow = ""
	BBlue = ""
	BCyan = ""
	BMagenta = ""
}

// -----------------------------------------------
//   LOGGING HELPERS
// -----------------------------------------------

func ts() string {
	return fmt.Sprintf("%s[%s]%s", Gray, time.Now().Format("15:04:05"), Reset)
}

func logInfo(format string, a ...any) {
	if Silent {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[*]%s %s\n", ts(), Blue, Reset, msg)
}

func logSuccess(format string, a ...any) {
	if Silent {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[+]%s %s%s%s\n", ts(), Green, Reset, Green, msg, Reset)
}

func logWarn(format string, a ...any) {
	if Silent {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[!]%s %s%s%s\n", ts(), Yellow, Reset, Yellow, msg, Reset)
}

func logError(format string, a ...any) {
	if Silent {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[-]%s %s%s%s\n", ts(), Red, Reset, Red, msg, Reset)
}

func logDebug(format string, a ...any) {
	if !Debug {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[D]%s %s%s%s\n", ts(), Gray, Reset, Gray, msg, Reset)
}

func logVerbose(format string, a ...any) {
	if !Verbose {
		return
	}
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s %s[~]%s %s\n", ts(), Gray, Reset, msg)
}

func logSection(title string) {
	if Silent {
		return
	}
	bar := strings.Repeat("-", 60)
	fmt.Printf("\n%s%s  +%s+\n", Cyan, Bold, bar)
	fmt.Printf("  |  %-58s|\n", title)
	fmt.Printf("  +%s+%s\n", bar, Reset)
}

func logResult(label, bucket, status, extra string) {
	if Silent {
		return
	}
	statusColors := map[string]string{
		"OPEN":          BRed + White + Bold + " OPEN ",
		"PRIVATE":       BBlue + White + " PRIVATE ",
		"PUBLIC":        BRed + White + Bold + " PUBLIC ",
		"READ":          BGreen + White + Bold + " READ ",
		"WRITE":         BRed + White + Bold + " WRITE ",
		"READ_ACP":      BYellow + White + Bold + " READ_ACP ",
		"WRITE_ACP":     BRed + White + Bold + " WRITE_ACP ",
		"FULL_CONTROL":  BMagenta + White + Bold + " FULL_CTRL ",
		"ACCESS_DENIED": Gray + " ACCESS DENIED ",
		"NOT_FOUND":     Gray + " NOT FOUND ",
		"ERROR":         Yellow + " ERROR ",
		"MANUAL":        BCyan + White + " MANUAL ",
		"UNKNOWN":       BYellow + White + " UNKNOWN ",
	}
	color, ok := statusColors[strings.ToUpper(status)]
	if !ok {
		color = Gray + " " + status + " "
	}
	fmt.Printf("  %s%-18s%s %s%-50s%s %s%s  %s%s%s\n",
		Cyan, label, Reset, White, bucket, Reset, color, Reset, Gray, extra, Reset)
}

// -----------------------------------------------
//   PROGRESS TRACKING
// -----------------------------------------------

type ProgressTracker struct {
	Total     int64
	Completed int64
	Found     int64
	Errors    int64
	StartTime time.Time
	Label     string
}

func NewProgressTracker(total int, label string) *ProgressTracker {
	return &ProgressTracker{
		Total:     int64(total),
		StartTime: time.Now(),
		Label:     label,
	}
}

func (p *ProgressTracker) Increment() {
	atomic.AddInt64(&p.Completed, 1)
}

func (p *ProgressTracker) IncrementFound() {
	atomic.AddInt64(&p.Found, 1)
}

func (p *ProgressTracker) IncrementErrors() {
	atomic.AddInt64(&p.Errors, 1)
}

func (p *ProgressTracker) Print() {
	if Silent {
		return
	}
	completed := atomic.LoadInt64(&p.Completed)
	found := atomic.LoadInt64(&p.Found)
	errors := atomic.LoadInt64(&p.Errors)
	total := p.Total

	pct := float64(0)
	if total > 0 {
		pct = float64(completed) / float64(total) * 100
	}

	elapsed := time.Since(p.StartTime)
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(completed) / elapsed.Seconds()
	}

	// Build progress bar
	barWidth := 30
	filled := int(pct / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)

	fmt.Printf(
		"\r  %s[%s]%s %s%.1f%%%s  %s|%s  %d/%d  %sfound:%s %s%d%s  %serr:%s %s%d%s  %s%.0f/s%s  ",
		Cyan,
		bar,
		Reset,
		Bold,
		pct,
		Reset,
		Gray,
		Reset,
		completed,
		total,
		Green,
		Reset,
		Green,
		found,
		Reset,
		Yellow,
		Reset,
		Yellow,
		errors,
		Reset,
		Gray,
		rate,
		Reset,
	)
}

func (p *ProgressTracker) Done() {
	if Silent {
		return
	}
	completed := atomic.LoadInt64(&p.Completed)
	found := atomic.LoadInt64(&p.Found)
	errors := atomic.LoadInt64(&p.Errors)
	elapsed := time.Since(p.StartTime)

	fmt.Printf("\r%s\r", strings.Repeat(" ", 120)) // Clear line
	logSuccess("%s complete: %d/%d checked, %s%d found%s, %d errors in %s",
		p.Label, completed, p.Total, Cyan, found, Green, errors,
		elapsed.Truncate(time.Millisecond))
}

// -----------------------------------------------
//   BANNER
// -----------------------------------------------

func printBanner() {
	if Silent {
		return
	}
	fmt.Printf("%s%s", Cyan, Bold)
	fmt.Println(`
  ██████╗██╗      ██████╗ ██╗   ██╗██████╗      ██████╗ ██████╗ ██╗   ██╗██╗     ██████╗ 
 ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔════╝██╔═══██╗██║   ██║██║     ██╔══██╗
 ██║     ██║     ██║   ██║██║   ██║██║  ██║    ██║     ██║   ██║██║   ██║██║     ██║  ██║
 ██║     ██║     ██║   ██║██║   ██║██║  ██║    ██║     ██║   ██║██║   ██║██║     ██║  ██║
 ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ╚██████╗╚██████╔╝╚██████╔╝███████╗██████╔╝
  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝      ╚═════╝ ╚═════╝  ╚═════╝╚══════╝╚═════╝ `)
	fmt.Print(Reset)
	fmt.Printf(
		`%s  +---------------------------------------------------------------------------------+
  |   Multi-Cloud Pentesting Framework  ·  by %sk3rn3lbr3ach3r%s  ·  v2.0.0             |
  |   AWS S3 + GCS + Azure + Alibaba  ·  Discovery + Deep Scan + Evasion            |
  |   Rate Limit Bypass · Proxy Rotation · Auto-Setup · Multi-Format Reports        |
  +---------------------------------------------------------------------------------+%s
`,
		Gray,
		Cyan,
		Gray,
		Reset,
	)
}

// -----------------------------------------------
//   SCAN PHASE HEADER
// -----------------------------------------------

func printPhaseHeader(phase int, title string) {
	if Silent {
		return
	}
	fmt.Printf("\n%s%s", Magenta, Bold)
	fmt.Printf("  ╔══════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("  ║  PHASE %d: %-60s║\n", phase, title)
	fmt.Printf("  ╚══════════════════════════════════════════════════════════════════════╝\n")
	fmt.Print(Reset)
}

// -----------------------------------------------
//   SEVERITY CLASSIFICATION
// -----------------------------------------------

type FindingSeverity int

const (
	SevInfo     FindingSeverity = 0
	SevLow      FindingSeverity = 1
	SevMedium   FindingSeverity = 2
	SevHigh     FindingSeverity = 3
	SevCritical FindingSeverity = 4
)

func (s FindingSeverity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s FindingSeverity) Color() string {
	switch s {
	case SevCritical:
		return Red + Bold
	case SevHigh:
		return Red
	case SevMedium:
		return Yellow
	case SevLow:
		return Blue
	default:
		return Gray
	}
}

func classifyFinding(finding string) FindingSeverity {
	fl := strings.ToLower(finding)

	// Critical: write access, full control, anonymous upload/delete,
	// or a grant/policy that hands access to ANY authenticated cloud
	// account -- not just the bucket owner (AWS AuthenticatedUsers group,
	// GCP allAuthenticatedUsers, open Principal:* policy).
	if strings.Contains(fl, "write (anonymous)") ||
		strings.Contains(fl, "delete (anonymous)") ||
		strings.Contains(fl, "public-read-write") ||
		strings.Contains(fl, "full_control") ||
		strings.Contains(fl, "authenticatedusers") ||
		strings.Contains(fl, "any authenticated") ||
		strings.Contains(fl, "any aws account") ||
		strings.Contains(fl, "principal:* with no restricting") {
		return SevCritical
	}

	// High: public listing, anonymous access, proof of concept
	if strings.Contains(fl, "public list") ||
		strings.Contains(fl, "anonymous") ||
		strings.Contains(fl, "proof of concept") ||
		strings.Contains(fl, "write (authenticated)") {
		return SevHigh
	}

	// Medium: authenticated access, CORS wildcard, website hosting
	if strings.Contains(fl, "authenticated") ||
		strings.Contains(fl, "cors") ||
		strings.Contains(fl, "website") ||
		strings.Contains(fl, "subdomain takeover") ||
		strings.Contains(fl, "https not enforced") {
		return SevMedium
	}

	// Low: versioning, logging, policy readable
	if strings.Contains(fl, "versioning") ||
		strings.Contains(fl, "logging") ||
		strings.Contains(fl, "soft delete") ||
		strings.Contains(fl, "referer") {
		return SevLow
	}

	return SevInfo
}

// -----------------------------------------------
//   ENHANCED FINAL REPORT (scan.go uses this)
// -----------------------------------------------

func printSeverityBadge(sev FindingSeverity) string {
	switch sev {
	case SevCritical:
		return fmt.Sprintf("%s%s CRITICAL %s", BRed, White+Bold, Reset)
	case SevHigh:
		return fmt.Sprintf("%s%s HIGH %s", BRed, White, Reset)
	case SevMedium:
		return fmt.Sprintf("%s%s MEDIUM %s", BYellow, White, Reset)
	case SevLow:
		return fmt.Sprintf("%s%s LOW %s", BBlue, White, Reset)
	default:
		return fmt.Sprintf("%s INFO %s", Gray, Reset)
	}
}

// -----------------------------------------------
//   IDENTITY / AUTH CONTEXT
// -----------------------------------------------

// printIdentityBanner shows which principal (if any) authenticated-mode
// deep-scan checks will run as for a given cloud, so the analyst knows
// whose credentials cross-account/authenticated-access findings belong to.
func printIdentityBanner(ctx AuthContext) {
	if Silent {
		return
	}
	if !ctx.Authenticated {
		fmt.Printf("  %s%-8s%s %s%s%s\n", Cyan, strings.ToUpper(ctx.Cloud), Reset, Gray, "no credentials configured -- authenticated checks will run anonymously", Reset)
		return
	}
	detail := ctx.Principal
	if ctx.Account != "" {
		detail = fmt.Sprintf("%s (account: %s)", detail, ctx.Account)
	}
	if ctx.Extra != "" {
		detail = fmt.Sprintf("%s [%s]", detail, ctx.Extra)
	}
	fmt.Printf("  %s%-8s%s %s%s%s %s%s%s\n", Cyan, strings.ToUpper(ctx.Cloud), Reset, Green, "authenticated as", Reset, White, detail, Reset)
}

// -----------------------------------------------
//   TABLE HELPERS
// -----------------------------------------------

func printTableHeader(columns []string, widths []int) {
	if Silent {
		return
	}
	// Header
	fmt.Print("  ")
	for i, col := range columns {
		fmt.Printf("%s%s%-*s%s  ", Bold, White, widths[i], col, Reset)
	}
	fmt.Println()
	// Separator
	fmt.Print("  ")
	for _, w := range widths {
		fmt.Printf("%s%s%s  ", Gray, strings.Repeat("-", w), Reset)
	}
	fmt.Println()
}

func printTableRow(values []string, widths []int, colors []string) {
	if Silent {
		return
	}
	fmt.Print("  ")
	for i, val := range values {
		color := ""
		if i < len(colors) {
			color = colors[i]
		}
		display := val
		if len(display) > widths[i] {
			display = display[:widths[i]-3] + "..."
		}
		fmt.Printf("%s%-*s%s  ", color, widths[i], display, Reset)
	}
	fmt.Println()
}
