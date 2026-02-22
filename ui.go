package main

import (
	"fmt"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
//   ANSI COLOR CODES
// ─────────────────────────────────────────────

var (
	Silent  bool
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[95m"
	Cyan    = "\033[96m"
	White   = "\033[97m"
	Gray    = "\033[90m"
	BRed    = "\033[41m"
	BGreen  = "\033[42m"
	BYellow = "\033[43m"
	BBlue   = "\033[44m"
	BCyan   = "\033[46m"
)

func disableColors() {
	Reset = ""; Bold = ""; Dim = ""
	Red = ""; Green = ""; Yellow = ""; Blue = ""
	Magenta = ""; Cyan = ""; White = ""; Gray = ""
	BRed = ""; BGreen = ""; BYellow = ""
	BBlue = ""; BCyan = ""
}

// ─────────────────────────────────────────────
//   LOGGING HELPERS
// ─────────────────────────────────────────────

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

func logSection(title string) {
	if Silent {
		return
	}
	bar := strings.Repeat("─", 60)
	fmt.Printf("\n%s%s  ┌%s┐\n", Cyan, Bold, bar)
	fmt.Printf("  │  %-58s│\n", title)
	fmt.Printf("  └%s┘%s\n", bar, Reset)
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
		"ACCESS_DENIED": Gray + " ACCESS DENIED ",
		"NOT_FOUND":     Gray + " NOT FOUND ",
		"ERROR":         Yellow + " ERROR ",
		"MANUAL":        BCyan + White + " MANUAL ",
	}
	color, ok := statusColors[strings.ToUpper(status)]
	if !ok {
		color = Gray + " " + status + " "
	}
	fmt.Printf("  %s%-18s%s %s%-50s%s %s%s  %s%s%s\n",
		Cyan, label, Reset, White, bucket, Reset, color, Reset, Gray, extra, Reset)
}

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
	fmt.Printf(`%s  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │   Multi-Cloud Pentesting Framework  ·  by %sk3rn3lbr3ach3r%s  ·  v1.0.0             │
  │   AWS S3 + GCS + Azure + Alibaba  ·  Discovery + Deep Scan Pipeline             │
  └─────────────────────────────────────────────────────────────────────────────────┘%s
`, Gray, Cyan, Gray, Reset)
}
