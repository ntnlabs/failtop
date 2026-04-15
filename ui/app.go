// ui/app.go
package ui

import (
	"fmt"
	"time"

	"failtop/sources/geo"
	"failtop/state"
	"failtop/ui/widgets"

	"github.com/gdamore/tcell/v2"
)

// Styles
var (
	styleDefault = tcell.StyleDefault
	styleHeader  = tcell.StyleDefault.Foreground(tcell.ColorAqua).Bold(true)
	styleFail    = tcell.StyleDefault.Foreground(tcell.ColorRed)
	styleOK      = tcell.StyleDefault.Foreground(tcell.ColorGreen)
	styleBan     = tcell.StyleDefault.Foreground(tcell.ColorYellow)
	styleBar     = tcell.StyleDefault.Foreground(tcell.ColorRed)
	styleAlt     = tcell.StyleDefault.Background(tcell.ColorDarkBlue)
	styleSparkRx = tcell.StyleDefault.Foreground(tcell.ColorGreen)
	styleSparkTx = tcell.StyleDefault.Foreground(tcell.ColorBlue)
	styleDim     = tcell.StyleDefault.Foreground(tcell.ColorGray)
)

// App is the main TUI application.
type App struct {
	screen       tcell.Screen
	st           *state.AppState
	geo          *geo.Geo
	interval     time.Duration
	authLog      *widgets.ScrollText
	blockedTable *widgets.Table
	quit         chan struct{}
}

// New creates an App. interval is the draw/refresh tick.
func New(st *state.AppState, g *geo.Geo, interval time.Duration) (*App, error) {
	s, err := tcell.NewScreen()
	if err != nil {
		return nil, err
	}
	if err := s.Init(); err != nil {
		return nil, err
	}
	s.SetStyle(styleDefault)
	s.EnableMouse(tcell.MouseButtonEvents)

	app := &App{
		screen:   s,
		st:       st,
		geo:      g,
		interval: interval,
		authLog: &widgets.ScrollText{
			MaxLen: state.MaxAuthEvents,
		},
		blockedTable: &widgets.Table{
			Cols: []widgets.Column{
				{Header: "IP", Width: 16},
				{Header: "CC", Width: 3},
				{Header: "City", Width: 14},
				{Header: "ASN/Org", Width: 18},
				{Header: "Src", Width: 5},
				{Header: "Age", Width: 6},
			},
		},
		quit: make(chan struct{}),
	}
	return app, nil
}

// Run starts the draw ticker and event loop. Blocks until the user quits.
func (a *App) Run() {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	// Draw immediately on start
	a.draw()

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			ev := a.screen.PollEvent()
			if ev == nil {
				return
			}
			events <- ev
		}
	}()

	for {
		select {
		case <-ticker.C:
			a.draw()
		case ev := <-events:
			switch e := ev.(type) {
			case *tcell.EventKey:
				switch {
				case e.Key() == tcell.KeyRune && e.Rune() == 'q':
					a.screen.Fini()
					close(a.quit)
					return
				case e.Key() == tcell.KeyUp:
					a.blockedTable.ScrollUp()
					a.draw()
				case e.Key() == tcell.KeyDown:
					w, h := a.screen.Size()
					g := Recalculate(w, h)
					a.blockedTable.ScrollDown(g.MainUpper.H - 4)
					a.draw()
				case e.Key() == tcell.KeyRune && e.Rune() == 'r':
					a.draw()
				}
			case *tcell.EventResize:
				a.screen.Sync()
				a.draw()
			}
		}
	}
}

// Done returns a channel that closes when the user quits.
func (a *App) Done() <-chan struct{} {
	return a.quit
}

func (a *App) draw() {
	s := a.screen
	w, h := s.Size()
	s.Clear()
	g := Recalculate(w, h)

	a.st.RLock()
	defer a.st.RUnlock()

	a.drawHeader(g)
	a.drawStats(g)
	a.drawNICGraph(g)
	a.drawTopSources(g)
	a.drawBlockedIPs(g)
	a.drawAuthLog(g)
	a.drawFooter(g)

	s.Show()
}

func (a *App) drawHeader(g Geometry) {
	nic := a.st.NIC
	header := fmt.Sprintf(" failtop  %s  ▲ %s  ▼ %s  │  pub: %s  local: %s",
		nic.Interface,
		fmtRate(nic.TxRate),
		fmtRate(nic.RxRate),
		strOr(nic.PublicIP, "-"),
		strOr(nic.LocalIP, "-"),
	)
	widgets.Pad(a.screen, 0, 0, g.Header.W, styleHeader)
	widgets.Text(a.screen, 0, 0, header, styleHeader, g.Header.W)
}

func (a *App) drawStats(g Geometry) {
	r := g.Stats
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "SECURITY", styleDefault)

	fw := a.st.Firewall
	f2b := a.st.Fail2Ban
	lines := []string{
		fmt.Sprintf(" Firewall:  %-8s", fw.Type),
		fmt.Sprintf(" Blocked:   %d", fw.Blocked),
		fmt.Sprintf(" Rules:     %d", fw.Rules),
		"",
		fmt.Sprintf(" F2B jails: %d", len(f2b.Jails)),
		fmt.Sprintf(" F2B banned:%d", f2b.TotalBanned),
		fmt.Sprintf(" SSH fails: %d", a.st.SSHFails),
		fmt.Sprintf(" Sessions:  %d", a.st.SSHSessions),
	}
	for i, line := range lines {
		if r.Y+1+i >= r.Y+r.H-1 {
			break
		}
		widgets.Pad(a.screen, r.X+1, r.Y+1+i, r.W-2, styleDefault)
		widgets.Text(a.screen, r.X+1, r.Y+1+i, line, styleDefault, r.W-2)
	}
}

func (a *App) drawNICGraph(g Geometry) {
	r := g.NICGraph
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "NETWORK", styleDefault)
	innerW := r.W - 4 // prefix "▲ " and "▼ "

	if r.H > 3 {
		widgets.Text(a.screen, r.X+1, r.Y+1, "▲ ", styleSparkRx, 2)
		widgets.Sparkline(a.screen, r.X+3, r.Y+1, a.st.NICTxHist, innerW, styleSparkRx)
		widgets.Text(a.screen, r.X+1, r.Y+2, "▼ ", styleSparkTx, 2)
		widgets.Sparkline(a.screen, r.X+3, r.Y+2, a.st.NICRxHist, innerW, styleSparkTx)
	}
}

func (a *App) drawTopSources(g Geometry) {
	r := g.TopSrc
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "TOP SOURCES", styleDefault)
	entries := make([]widgets.BarEntry, 0, len(a.st.TopSources))
	for _, src := range a.st.TopSources {
		entries = append(entries, widgets.BarEntry{
			Label: src.Country,
			Value: src.Pct,
			Count: src.Count,
		})
	}
	widgets.BarChart(a.screen, r.X, r.Y, r.W, r.H, entries, styleBar, styleDefault)
}

func (a *App) drawBlockedIPs(g Geometry) {
	r := g.MainUpper
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "BLOCKED IPs", styleDefault)

	rows := make([][]string, 0, len(a.st.BlockedIPs))
	for _, b := range a.st.BlockedIPs {
		geoResult := a.geo.Lookup(b.IP)
		rows = append(rows, []string{
			b.IP,
			strOr(geoResult.Country, b.Country),
			strOr(geoResult.City, b.City),
			strOr(shortOrg(geoResult.ASN, geoResult.Org), "-"),
			b.Source,
			fmtAge(b.SeenAt),
		})
	}
	a.blockedTable.Rows = rows
	a.blockedTable.Draw(a.screen, r.X, r.Y, r.W, r.H, styleHeader, styleDefault, styleAlt)
}

func (a *App) drawAuthLog(g Geometry) {
	r := g.MainLower
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "AUTH LOG", styleDefault)

	// Rebuild scroll text from current auth events
	a.authLog.Lines = a.authLog.Lines[:0]
	for _, ev := range a.st.AuthEvents {
		var style tcell.Style
		switch ev.Type {
		case "FAIL", "INVALID":
			style = styleFail
		case "OK":
			style = styleOK
		case "BAN":
			style = styleBan
		default:
			style = styleDefault
		}
		line := fmt.Sprintf("%s %-7s %-16s %s", ev.Time.Format("15:04:05"), ev.Type, ev.User, ev.IP)
		a.authLog.Append(line, style)
	}
	a.authLog.Draw(a.screen, r.X, r.Y, r.W, r.H)
}

func (a *App) drawFooter(g Geometry) {
	footer := " [q]quit  [r]refresh  [↑↓]scroll IPs "
	widgets.Pad(a.screen, 0, g.Footer.Y, g.Footer.W, styleDim)
	widgets.Text(a.screen, 0, g.Footer.Y, footer, styleDim, g.Footer.W)
}

// --- Helpers ---

func fmtRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1fGB/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1fMB/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1fKB/s", bps/1e3)
	default:
		return fmt.Sprintf("%.0fB/s", bps)
	}
}

func fmtAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

func strOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func shortOrg(asn, org string) string {
	if asn == "" && org == "" {
		return ""
	}
	if len(org) > 14 {
		org = org[:14]
	}
	return asn + " " + org
}
