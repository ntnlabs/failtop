// ui/widgets/barchart.go
package widgets

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
)

// BarEntry is one row in a bar chart.
type BarEntry struct {
	Label string
	Value float64 // percentage 0–100
	Count int
}

// BarChart draws a horizontal bar chart inside the box at (x,y,w,h).
// Each entry takes one row.
func BarChart(s tcell.Screen, x, y, w, h int, entries []BarEntry, barStyle, labelStyle tcell.Style) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2

	maxBars := h - 2
	for i, e := range entries {
		if i >= maxBars {
			break
		}
		row := innerY + i
		Pad(s, innerX, row, innerW, labelStyle)

		// Label: 2-char country code + space
		label := fmt.Sprintf("%-2s ", e.Label)
		Text(s, innerX, row, label, labelStyle, 4)

		// Bar proportional to value
		barMaxW := innerW - 4 - 10
		if barMaxW < 1 {
			barMaxW = 1
		}
		barLen := int(e.Value / 100 * float64(barMaxW))
		for b := 0; b < barLen; b++ {
			s.SetContent(innerX+4+b, row, '█', nil, barStyle)
		}

		// Percentage and count
		pct := fmt.Sprintf(" %3.0f%% (%d)", e.Value, e.Count)
		Text(s, innerX+4+barLen, row, pct, labelStyle, innerW-4-barLen)
	}
}
