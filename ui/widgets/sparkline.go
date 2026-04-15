// ui/widgets/sparkline.go
package widgets

import "github.com/gdamore/tcell/v2"

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// Sparkline draws a single-row sparkline graph from samples.
// samples should be the most recent N rate values (bytes/s).
// Fits the last `width` data points.
func Sparkline(s tcell.Screen, x, y int, samples []float64, width int, style tcell.Style) {
	if len(samples) == 0 || width < 1 {
		return
	}
	// Find max for normalization
	max := 0.0
	for _, v := range samples {
		if v > max {
			max = v
		}
	}

	// Take the last `width` samples
	start := 0
	if len(samples) > width {
		start = len(samples) - width
	}
	visible := samples[start:]

	for i, v := range visible {
		idx := 0
		if max > 0 {
			idx = int(v / max * float64(len(sparkChars)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		s.SetContent(x+i, y, sparkChars[idx], nil, style)
	}
}
