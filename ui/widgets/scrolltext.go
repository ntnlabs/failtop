// ui/widgets/scrolltext.go
package widgets

import "github.com/gdamore/tcell/v2"

// ScrollText is a fixed-capacity log viewer that shows the last N lines.
type ScrollText struct {
	Lines  []StyledLine
	MaxLen int
}

// StyledLine is a line with a tcell style.
type StyledLine struct {
	Text  string
	Style tcell.Style
}

// Append adds a line, evicting the oldest if at capacity.
func (st *ScrollText) Append(text string, style tcell.Style) {
	if len(st.Lines) >= st.MaxLen {
		st.Lines = st.Lines[1:]
	}
	st.Lines = append(st.Lines, StyledLine{Text: text, Style: style})
}

// Draw renders the last visible lines into the inner area of the box at (x,y,w,h).
func (st *ScrollText) Draw(s tcell.Screen, x, y, w, h int) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	// Show the last innerH lines
	start := 0
	if len(st.Lines) > innerH {
		start = len(st.Lines) - innerH
	}
	visible := st.Lines[start:]

	for i, line := range visible {
		Pad(s, innerX, innerY+i, innerW, tcell.StyleDefault)
		Text(s, innerX, innerY+i, line.Text, line.Style, innerW)
	}
}
