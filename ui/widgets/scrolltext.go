// ui/widgets/scrolltext.go
package widgets

import "github.com/gdamore/tcell/v2"

// ScrollText is a fixed-capacity log viewer with scroll support.
type ScrollText struct {
	Lines  []StyledLine
	MaxLen int
	Scroll int // lines from bottom; 0 = newest, higher = older
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

// ScrollUp scrolls toward older content.
func (st *ScrollText) ScrollUp(visibleRows int) {
	max := len(st.Lines) - visibleRows
	if max < 0 {
		max = 0
	}
	if st.Scroll < max {
		st.Scroll++
	}
}

// ScrollDown scrolls toward newer content.
func (st *ScrollText) ScrollDown() {
	if st.Scroll > 0 {
		st.Scroll--
	}
}

// ScrollToTop scrolls to the oldest content.
func (st *ScrollText) ScrollToTop(visibleRows int) {
	max := len(st.Lines) - visibleRows
	if max < 0 {
		max = 0
	}
	st.Scroll = max
}

// ScrollToBottom scrolls to the newest content.
func (st *ScrollText) ScrollToBottom() {
	st.Scroll = 0
}

// Draw renders visible lines into the inner area of the box at (x,y,w,h).
func (st *ScrollText) Draw(s tcell.Screen, x, y, w, h int) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	end := len(st.Lines) - st.Scroll
	if end < 0 {
		end = 0
	}
	start := end - innerH
	if start < 0 {
		start = 0
	}
	visible := st.Lines[start:end]

	for i, line := range visible {
		Pad(s, innerX, innerY+i, innerW, tcell.StyleDefault)
		Text(s, innerX, innerY+i, line.Text, line.Style, innerW)
	}
	for i := len(visible); i < innerH; i++ {
		Pad(s, innerX, innerY+i, innerW, tcell.StyleDefault)
	}
}
