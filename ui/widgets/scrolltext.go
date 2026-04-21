// ui/widgets/scrolltext.go
package widgets

import "github.com/gdamore/tcell/v2"

// ScrollText is a fixed-capacity log viewer with scroll support.
// Lines are stored newest-first (index 0 = newest). Scroll=0 shows the top (newest).
type ScrollText struct {
	Lines  []StyledLine
	MaxLen int
	Scroll int // offset from top; 0 = newest, higher = older
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

// ScrollUp scrolls toward newer content (toward top).
func (st *ScrollText) ScrollUp(visibleRows int) {
	if st.Scroll > 0 {
		st.Scroll--
	}
}

// ScrollDown scrolls toward older content (toward bottom).
func (st *ScrollText) ScrollDown() {
	max := len(st.Lines) - 1
	if max < 0 {
		max = 0
	}
	if st.Scroll < max {
		st.Scroll++
	}
}

// ScrollToTop scrolls to newest content (top).
func (st *ScrollText) ScrollToTop(visibleRows int) {
	st.Scroll = 0
}

// ScrollToBottom scrolls to oldest content (bottom).
func (st *ScrollText) ScrollToBottom() {
	if len(st.Lines) > 0 {
		st.Scroll = len(st.Lines) - 1
	}
}

// Draw renders visible lines into the inner area of the box at (x,y,w,h).
func (st *ScrollText) Draw(s tcell.Screen, x, y, w, h int) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	start := st.Scroll
	end := start + innerH
	if end > len(st.Lines) {
		end = len(st.Lines)
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
