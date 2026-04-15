// ui/widgets/draw.go
package widgets

import "github.com/gdamore/tcell/v2"

// Box draws a bordered rectangle with an optional title on the top border.
// x, y are top-left corner; w, h are width and height (including border).
func Box(s tcell.Screen, x, y, w, h int, title string, style tcell.Style) {
	if w < 2 || h < 2 {
		return
	}
	// Corners
	s.SetContent(x, y, '┌', nil, style)
	s.SetContent(x+w-1, y, '┐', nil, style)
	s.SetContent(x, y+h-1, '└', nil, style)
	s.SetContent(x+w-1, y+h-1, '┘', nil, style)
	// Top/bottom edges
	for i := 1; i < w-1; i++ {
		s.SetContent(x+i, y, '─', nil, style)
		s.SetContent(x+i, y+h-1, '─', nil, style)
	}
	// Side edges
	for j := 1; j < h-1; j++ {
		s.SetContent(x, y+j, '│', nil, style)
		s.SetContent(x+w-1, y+j, '│', nil, style)
	}
	// Title
	if title != "" {
		runes := []rune(" " + title + " ")
		for i, r := range runes {
			if x+2+i >= x+w-1 {
				break
			}
			s.SetContent(x+2+i, y, r, nil, style)
		}
	}
}

// Text draws a string at (x, y). Clips at maxWidth runes.
func Text(s tcell.Screen, x, y int, text string, style tcell.Style, maxWidth int) {
	col := 0
	for _, r := range text {
		if col >= maxWidth {
			break
		}
		s.SetContent(x+col, y, r, nil, style)
		col++
	}
}

// Pad draws spaces from x to x+width-1 at row y, effectively clearing a row.
func Pad(s tcell.Screen, x, y, width int, style tcell.Style) {
	for i := 0; i < width; i++ {
		s.SetContent(x+i, y, ' ', nil, style)
	}
}

// VLine draws a vertical line from (x,y) downward for length cells.
func VLine(s tcell.Screen, x, y, length int, style tcell.Style) {
	for i := 0; i < length; i++ {
		s.SetContent(x, y+i, '│', nil, style)
	}
}
