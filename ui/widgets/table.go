// ui/widgets/table.go
package widgets

import "github.com/gdamore/tcell/v2"

// Column defines one column in a Table.
type Column struct {
	Header string
	Width  int
}

// Table is a scrollable, fixed-column table widget.
type Table struct {
	Cols   []Column
	Rows   [][]string
	Scroll int // first visible row index
}

// ScrollUp moves the view up by one row.
func (t *Table) ScrollUp() {
	if t.Scroll > 0 {
		t.Scroll--
	}
}

// ScrollDown moves the view down by one row, bounded by row count.
func (t *Table) ScrollDown(visibleRows int) {
	if t.Scroll < len(t.Rows)-visibleRows {
		t.Scroll++
	}
}

// Draw renders the table into the box defined by x, y, w, h.
// Row 0 is the header. Inner area starts at (x+1, y+1).
func (t *Table) Draw(s tcell.Screen, x, y, w, h int, headerStyle, rowStyle, altStyle tcell.Style) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	if innerH < 1 {
		return
	}

	// Draw header row
	col := innerX
	for _, c := range t.Cols {
		Text(s, col, innerY, c.Header, headerStyle, c.Width)
		col += c.Width + 1
	}
	// Underline after header
	if innerH > 1 {
		for i := 0; i < innerW; i++ {
			s.SetContent(innerX+i, innerY+1, '─', nil, headerStyle)
		}
	}

	// Draw rows
	dataRows := innerH - 2 // header + underline
	for rowIdx := 0; rowIdx < dataRows; rowIdx++ {
		srcIdx := t.Scroll + rowIdx
		ry := innerY + 2 + rowIdx
		Pad(s, innerX, ry, innerW, rowStyle)
		if srcIdx >= len(t.Rows) {
			continue
		}
		row := t.Rows[srcIdx]
		style := rowStyle
		if rowIdx%2 == 1 {
			style = altStyle
		}
		col := innerX
		for ci, c := range t.Cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}
			Text(s, col, ry, val, style, c.Width)
			col += c.Width + 1
		}
	}
}
