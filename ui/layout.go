// ui/layout.go
package ui

// Rect defines a rectangular region on screen.
type Rect struct {
	X, Y, W, H int
}

// Geometry holds the computed panel bounds for the current terminal size.
type Geometry struct {
	Header    Rect
	Sidebar   Rect
	Stats     Rect // top portion of sidebar
	NICGraph  Rect // mid portion of sidebar
	TopSrc    Rect // bottom portion of sidebar
	MainUpper Rect // blocked IPs table
	MainLower Rect // auth log
	Footer    Rect

	SidebarWidth int
}

const (
	sidebarWidthMin  = 24
	sidebarWidthFrac = 5 // sidebar is 1/5 of total width
	headerHeight     = 1
	footerHeight     = 1
	statsHeight      = 11
	nicGraphHeight   = 5
)

// Recalculate computes panel bounds for a terminal of size (w, h).
func Recalculate(w, h int) Geometry {
	g := Geometry{}
	g.SidebarWidth = w / sidebarWidthFrac
	if g.SidebarWidth < sidebarWidthMin {
		g.SidebarWidth = sidebarWidthMin
	}

	mainW := w - g.SidebarWidth

	g.Header = Rect{0, 0, w, headerHeight}
	g.Footer = Rect{0, h - footerHeight, w, footerHeight}

	bodyY := headerHeight
	bodyH := h - headerHeight - footerHeight

	// Sidebar panels
	g.Stats = Rect{0, bodyY, g.SidebarWidth, statsHeight}
	g.NICGraph = Rect{0, bodyY + statsHeight, g.SidebarWidth, nicGraphHeight}
	topSrcY := bodyY + statsHeight + nicGraphHeight
	topSrcH := bodyH - statsHeight - nicGraphHeight
	g.TopSrc = Rect{0, topSrcY, g.SidebarWidth, topSrcH}
	g.Sidebar = Rect{0, bodyY, g.SidebarWidth, bodyH}

	// Main area panels
	mainUpperH := bodyH * 6 / 10
	mainLowerH := bodyH - mainUpperH
	g.MainUpper = Rect{g.SidebarWidth, bodyY, mainW, mainUpperH}
	g.MainLower = Rect{g.SidebarWidth, bodyY + mainUpperH, mainW, mainLowerH}

	return g
}
