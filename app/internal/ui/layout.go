//go:build !ios

package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var placeholderIcon = fyne.NewStaticResource("app-placeholder.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><rect width="128" height="128" rx="28" ry="28" fill="#243b40"/><g fill="none" stroke="#86cdd1" stroke-width="5"><rect x="32" y="32" width="24" height="24" rx="6" ry="6"/><rect x="72" y="32" width="24" height="24" rx="6" ry="6"/><rect x="32" y="72" width="24" height="24" rx="6" ry="6"/><rect x="72" y="72" width="24" height="24" rx="6" ry="6"/></g></svg>`))

func column(gap float32, objects ...fyne.CanvasObject) *fyne.Container {
	return container.New(layout.NewCustomPaddedVBoxLayout(gap), objects...)
}

type insetLayout struct{ top, right, bottom, left float32 }

func (l insetLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(l.left+l.right, l.top+l.bottom)
	}
	return objects[0].MinSize().Add(fyne.NewSize(l.left+l.right, l.top+l.bottom))
}
func (l insetLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, object := range objects {
		object.Move(fyne.NewPos(l.left, l.top))
		object.Resize(fyne.NewSize(fyne.Max(0, size.Width-l.left-l.right), fyne.Max(0, size.Height-l.top-l.bottom)))
	}
}
func inset(padding float32, content fyne.CanvasObject) *fyne.Container {
	return container.New(insetLayout{padding, padding, padding, padding}, content)
}

type minHeightLayout struct{ height float32 }

func (l minHeightLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	s := objects[0].MinSize()
	return fyne.NewSize(s.Width, fyne.Max(s.Height, l.height))
}
func (l minHeightLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	objects[0].Move(fyne.NewPos(0, 0))
	objects[0].Resize(size)
}
func control(height float32, object fyne.CanvasObject) *fyne.Container {
	return container.New(minHeightLayout{height}, object)
}

// Entry text is top-aligned by Fyne. Match its own padding to our 36-point
// controls so placeholders, typed text and the cursor stay vertically centred.
// Scope this to login entries; labels and buttons already centre themselves.
type loginEntryTheme struct{ fyne.Theme }

func (t loginEntryTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameInnerPadding {
		return 8
	}
	return t.Theme.Size(name)
}

func loginEntry(entry *widget.Entry) fyne.CanvasObject {
	return container.NewThemeOverride(entry, loginEntryTheme{fyne.CurrentApp().Settings().Theme()})
}

// A plain container keeps the full content size in its minimum: no Card header
// or shadow layout can subtract space from the app controls as text changes.
type surfacePanel struct {
	widget.BaseWidget
	content fyne.CanvasObject
}

func surface(content fyne.CanvasObject) *surfacePanel {
	p := &surfacePanel{content: inset(12, content)}
	p.ExtendBaseWidget(p)
	return p
}
func (p *surfacePanel) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(theme.Color(theme.ColorNameInputBackground))
	background.CornerRadius = 12
	return &surfaceRenderer{panel: p, background: background}
}

type surfaceRenderer struct {
	panel      *surfacePanel
	background *canvas.Rectangle
}

func (r *surfaceRenderer) Layout(size fyne.Size) {
	r.background.Resize(size)
	r.panel.content.Resize(size)
}
func (r *surfaceRenderer) MinSize() fyne.Size { return r.panel.content.MinSize() }
func (r *surfaceRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.panel.content}
}
func (r *surfaceRenderer) Destroy() {}
func (r *surfaceRenderer) Refresh() {
	r.background.FillColor = theme.Color(theme.ColorNameInputBackground)
	r.background.Refresh()
	r.panel.content.Refresh()
}

func caption(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.SizeName = theme.SizeNameCaptionText
	label.Importance = widget.LowImportance
	return label
}

func singleLine(label *widget.Label) {
	label.Wrapping = fyne.TextWrapOff
	label.Truncation = fyne.TextTruncateEllipsis
}

type slimProgress struct{ widget.ProgressBar }

func newSlimProgress() *slimProgress {
	p := &slimProgress{}
	p.ExtendBaseWidget(p)
	p.Max = 1
	p.TextFormatter = func() string { return "" }
	return p
}
func (*slimProgress) MinSize() fyne.Size { return fyne.NewSize(80, 6) }

type Palette struct {
	fyne.Theme
}

func NewTheme() fyne.Theme { return &Palette{Theme: theme.DefaultTheme()} }
func (p *Palette) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameHeadingText:
		return 24
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameButtonRadius:
		return 8
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	}
	return p.Theme.Size(name)
}
func (p *Palette) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNamePrimary {
		return color.NRGBA{R: 8, G: 127, B: 140, A: 255}
	}
	if variant == theme.VariantLight {
		switch name {
		case theme.ColorNameBackground:
			return color.NRGBA{R: 247, G: 249, B: 250, A: 255}
		case theme.ColorNameForeground:
			return color.NRGBA{R: 29, G: 40, B: 51, A: 255}
		case theme.ColorNameInputBackground:
			return color.NRGBA{R: 237, G: 241, B: 244, A: 255}
		case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
			return color.NRGBA{R: 112, G: 124, B: 136, A: 255}
		case theme.ColorNameSuccess:
			return color.NRGBA{R: 30, G: 128, B: 72, A: 255}
		case theme.ColorNameError:
			return color.NRGBA{R: 180, G: 42, B: 42, A: 255}
		case theme.ColorNameWarning:
			return color.NRGBA{R: 160, G: 77, B: 5, A: 255}
		}
	} else {
		switch name {
		case theme.ColorNameBackground:
			return color.NRGBA{R: 23, G: 26, B: 30, A: 255}
		case theme.ColorNameForeground:
			return color.NRGBA{R: 235, G: 239, B: 242, A: 255}
		case theme.ColorNameInputBackground:
			return color.NRGBA{R: 34, G: 40, B: 47, A: 255}
		case theme.ColorNameButton:
			return color.NRGBA{R: 47, G: 55, B: 64, A: 255}
		case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
			return color.NRGBA{R: 136, G: 149, B: 161, A: 255}
		case theme.ColorNameSeparator:
			return color.NRGBA{R: 49, G: 57, B: 65, A: 255}
		case theme.ColorNameSuccess:
			return color.NRGBA{R: 112, G: 206, B: 151, A: 255}
		case theme.ColorNameError:
			return color.NRGBA{R: 243, G: 130, B: 130, A: 255}
		}
	}
	return p.Theme.Color(name, variant)
}

func (s *Screen) toggleActivity() {
	if s.activityScroll.Visible() {
		s.activityScroll.Hide()
		s.showActivity.SetText("Show details")
		s.showActivity.SetIcon(theme.MenuDropDownIcon())
	} else {
		s.activityScroll.Show()
		s.showActivity.SetText("Hide details")
		s.showActivity.SetIcon(theme.MenuDropUpIcon())
	}
	s.resizeOperation()
	s.root.Refresh()
}

func (s *Screen) collapseActivity() {
	s.activityScroll.Hide()
	s.showActivity.SetText("Show details")
	s.showActivity.SetIcon(theme.MenuDropDownIcon())
}

func appPickerLayout(icon, name, detail, choose fyne.CanvasObject) fyne.CanvasObject {
	return column(8, container.NewBorder(nil, nil, container.NewCenter(icon), nil, column(4, name, detail)),
		container.NewBorder(nil, nil, nil, control(36, choose)))
}

// Keep sign-in comfortably sized when the user widens the desktop window.
type readableWidth struct{ max float32 }

func (l readableWidth) MinSize(objects []fyne.CanvasObject) fyne.Size {
	size := objects[0].MinSize()
	return fyne.NewSize(fyne.Min(size.Width, l.max), size.Height)
}
func (l readableWidth) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	width := fyne.Min(size.Width, l.max)
	objects[0].Move(fyne.NewPos((size.Width-width)/2, 0))
	objects[0].Resize(fyne.NewSize(width, size.Height))
}
