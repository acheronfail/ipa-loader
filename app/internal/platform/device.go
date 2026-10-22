package platform

// DisplayID prefers the hardware identifier when available.
func (d Device) DisplayID() string {
	if d.UDID != "" {
		return d.UDID
	}
	return d.ID
}

func (d Device) Label() string {
	name := d.Name
	if name == "" {
		name = "iPhone"
	}
	if d.Transport != "" {
		name += " @" + d.Transport
	}
	if id := d.DisplayID(); id != "" {
		name += " · " + id
	}
	return name
}
