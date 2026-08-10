extends Node
## Colour palette, mirrored from the old pygame theme.py so the Godot front-end
## keeps the same red-team / CRT identity.

const BG          := Color("05030a")
const BG_PANEL    := Color("0a0610")
const RED         := Color8(255, 30, 30)     # the signature RED
const RED_CORE    := Color8(255, 180, 150)
const RED_DEEP    := Color8(150, 8, 12)
const AMBER       := Color8(255, 176, 0)
const GREEN       := Color8(70, 230, 130)
const CYAN        := Color8(90, 200, 255)
const WARN        := Color8(255, 90, 60)
const TEXT        := Color8(210, 210, 215)
const TEXT_BRIGHT := Color8(240, 240, 245)
const DIM         := Color8(140, 140, 150)
const DIMMER      := Color8(90, 90, 100)
const GRID_FAINT  := Color8(30, 16, 22)

## severity + status colours (match database.severity_color / status_color)
static func severity(sev: String) -> Color:
	match sev.to_upper():
		"CRITICAL": return Color8(255, 40, 40)
		"HIGH":     return Color8(255, 110, 60)
		"MEDIUM":   return Color8(255, 176, 0)
		"LOW":      return Color8(120, 200, 255)
		_:          return Color8(140, 140, 150)   # INFO

static func kind(k: String) -> Color:
	match k:
		"command":   return Color8(90, 200, 255)
		"discovery": return Color8(70, 230, 130)
		"finding":   return Color8(255, 176, 0)
		"vault":     return Color8(255, 120, 200)
		"error":     return Color8(255, 90, 60)
		"export":    return Color8(120, 200, 255)
		_:           return Color8(140, 140, 150)

## Cached 16x12 camera icon (for "has screenshot" badges). Font-independent.
static var _cam: ImageTexture

static func cam_icon() -> ImageTexture:
	if _cam != null:
		return _cam
	var img := Image.create(16, 12, false, Image.FORMAT_RGBA8)
	img.fill(Color(0, 0, 0, 0))
	var body := Color(0.35, 0.78, 1.0)
	for x in range(5, 9):        # viewfinder bump
		img.set_pixel(x, 1, body)
	for y in range(3, 11):       # body
		for x in range(1, 15):
			img.set_pixel(x, y, body)
	for y in range(5, 9):        # lens (dark)
		for x in range(6, 10):
			img.set_pixel(x, y, Color(0.03, 0.03, 0.06))
	_cam = ImageTexture.create_from_image(img)
	return _cam

## Loose host match against a set (Dictionary keys) of screenshot hosts.
static func host_in(host: String, host_set: Dictionary) -> bool:
	host = host.strip_edges().to_lower()
	if host == "":
		return false
	for k in host_set:
		var ks := str(k)
		if ks == host or (ks != "" and (host.find(ks) != -1 or ks.find(host) != -1)):
			return true
	return false
