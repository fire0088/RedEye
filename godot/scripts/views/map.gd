extends Control
## Attack surface -- a sci-fi threat display of the attack graph.
##
## Concentric "radar" rings by node type (credentials inner -> assets mid ->
## findings outer), glowing edges, and light pulses that travel along the real
## cred -> asset -> finding attack chains from the `attack_graph` RPC. Custom-
## drawn 2D with a rotating radar sweep and hover highlighting. Refreshes as the
## correlated view changes.
signal directive(text: String)

var _graph: Dictionary = {}
var _nodes: Array = []
var _edges: Array = []
var _pulses: Array = []
var _id_index: Dictionary = {}
var _t := 0.0
var _hover := -1
var _dirty := false
var _last_fetch := -10.0
var _font
var _shot
var _shot_hosts: Dictionary = {}

const ShotPreview = preload("res://scripts/shot_preview.gd")

const R_CRED := 0.30
const R_ASSET := 0.60
const R_FIND := 0.92

func _ready() -> void:
	_font = ThemeDB.fallback_font
	mouse_filter = Control.MOUSE_FILTER_STOP
	resized.connect(_layout)
	set_process(true)
	_shot = ShotPreview.new()
	add_child(_shot)

func on_show() -> void:
	_fetch()

func on_event(msg: Dictionary) -> void:
	var t := str(msg.get("type", ""))
	if t in ["CorrelationUpdated", "HostUpsert", "FindingUpsert", "VaultUpsert", "ScreenshotCaptured"]:
		_dirty = true

func _process(delta: float) -> void:
	if not visible:
		return
	_t += delta
	if _dirty and (_t - _last_fetch) > 1.2:
		_fetch()
	queue_redraw()

func _fetch() -> void:
	_last_fetch = _t
	_dirty = false
	var g = await Backend.call_rpc("attack_graph")
	if g is Dictionary:
		_graph = g
		_rebuild()
	var ls = await Backend.call_rpc("list_screenshots")
	_shot_hosts = {}
	if ls is Array:
		for s in ls:
			var a := str(s.get("asset", "")).strip_edges().to_lower()
			if a != "":
				_shot_hosts[a] = true

func _rebuild() -> void:
	_nodes = []
	_edges = []
	_id_index = {}
	for n in _graph.get("nodes", []):
		_id_index[str(n.get("id"))] = _nodes.size()
		_nodes.append({
			"id": str(n.get("id")), "type": str(n.get("type")),
			"label": str(n.get("label", "")), "kind": str(n.get("kind", "")),
			"severity": str(n.get("severity", "")), "status": str(n.get("status", "")),
			"in_scope": int(n.get("in_scope", 1)), "pos": Vector2.ZERO, "angle": 0.0,
			"nbr": [],
		})
	for e in _graph.get("edges", []):
		var a = _id_index.get(str(e.get("source")), -1)
		var b = _id_index.get(str(e.get("target")), -1)
		if a >= 0 and b >= 0:
			var sev := ""
			if _nodes[b]["type"] == "finding":
				sev = _nodes[b]["severity"]
			_edges.append({"a": a, "b": b, "kind": str(e.get("kind", "")), "severity": sev})
			_nodes[a]["nbr"].append(b)
			_nodes[b]["nbr"].append(a)
	_layout()

func _layout() -> void:
	if _nodes.is_empty():
		return
	var center := size * 0.5
	var R: float = min(size.x, size.y) * 0.5 - 54.0
	if R < 40:
		R = 40.0
	var assets := []
	var finds := []
	var creds := []
	for i in _nodes.size():
		match _nodes[i]["type"]:
			"asset": assets.append(i)
			"finding": finds.append(i)
			"cred": creds.append(i)

	var na = max(1, assets.size())
	for k in assets.size():
		var ang: float = -PI / 2 + TAU * k / na
		_nodes[assets[k]]["angle"] = ang
		_nodes[assets[k]]["pos"] = center + Vector2(cos(ang), sin(ang)) * (R * R_ASSET)

	var asset_finds := {}
	for e in _edges:
		if e["kind"] == "has":
			if not asset_finds.has(e["a"]):
				asset_finds[e["a"]] = []
			asset_finds[e["a"]].append(e["b"])
	var placed := {}
	for aidx in asset_finds.keys():
		var group: Array = asset_finds[aidx]
		var base: float = _nodes[aidx]["angle"]
		var span: float = min(0.5, 0.16 * group.size())
		for j in group.size():
			var fidx = group[j]
			if placed.has(fidx):
				continue
			var frac := 0.0
			if group.size() > 1:
				frac = float(j) / float(group.size() - 1) - 0.5
			var ang2: float = base + frac * span
			_nodes[fidx]["angle"] = ang2
			_nodes[fidx]["pos"] = center + Vector2(cos(ang2), sin(ang2)) * (R * R_FIND)
			placed[fidx] = true
	var leftover := []
	for i in finds:
		if not placed.has(i):
			leftover.append(i)
	for k in leftover.size():
		var ang3: float = TAU * k / max(1, leftover.size())
		_nodes[leftover[k]]["pos"] = center + Vector2(cos(ang3), sin(ang3)) * (R * R_FIND)

	var cred_assets := {}
	for e in _edges:
		if e["kind"] == "opens":
			if not cred_assets.has(e["a"]):
				cred_assets[e["a"]] = []
			cred_assets[e["a"]].append(e["b"])
	for k in creds.size():
		var cidx = creds[k]
		var ang4: float
		if cred_assets.has(cidx) and cred_assets[cidx].size() > 0:
			var sx := 0.0
			var sy := 0.0
			for aidx2 in cred_assets[cidx]:
				sx += cos(_nodes[aidx2]["angle"])
				sy += sin(_nodes[aidx2]["angle"])
			ang4 = atan2(sy, sx)
		else:
			ang4 = PI / 2 + TAU * k / max(1, creds.size())
		_nodes[cidx]["pos"] = center + Vector2(cos(ang4), sin(ang4)) * (R * R_CRED)

	_pulses = []
	var cred_by := {}
	var asset_by := {}
	var find_by := {}
	for i in _nodes.size():
		match _nodes[i]["type"]:
			"cred": cred_by[_nodes[i]["label"]] = i
			"asset": asset_by[_nodes[i]["label"]] = i
			"finding": find_by[_nodes[i]["label"]] = i
	for ch in _graph.get("chains", []):
		var ci = cred_by.get(str(ch.get("cred", "")), -1)
		var ai = asset_by.get(str(ch.get("asset", "")), -1)
		var fi = find_by.get(str(ch.get("finding", "")), -1)
		var pts := PackedVector2Array()
		if ci >= 0: pts.append(_nodes[ci]["pos"])
		if ai >= 0: pts.append(_nodes[ai]["pos"])
		if fi >= 0: pts.append(_nodes[fi]["pos"])
		if pts.size() >= 2:
			_pulses.append({"pts": pts, "off": randf()})

func _draw() -> void:
	draw_rect(Rect2(Vector2.ZERO, size), Palette.BG)
	var center := size * 0.5
	var R: float = min(size.x, size.y) * 0.5 - 54.0
	if R < 40:
		R = 40.0

	for rr in [R_CRED, R_ASSET, R_FIND, 1.0]:
		draw_arc(center, R * rr, 0, TAU, 96, Color(1, 0.18, 0.18, 0.10), 1.0, true)
	for k in 12:
		var a: float = TAU * k / 12
		draw_line(center, center + Vector2(cos(a), sin(a)) * R, Color(1, 0.2, 0.2, 0.045), 1.0)

	var sweep: float = _t * 0.6
	for i in 18:
		var a2: float = sweep - i * 0.05
		var alpha: float = (1.0 - i / 18.0) * 0.10
		draw_line(center, center + Vector2(cos(a2), sin(a2)) * R, Color(0.35, 0.9, 1.0, alpha), 2.0)

	if _nodes.is_empty():
		_draw_text(center + Vector2(-160, 0),
			"NO ATTACK SURFACE YET -- run scans, add findings and credentials", Palette.DIM, 14)
		_hud()
		return

	for e in _edges:
		var lit := _hover < 0 or _hover == e["a"] or _hover == e["b"]
		var col: Color
		if e["kind"] == "opens":
			col = Palette.AMBER
		elif e["severity"] != "":
			col = Palette.severity(e["severity"])
		else:
			col = Palette.CYAN
		col.a = 1.0 if lit else 0.12
		_glow_line(_nodes[e["a"]]["pos"], _nodes[e["b"]]["pos"], col, 2.0 if lit else 1.0)

	for p in _pulses:
		var tt: float = fmod(_t * 0.35 + p["off"], 1.0)
		var pos := _along(p["pts"], tt)
		draw_circle(pos, 7.0, Color(1, 0.85, 0.7, 0.16))
		draw_circle(pos, 3.5, Color(1, 0.95, 0.85, 0.95))

	for i in _nodes.size():
		_draw_node(i, _hover < 0 or _connected(i))

	for i in _nodes.size():
		var n = _nodes[i]
		if n["type"] == "asset" or i == _hover or _connected_to_hover(i):
			_draw_text(n["pos"] + Vector2(10, -10), n["label"],
				Palette.TEXT if i == _hover else Palette.DIM, 11)

	_hud()

func _draw_node(i: int, lit: bool) -> void:
	var n = _nodes[i]
	var pos: Vector2 = n["pos"]
	var a: float = 1.0 if lit else 0.18
	match n["type"]:
		"asset":
			var col: Color = Palette.kind(n["kind"])
			var aa := a
			if int(n.get("in_scope", 1)) == 0:
				aa = a * 0.5
			col = Color(col.r, col.g, col.b, aa)
			_hex(pos, 11.0, col, i == _hover)
			if Palette.host_in(str(n["label"]), _shot_hosts):
				var mp := pos + Vector2(10, -10)
				draw_rect(Rect2(mp - Vector2(5, 3), Vector2(10, 6)),
					Color(0.35, 0.78, 1.0, a))
				draw_rect(Rect2(mp - Vector2(2, 1.5), Vector2(4, 3)),
					Color(0.03, 0.03, 0.06, a))
		"finding":
			var col2: Color = Palette.severity(n["severity"])
			col2 = Color(col2.r, col2.g, col2.b, a)
			var pulse := 1.0
			if n["severity"] == "CRITICAL":
				pulse = 1.0 + 0.25 * sin(_t * 5.0)
			_diamond(pos, 8.0 * pulse, col2, i == _hover)
		"cred":
			var base: Color = Palette.GREEN if n["status"] == "valid" else Palette.AMBER
			var col3 := Color(base.r, base.g, base.b, a)
			draw_circle(pos, 8.0, Color(base.r, base.g, base.b, 0.18 * a))
			draw_arc(pos, 6.0, 0, TAU, 20, col3, 2.0, true)
			draw_line(pos + Vector2(0, 2), pos + Vector2(0, 7), col3, 2.0)

func _hex(c: Vector2, r: float, col: Color, big: bool) -> void:
	var pts := PackedVector2Array()
	for k in 6:
		var a: float = PI / 6 + k * PI / 3
		pts.append(c + Vector2(cos(a), sin(a)) * r)
	draw_colored_polygon(pts, Color(col.r, col.g, col.b, col.a * 0.22))
	pts.append(pts[0])
	draw_polyline(pts, col, 2.0 if big else 1.5, true)

func _diamond(c: Vector2, r: float, col: Color, big: bool) -> void:
	var pts := PackedVector2Array([c + Vector2(0, -r), c + Vector2(r, 0),
		c + Vector2(0, r), c + Vector2(-r, 0)])
	draw_colored_polygon(pts, Color(col.r, col.g, col.b, col.a * 0.3))
	pts.append(pts[0])
	draw_polyline(pts, col, 2.0 if big else 1.5, true)

func _glow_line(a: Vector2, b: Vector2, col: Color, w: float) -> void:
	draw_line(a, b, Color(col.r, col.g, col.b, col.a * 0.10), w * 4.0)
	draw_line(a, b, Color(col.r, col.g, col.b, col.a * 0.20), w * 2.0)
	draw_line(a, b, col, w)

func _hud() -> void:
	var c = _graph.get("counts", {})
	_draw_text(Vector2(16, 22), "ATTACK SURFACE", Palette.RED, 16)
	_draw_text(Vector2(16, 42), "%s assets  %s findings  %s creds  %s chains" % [
		str(c.get("assets", 0)), str(c.get("findings", 0)),
		str(c.get("creds", 0)), str(c.get("chains", 0))], Palette.DIM, 11)
	var lx := size.x - 150
	_legend(Vector2(lx, 20), Palette.kind("host"), "asset")
	_legend(Vector2(lx, 38), Palette.severity("CRITICAL"), "finding")
	_legend(Vector2(lx, 56), Palette.GREEN, "credential")
	_legend(Vector2(lx, 74), Palette.AMBER, "opens / chain")
	_legend(Vector2(lx, 92), Palette.CYAN, "has screenshot")
	var chains: Array = _graph.get("chains", [])
	if chains.size() > 0:
		var yy := size.y - 12 - min(3, chains.size()) * 15
		_draw_text(Vector2(16, yy - 4), "ATTACK CHAINS", Palette.WARN, 11)
		for j in min(3, chains.size()):
			_draw_text(Vector2(16, yy + 14 + j * 15), "-> " + str(chains[j].get("text", "")), Palette.TEXT, 11)

func _legend(pos: Vector2, col: Color, label: String) -> void:
	draw_circle(pos, 5.0, col)
	_draw_text(pos + Vector2(12, 4), label, Palette.DIM, 11)

func _draw_text(pos: Vector2, text: String, col: Color, sz: int) -> void:
	if _font:
		draw_string(_font, pos, text, HORIZONTAL_ALIGNMENT_LEFT, -1, sz, col)

func _along(pts: PackedVector2Array, t: float) -> Vector2:
	if pts.size() < 2:
		return pts[0] if pts.size() == 1 else Vector2.ZERO
	var total := 0.0
	for i in range(pts.size() - 1):
		total += pts[i].distance_to(pts[i + 1])
	var target := total * clamp(t, 0.0, 1.0)
	var acc := 0.0
	for i in range(pts.size() - 1):
		var seg := pts[i].distance_to(pts[i + 1])
		if acc + seg >= target:
			var f := 0.0
			if seg > 0:
				f = (target - acc) / seg
			return pts[i].lerp(pts[i + 1], f)
		acc += seg
	return pts[pts.size() - 1]

func _connected(i: int) -> bool:
	return i == _hover or _connected_to_hover(i)

func _connected_to_hover(i: int) -> bool:
	if _hover < 0:
		return false
	return _nodes[_hover]["nbr"].has(i)

func _gui_input(e: InputEvent) -> void:
	if e is InputEventMouseMotion:
		_hover = _pick(e.position)
		if _hover >= 0 and _nodes[_hover]["type"] == "asset":
			_shot.show_for(str(_nodes[_hover]["label"]), get_global_mouse_position())
		else:
			_shot.hide_preview()
	elif e is InputEventMouseButton and e.button_index == MOUSE_BUTTON_LEFT and e.pressed:
		var idx := _pick(e.position)
		if idx >= 0:
			var n = _nodes[idx]
			if n["type"] == "asset":
				directive.emit("Tell me everything we know about %s and how it could be attacked." % n["label"])
			elif n["type"] == "finding":
				directive.emit("Explain the finding '%s' and how to exploit and remediate it." % n["label"])

func _pick(p: Vector2) -> int:
	var best := -1
	var bd := 20.0
	for i in _nodes.size():
		var d: float = p.distance_to(_nodes[i]["pos"])
		if d < bd:
			bd = d
			best = i
	return best
