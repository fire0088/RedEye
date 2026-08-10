extends Control
## Root shell. Builds the nav bar + view stack + CRT overlay, routes Backend
## signals to the active view, and handles F1-F6 switching. Views are plain
## Control subclasses (scripts/views/*.gd) instantiated here -- no per-view
## .tscn files, which keeps the hand-authored scene surface to just Main.tscn.

const Boot      = preload("res://scripts/views/boot.gd")
const Console   = preload("res://scripts/views/console.gd")
const Findings  = preload("res://scripts/views/findings.gd")
const Inventory = preload("res://scripts/views/inventory.gd")
const MapView   = preload("res://scripts/views/map.gd")
const Vault     = preload("res://scripts/views/vault.gd")
const LogView   = preload("res://scripts/views/log.gd")
const Gallery   = preload("res://scripts/views/gallery.gd")
const Versions  = preload("res://scripts/views/versions.gd")
const Eye       = preload("res://scripts/eye.gd")

var views: Dictionary = {}
var current: String = "boot"
var _nav: HBoxContainer
var _content: Control
var _link: Label
var _bg_layer: Control
var _bg_eye
var _warn: Label
var _tool_status: Dictionary = {}   # key -> status
var _crt_mat: ShaderMaterial
var _crt_levels := [0.0, 0.28, 0.6]   # off / subtle / full
var _crt_i := 1
var _advisor: PanelContainer
var _advisor_vbox: VBoxContainer
var _next_btn: Button
var _adv_last := 0

# F-key -> view
const FKEYS := {
	KEY_F1: "console", KEY_F2: "map", KEY_F3: "inventory",
	KEY_F4: "findings", KEY_F5: "vault", KEY_F6: "log", KEY_F7: "gallery",
	KEY_F8: "versions",
}
const NAV := [
	["console", "F1 CONSOLE"], ["map", "F2 MAP"], ["inventory", "F3 INVENTORY"],
	["findings", "F4 FINDINGS"], ["vault", "F5 VAULT"], ["log", "F6 LOG"],
	["gallery", "F7 GALLERY"], ["versions", "F8 VERSIONS"],
]

func _ready() -> void:
	_build_shell()
	_build_bg_eye()
	_build_views()
	_build_crt()
	_build_advisor()
	Backend.event.connect(_on_event)
	Backend.hello.connect(_on_hello)
	Backend.link_changed.connect(_on_link)
	_show("boot")

func _build_bg_eye() -> void:
	# a big, dim eye that lives BEHIND the UI (drawn right after the bg fill)
	_bg_layer = CenterContainer.new()
	_bg_layer.set_anchors_preset(Control.PRESET_FULL_RECT)
	_bg_layer.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_bg_eye = Eye.new()
	_bg_eye.custom_minimum_size = Vector2(660, 660)   # square -> circular iris
	_bg_eye.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_bg_layer.add_child(_bg_eye)
	add_child(_bg_layer)
	move_child(_bg_layer, 1)          # index 0 = bg fill, 1 = eye, 2 = UI
	_bg_eye.set_intensity(0.4)        # subtle behind text
	_bg_eye.set_mode(0)

# -- shell -------------------------------------------------------------------
func _build_shell() -> void:
	var bg := ColorRect.new()
	bg.color = Palette.BG
	bg.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(bg)

	var root := VBoxContainer.new()
	root.set_anchors_preset(Control.PRESET_FULL_RECT)
	root.add_theme_constant_override("separation", 0)
	add_child(root)

	# top bar: brand + nav + link indicator
	var top := HBoxContainer.new()
	top.custom_minimum_size = Vector2(0, 34)
	var brand := Label.new()
	brand.text = "  REDEYE"
	brand.add_theme_color_override("font_color", Palette.RED)
	top.add_child(brand)
	# tool warning badge -- lights when a scanner tool is missing/failed
	_warn = Label.new()
	_warn.text = "  \u26A0 tools"
	_warn.add_theme_color_override("font_color", Palette.WARN)
	_warn.mouse_filter = Control.MOUSE_FILTER_STOP
	_warn.tooltip_text = "One or more scanner tools are unavailable (running in mock mode). Open the console to see which."
	_warn.gui_input.connect(func(e): if e is InputEventMouseButton and e.pressed: _show("console"))
	_warn.visible = false
	top.add_child(_warn)
	var spacer := Control.new()
	spacer.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	top.add_child(spacer)
	_nav = HBoxContainer.new()
	_nav.add_theme_constant_override("separation", 14)
	top.add_child(_nav)
	for pair in NAV:
		var b := Label.new()
		b.name = pair[0]
		b.text = pair[1]
		b.mouse_filter = Control.MOUSE_FILTER_STOP
		b.add_theme_color_override("font_color", Palette.DIM)
		b.gui_input.connect(func(e): if e is InputEventMouseButton and e.pressed: _show(pair[0]))
		_nav.add_child(b)
	_next_btn = Button.new()
	_next_btn.text = "NEXT STEPS"
	_next_btn.toggle_mode = true
	_next_btn.tooltip_text = "Recommended next steps for this engagement."
	_next_btn.toggled.connect(_toggle_advisor)
	top.add_child(_next_btn)
	_link = Label.new()
	_link.text = "  LINK ??  "
	_link.add_theme_color_override("font_color", Palette.AMBER)
	top.add_child(_link)
	root.add_child(top)

	# content area
	_content = Control.new()
	_content.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_content.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	root.add_child(_content)

func _build_views() -> void:
	views = {
		"boot": Boot.new(), "console": Console.new(), "map": MapView.new(),
		"inventory": Inventory.new(), "findings": Findings.new(),
		"vault": Vault.new(), "log": LogView.new(), "gallery": Gallery.new(),
		"versions": Versions.new(),
	}
	for name in views:
		var v: Control = views[name]
		v.set_anchors_preset(Control.PRESET_FULL_RECT)
		v.visible = false
		if v.has_signal("directive"):
			v.directive.connect(_dispatch_directive)
		if v.has_signal("goto"):
			v.goto.connect(_show)
		if v.has_signal("suggestion"):
			v.suggestion.connect(_do_advisor_action)
		_content.add_child(v)

func _build_advisor() -> void:
	_advisor = PanelContainer.new()
	_advisor.anchor_left = 1.0
	_advisor.anchor_right = 1.0
	_advisor.anchor_top = 0.0
	_advisor.anchor_bottom = 1.0
	_advisor.offset_left = -344
	_advisor.offset_right = 0
	_advisor.offset_top = 34
	_advisor.offset_bottom = 0
	_advisor.visible = false
	var sc := ScrollContainer.new()
	sc.horizontal_scroll_mode = ScrollContainer.SCROLL_MODE_DISABLED
	var vb := VBoxContainer.new()
	vb.custom_minimum_size = Vector2(320, 0)
	vb.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	vb.add_theme_constant_override("separation", 8)
	_advisor_vbox = vb
	sc.add_child(vb)
	_advisor.add_child(sc)
	add_child(_advisor)

func _toggle_advisor(on: bool) -> void:
	_advisor.visible = on
	if on:
		_refresh_advisor()

func _refresh_advisor() -> void:
	var recs = await Backend.call_rpc("recommendations")
	for c in _advisor_vbox.get_children():
		c.queue_free()
	var title := Label.new()
	title.text = "  RECOMMENDED NEXT STEPS"
	title.add_theme_color_override("font_color", Palette.RED)
	_advisor_vbox.add_child(title)
	if not (recs is Array) or recs.is_empty():
		var e := Label.new()
		e.text = "  (nothing yet)"
		e.add_theme_color_override("font_color", Palette.DIMMER)
		_advisor_vbox.add_child(e)
		return
	var cats := {"inventory": "BUILD INVENTORY", "explore": "EXPLORE ENDPOINTS",
		"security": "SECURITY TESTING"}
	for cat in ["inventory", "explore", "security"]:
		var group := []
		for r in recs:
			if r.get("category", "") == cat:
				group.append(r)
		if group.is_empty():
			continue
		var h := Label.new()
		h.text = "  " + str(cats.get(cat, cat))
		h.add_theme_color_override("font_color", Palette.AMBER)
		h.add_theme_font_size_override("font_size", 11)
		_advisor_vbox.add_child(h)
		for r in group:
			_advisor_vbox.add_child(_rec_card(r))

func _rec_card(r: Dictionary) -> Control:
	var box := VBoxContainer.new()
	box.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	box.add_theme_constant_override("separation", 3)
	var t := Label.new()
	t.text = str(r.get("title", ""))
	t.add_theme_color_override("font_color", Palette.TEXT_BRIGHT)
	t.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	box.add_child(t)
	var d := Label.new()
	d.text = str(r.get("detail", ""))
	d.add_theme_color_override("font_color", Palette.DIM)
	d.add_theme_font_size_override("font_size", 10)
	d.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	box.add_child(d)
	var a: Dictionary = r.get("action", {})
	var b := Button.new()
	b.text = _action_label(a)
	b.pressed.connect(_do_advisor_action.bind(a))
	box.add_child(b)
	var pc := PanelContainer.new()
	pc.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	pc.add_child(box)
	return pc

func _action_label(a: Dictionary) -> String:
	match str(a.get("kind", "")):
		"directive": return "ask RED"
		"goto": return "open " + str(a.get("view", ""))
		_: return "run"

func _do_advisor_action(a: Dictionary) -> void:
	match str(a.get("kind", "")):
		"directive":
			_dispatch_directive(str(a.get("text", "")))
		"goto":
			_show(str(a.get("view", "console")))
		"command":
			Backend.send_command(a.get("payload", {}))
			_toast("started")
			if a.has("goto"):
				_show(str(a["goto"]))
		"rpc":
			await Backend.call_rpc(str(a.get("name", "")), a.get("args", {}))
			if a.has("toast"):
				_toast(str(a["toast"]))
			if a.has("goto"):
				_show(str(a["goto"]))
			_refresh_advisor()

func _toast(text: String) -> void:
	var l := Label.new()
	l.text = "  " + text
	l.add_theme_color_override("font_color", Palette.CYAN)
	add_child(l)
	l.position = Vector2(16, size.y - 30)
	await get_tree().create_timer(3.0).timeout
	l.queue_free()

func _dispatch_directive(text: String) -> void:
	Backend.send_command({"cmd": "user_message", "text": text})
	_show("console")

func _build_crt() -> void:
	var layer := CanvasLayer.new()
	layer.layer = 10
	add_child(layer)
	var rect := ColorRect.new()
	rect.set_anchors_preset(Control.PRESET_FULL_RECT)
	rect.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_crt_mat = ShaderMaterial.new()
	_crt_mat.shader = load("res://shaders/crt.gdshader")
	rect.material = _crt_mat
	layer.add_child(rect)

# -- view switching ----------------------------------------------------------
func _show(name: String) -> void:
	if not views.has(name):
		return
	current = name
	for n in views:
		views[n].visible = (n == name)
	# nav highlight
	for child in _nav.get_children():
		child.add_theme_color_override("font_color",
			Palette.RED if child.name == name else Palette.DIM)
	var v: Control = views[name]
	if v.has_method("on_show"):
		v.on_show()
	# the big background eye shows everywhere except the boot/power-on screen
	if _bg_layer:
		_bg_layer.visible = (name != "boot")

func _unhandled_key_input(e: InputEvent) -> void:
	if e is InputEventKey and e.pressed and not e.echo:
		if e.keycode == KEY_F9:
			_crt_i = (_crt_i + 1) % _crt_levels.size()
			if _crt_mat:
				_crt_mat.set_shader_parameter("strength", _crt_levels[_crt_i])
			return
		if FKEYS.has(e.keycode) and current != "boot":
			_show(FKEYS[e.keycode])

# -- backend routing ---------------------------------------------------------
func _on_event(msg: Dictionary) -> void:
	# route to every view that cares; boot advances to console on Connected
	for n in views:
		if views[n].has_method("on_event"):
			views[n].on_event(msg)
	var t := str(msg.get("type", ""))
	if _advisor and _advisor.visible and t in ["HostUpsert", "FindingUpsert",
			"VaultUpsert", "CorrelationUpdated", "ScreenshotCaptured",
			"ScopeUpdated", "LabelUpdated", "SnapshotUpdated"]:
		var now := Time.get_ticks_msec()
		if now - _adv_last > 1500:
			_adv_last = now
			_refresh_advisor()
	match t:
		"Connected":
			_show("console")
		"AssistantStart":
			_eye_mode(2)
		"AssistantEnd":
			_eye_mode(0)
		"Thinking":
			_eye_mode(1 if msg.get("on", false) else 0)
		"Error":
			_eye_mode(3)
		"ToolStatus":
			_tool_status[str(msg.get("key", msg.get("tool", "")))] = str(msg.get("status", ""))
			_update_warn()

func _eye_mode(m: int) -> void:
	if _bg_eye:
		_bg_eye.set_mode(m)

func _update_warn() -> void:
	var bad := 0
	for k in _tool_status:
		if _tool_status[k] in ["mock", "error"]:
			bad += 1
	if _warn:
		_warn.visible = bad > 0
		_warn.text = "  \u26A0 %d tool%s" % [bad, "" if bad == 1 else "s"]

func _on_hello(info: Dictionary) -> void:
	for rep in info.get("tools", []):
		_tool_status[str(rep.get("key", rep.get("tool", "")))] = str(rep.get("status", ""))
	_update_warn()

func _on_link(up: bool) -> void:
	_link.text = "  LINK LIVE  " if up else "  LINK DOWN  "
	_link.add_theme_color_override("font_color", Palette.GREEN if up else Palette.WARN)
