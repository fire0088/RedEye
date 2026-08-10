extends Control
## Screenshot gallery: a grid of captured web screenshots, filterable by label
## and free-text, and sortable by recency, HTTP status, visual similarity, or
## URL. Click a tile to enlarge. Backed by the `gallery` RPC.
signal directive(text: String)

var _grid: GridContainer
var _sort_opt: OptionButton
var _label_opt: OptionButton
var _query: LineEdit
var _hdr: Label
var _overlay: Control
var _over_tex: TextureRect
var _over_cap: Label
var _over_shot: Dictionary = {}

const SORTS := [["recent", "recent"], ["status", "HTTP status"],
				["similarity", "similarity"], ["url", "URL"]]

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)

	var bar := HBoxContainer.new()
	_hdr = Label.new()
	_hdr.text = "SCREENSHOTS"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	_hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	bar.add_child(_hdr)
	bar.add_child(_lbl("sort:"))
	_sort_opt = OptionButton.new()
	for s in SORTS:
		_sort_opt.add_item(s[1])
	_sort_opt.item_selected.connect(func(_i): _reload())
	bar.add_child(_sort_opt)
	bar.add_child(_lbl("label:"))
	_label_opt = OptionButton.new()
	_label_opt.item_selected.connect(func(_i): _reload())
	bar.add_child(_label_opt)
	_query = LineEdit.new()
	_query.placeholder_text = "filter (url / status)"
	_query.custom_minimum_size = Vector2(200, 0)
	_query.text_changed.connect(func(_t): _reload())
	bar.add_child(_query)
	var rb := Button.new()
	rb.text = "refresh"
	rb.pressed.connect(_reload)
	bar.add_child(rb)
	v.add_child(bar)

	var sc := ScrollContainer.new()
	sc.size_flags_vertical = Control.SIZE_EXPAND_FILL
	sc.horizontal_scroll_mode = ScrollContainer.SCROLL_MODE_DISABLED
	_grid = GridContainer.new()
	_grid.columns = 4
	_grid.add_theme_constant_override("h_separation", 12)
	_grid.add_theme_constant_override("v_separation", 12)
	_grid.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	sc.add_child(_grid)
	v.add_child(sc)

	_build_overlay()

func _lbl(t: String) -> Label:
	var l := Label.new()
	l.text = "  " + t
	l.add_theme_color_override("font_color", Palette.DIM)
	return l

func _build_overlay() -> void:
	_overlay = Control.new()
	_overlay.set_anchors_preset(Control.PRESET_FULL_RECT)
	_overlay.visible = false
	_overlay.mouse_filter = Control.MOUSE_FILTER_STOP
	var dim := ColorRect.new()
	dim.color = Color(0, 0, 0, 0.82)
	dim.set_anchors_preset(Control.PRESET_FULL_RECT)
	dim.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_overlay.add_child(dim)
	var cc := CenterContainer.new()
	cc.set_anchors_preset(Control.PRESET_FULL_RECT)
	cc.mouse_filter = Control.MOUSE_FILTER_IGNORE
	var box := VBoxContainer.new()
	box.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_over_tex = TextureRect.new()
	_over_tex.custom_minimum_size = Vector2(720, 405)
	_over_tex.stretch_mode = TextureRect.STRETCH_KEEP_ASPECT
	box.add_child(_over_tex)
	_over_cap = Label.new()
	_over_cap.add_theme_color_override("font_color", Palette.CYAN)
	box.add_child(_over_cap)
	var ask := Button.new()
	ask.text = "ask RED about this endpoint"
	ask.pressed.connect(_ask_about)
	box.add_child(ask)
	cc.add_child(box)
	_overlay.add_child(cc)
	_overlay.gui_input.connect(func(e):
		if e is InputEventMouseButton and e.pressed:
			_overlay.visible = false)
	add_child(_overlay)

func on_show() -> void:
	_reload_labels()
	_reload()

func on_event(msg: Dictionary) -> void:
	if str(msg.get("type", "")) == "ScreenshotCaptured":
		_reload()

func _reload_labels() -> void:
	var cur := _label_opt.selected
	_label_opt.clear()
	_label_opt.add_item("(all labels)")
	_label_opt.set_item_metadata(0, "")
	var ls = await Backend.call_rpc("list_labels")
	if ls is Array:
		for l in ls:
			_label_opt.add_item("%s (%d)" % [l.get("label", "?"), l.get("count", 0)])
			_label_opt.set_item_metadata(_label_opt.item_count - 1, l.get("label", ""))
	if cur >= 0 and cur < _label_opt.item_count:
		_label_opt.select(cur)

func _reload() -> void:
	var sort := "recent"
	if _sort_opt.selected >= 0:
		sort = SORTS[_sort_opt.selected][0]
	var label := ""
	if _label_opt.selected > 0:
		label = str(_label_opt.get_item_metadata(_label_opt.selected))
	var g = await Backend.call_rpc("gallery", {
		"sort": sort, "label": label, "query": _query.text.strip_edges()})
	for c in _grid.get_children():
		c.queue_free()
	var n := 0
	if g is Array:
		n = g.size()
		for s in g:
			_add_tile(s)
	_hdr.text = "SCREENSHOTS (%d)" % n
	if n == 0:
		var e := Label.new()
		e.text = "  no screenshots -- run 'screenshot web' from Inventory, or ask RED to screenshot a URL"
		e.add_theme_color_override("font_color", Palette.DIMMER)
		_grid.add_child(e)

func _add_tile(s: Dictionary) -> void:
	var tex := _decode(str(s.get("image_b64", "")))
	var box := VBoxContainer.new()
	var tr := TextureRect.new()
	tr.custom_minimum_size = Vector2(240, 135)
	tr.stretch_mode = TextureRect.STRETCH_KEEP_ASPECT
	tr.texture = tex
	tr.mouse_filter = Control.MOUSE_FILTER_STOP
	tr.gui_input.connect(func(e):
		if e is InputEventMouseButton and e.pressed:
			_enlarge(s, tex))
	box.add_child(tr)
	var st := int(s.get("status", 0))
	var cap := Label.new()
	cap.text = "%s  [%d]" % [str(s.get("asset", s.get("url", ""))), st]
	cap.add_theme_font_size_override("font_size", 10)
	cap.add_theme_color_override("font_color", _status_color(st))
	box.add_child(cap)
	var labs = s.get("labels", [])
	if labs is Array and labs.size() > 0:
		var ll := Label.new()
		ll.text = "  " + ", ".join(labs)
		ll.add_theme_font_size_override("font_size", 9)
		ll.add_theme_color_override("font_color", Palette.DIM)
		box.add_child(ll)
	_grid.add_child(box)

func _decode(b64: String) -> Texture2D:
	if b64 == "":
		return null
	var img := Image.new()
	if img.load_png_from_buffer(Marshalls.base64_to_raw(b64)) == OK:
		return ImageTexture.create_from_image(img)
	return null

func _status_color(st: int) -> Color:
	if st >= 500:
		return Palette.WARN
	if st >= 400:
		return Palette.AMBER
	if st >= 300:
		return Palette.CYAN
	if st >= 200:
		return Palette.GREEN
	return Palette.DIM

func _enlarge(s: Dictionary, tex: Texture2D) -> void:
	_over_shot = s
	_over_tex.texture = tex
	var labs = s.get("labels", [])
	_over_cap.text = "%s   status %s   [%s]" % [
		str(s.get("url", "")), str(s.get("status", "")),
		", ".join(labs) if labs is Array else ""]
	_overlay.visible = true

func _ask_about() -> void:
	if _over_shot.is_empty():
		return
	directive.emit("Assess the web endpoint %s (HTTP %s) -- what should I look at?" % [
		str(_over_shot.get("url", "")), str(_over_shot.get("status", ""))])
	_overlay.visible = false
