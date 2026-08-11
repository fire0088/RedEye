extends Control
## Inventory: discovered assets. Two modes:
##   RAW        -- one row per source record (nmap, aws, crowdstrike, ...)
##   CORRELATED -- merged view: records for the same host collapse into one row
##                 (with a SOURCES column), read-time via the daemon. Weak
##                 matches surface as suggestions you can merge or dismiss.
signal directive(text: String)
signal goto(view: String)

var _tree: Tree
var _menu: PopupMenu
var _sugg_menu: PopupMenu
var _mode_btn: Button
var _sugg_btn: Button
var _filter: LineEdit
var _q: LineEdit
var _labelname: LineEdit
var _labels_opt: OptionButton
var _tool_opt: OptionButton
var _playbook: LineEdit
var _cred_opt: OptionButton
var _tool_names: Array = []
var _creds: Array = []
var _all_rows: Array = []        # unfiltered
var _rows: Array = []            # current display rows (dicts)
var _suggestions: Array = []
var _correlated := false
var _sel_idx := -1
var _shot
var _hdr: Label
var _cam_icon: ImageTexture
var _shot_hosts: Dictionary = {}

const ShotPreview = preload("res://scripts/shot_preview.gd")

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)

	var bar := HBoxContainer.new()
	_hdr = Label.new()
	_hdr.text = "INVENTORY"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	_hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	bar.add_child(_hdr)
	_cam_icon = Palette.cam_icon()
	_mode_btn = Button.new()
	_mode_btn.toggle_mode = true
	_mode_btn.text = "RAW"
	_mode_btn.tooltip_text = "Toggle the merged (correlated) view."
	_mode_btn.toggled.connect(_on_mode)
	bar.add_child(_mode_btn)
	_sugg_btn = Button.new()
	_sugg_btn.text = "suggestions"
	_sugg_btn.visible = false
	_sugg_btn.pressed.connect(_open_suggestions)
	bar.add_child(_sugg_btn)
	v.add_child(bar)

	_filter = LineEdit.new()
	_filter.placeholder_text = "filter view (substring: web01, nginx, 10.0.0.)"
	_filter.text_changed.connect(func(_t): _apply_filter())
	v.add_child(_filter)

	_tree = Tree.new()
	_tree.column_titles_visible = true
	_tree.hide_root = true
	_tree.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_tree.item_mouse_selected.connect(_on_click)
	_tree.gui_input.connect(_on_tree_hover)
	_tree.mouse_exited.connect(func(): _shot.hide_preview())
	v.add_child(_tree)

	# --- batch operations bar ---
	v.add_child(HSeparator.new())
	var b1 := HBoxContainer.new()
	var bl := Label.new(); bl.text = "BATCH:"; bl.add_theme_color_override("font_color", Palette.AMBER)
	b1.add_child(bl)
	_q = LineEdit.new()
	_q.placeholder_text = "query (svc:nginx port:443)"
	_q.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	b1.add_child(_q)
	_labelname = LineEdit.new()
	_labelname.placeholder_text = "new label name"
	b1.add_child(_labelname)
	var mklbl := Button.new()
	mklbl.text = "label web endpoints"
	mklbl.pressed.connect(_make_label)
	b1.add_child(mklbl)
	var autob := Button.new()
	autob.text = "auto-label"
	autob.tooltip_text = "Group endpoints by service+port fingerprint and create a label for each group (e.g. every nginx:443)."
	autob.pressed.connect(_auto_label)
	b1.add_child(autob)
	var likeb := Button.new()
	likeb.text = "label like selected"
	likeb.tooltip_text = "Label every endpoint that runs the same service on the same port as the selected host."
	likeb.pressed.connect(_label_like_selected)
	b1.add_child(likeb)
	v.add_child(b1)

	var b2 := HBoxContainer.new()
	_labels_opt = OptionButton.new()
	b2.add_child(_labels_opt)
	var dellbl := Button.new()
	dellbl.text = "del label"
	dellbl.tooltip_text = "Delete the selected label (removes all its members)."
	dellbl.pressed.connect(_delete_label)
	b2.add_child(dellbl)
	_tool_opt = OptionButton.new()
	b2.add_child(_tool_opt)
	_playbook = LineEdit.new()
	_playbook.placeholder_text = "+ more tools (comma) -> playbook"
	_playbook.tooltip_text = "Optional: run several tools in sequence per endpoint, e.g. 'probe, scan'."
	_playbook.custom_minimum_size = Vector2(170, 0)
	b2.add_child(_playbook)
	_cred_opt = OptionButton.new()
	b2.add_child(_cred_opt)
	var runb := Button.new()
	runb.text = "RUN BATCH"
	runb.tooltip_text = "Run the selected tool(s) against every endpoint in the label (optionally with a vault credential)."
	runb.pressed.connect(_run_batch)
	b2.add_child(runb)
	var shotb := Button.new()
	shotb.text = "screenshot web"
	shotb.tooltip_text = "Capture a gowitness screenshot of every web endpoint in scope. Hover a row afterwards to preview."
	shotb.pressed.connect(_screenshot_web)
	b2.add_child(shotb)
	v.add_child(b2)

	_shot = ShotPreview.new()
	add_child(_shot)

	_menu = PopupMenu.new()
	_menu.id_pressed.connect(_on_menu)
	add_child(_menu)
	_sugg_menu = PopupMenu.new()
	_sugg_menu.id_pressed.connect(_on_sugg_menu)
	add_child(_sugg_menu)

func on_show() -> void:
	refresh()
	_reload_labels()
	_reload_creds()
	_reload_shots()

func _reload_shots() -> void:
	var ls = await Backend.call_rpc("list_screenshots")
	_shot_hosts = {}
	if ls is Array:
		for s in ls:
			var a := str(s.get("asset", "")).strip_edges().to_lower()
			if a != "":
				_shot_hosts[a] = true
	refresh()

func on_event(msg: Dictionary) -> void:
	var t := str(msg.get("type", ""))
	if t == "HostUpsert" or t == "CorrelationUpdated" or t == "ScopeUpdated":
		refresh()
	elif t == "LabelUpdated":
		_reload_labels()
	elif t == "VaultUpsert":
		_reload_creds()
	elif t == "ScreenshotCaptured":
		_reload_shots()
	elif t == "ServerTools":
		for tn in msg.get("tools", []):
			if not _tool_names.has(tn):
				_tool_names.append(tn)
		_reload_tools()

func _reload_labels() -> void:
	var ls = await Backend.call_rpc("list_labels")
	_labels_opt.clear()
	if ls is Array:
		for l in ls:
			_labels_opt.add_item("%s (%d)" % [l.get("label", "?"), l.get("count", 0)])
			_labels_opt.set_item_metadata(_labels_opt.item_count - 1, l.get("label", ""))

func _reload_creds() -> void:
	var cs = await Backend.call_rpc("list_vault")
	_creds = cs if cs is Array else []
	_cred_opt.clear()
	_cred_opt.add_item("(no cred)")
	_cred_opt.set_item_metadata(0, null)
	for c in _creds:
		_cred_opt.add_item("%s @ %s" % [c.get("username", "?"), c.get("scope", "")])
		_cred_opt.set_item_metadata(_cred_opt.item_count - 1, c.get("id"))

func _reload_tools() -> void:
	var keep = _tool_opt.selected
	_tool_opt.clear()
	for tn in _tool_names:
		_tool_opt.add_item(str(tn))
	if keep >= 0 and keep < _tool_opt.item_count:
		_tool_opt.select(keep)

func _apply_filter() -> void:
	var q := _filter.text.strip_edges().to_lower()
	if q == "":
		_rows = _all_rows.duplicate()
	else:
		_rows = []
		for a in _all_rows:
			var blob := ("%s %s %s %s %s" % [a.get("label", ""), a.get("ip", ""),
				a.get("hostname", ""), a.get("kind", ""), a.get("source", "")]).to_lower()
			if blob.find(q) != -1:
				_rows.append(a)
	_render_rows()

func _make_label() -> void:
	var name := _labelname.text.strip_edges()
	if name == "":
		return
	var r = await Backend.call_rpc_full("label_from_query",
		{"label": name, "query": _q.text.strip_edges(), "ports": "web"})
	_labelname.clear()
	_reload_labels()

func _run_batch() -> void:
	var tools := []
	if _tool_opt.selected >= 0:
		tools.append(_tool_opt.get_item_text(_tool_opt.selected))
	for t in _playbook.text.split(","):
		var tt := t.strip_edges()
		if tt != "" and not tools.has(tt):
			tools.append(tt)
	if tools.is_empty():
		_toast("pick a tool first")
		return
	var payload := {"cmd": "batch_run", "tools": tools}
	if _labels_opt.selected >= 0:
		payload["label"] = _labels_opt.get_item_metadata(_labels_opt.selected)
	elif _q.text.strip_edges() != "":
		payload["query"] = _q.text.strip_edges()
		payload["ports"] = "web"
	else:
		_toast("pick a label or enter a query")
		return
	if _cred_opt.selected > 0:
		payload["cred_id"] = _cred_opt.get_item_metadata(_cred_opt.selected)
	Backend.send_command(payload)
	goto.emit("console")   # watch progress in the console

func _delete_label() -> void:
	if _labels_opt.selected < 0:
		return
	var lbl = _labels_opt.get_item_metadata(_labels_opt.selected)
	await Backend.call_rpc("remove_label", {"label": lbl})
	_toast("deleted label " + str(lbl))
	_reload_labels()

func _on_mode(pressed: bool) -> void:
	_correlated = pressed
	_mode_btn.text = "CORRELATED" if pressed else "RAW"
	refresh()

# -- data --------------------------------------------------------------------
func refresh() -> void:
	if _correlated:
		await _refresh_correlated()
	else:
		await _refresh_raw()

func _columns(cols: Array) -> void:
	_tree.columns = cols.size()
	for i in cols.size():
		_tree.set_column_title(i, cols[i])
	_tree.set_column_expand(0, true)

func _refresh_raw() -> void:
	var res = await Backend.call_rpc("list_assets")
	_all_rows = res if res is Array else []
	_sugg_btn.visible = false
	_apply_filter()

func _refresh_correlated() -> void:
	var res = await Backend.call_rpc("correlated_assets")
	_all_rows = res if res is Array else []
	_suggestions = await Backend.call_rpc("correlation_suggestions")
	if not (_suggestions is Array):
		_suggestions = []
	_sugg_btn.visible = _suggestions.size() > 0
	_sugg_btn.text = "suggestions (%d)" % _suggestions.size()
	_apply_filter()

func _render_rows() -> void:
	if _correlated:
		_columns(["LABEL", "IP", "KIND", "SOURCES", "#", "SCOPE"])
	else:
		_columns(["LABEL", "IP / HOST", "OS", "KIND", "OPEN", "SOURCE", "SCOPE"])
	_tree.clear()
	var root := _tree.create_item()
	for i in _rows.size():
		var a = _rows[i]
		var it := _tree.create_item(root)
		if _correlated:
			it.set_text(0, str(a.get("label", "")))
			it.set_text(1, str(a.get("ip", "")))
			it.set_text(2, str(a.get("kind", "")))
			var srcs: Array = a.get("sources", [])
			it.set_text(3, ", ".join(srcs))
			if srcs.size() > 1:
				it.set_custom_color(3, Palette.CYAN)
			it.set_text(4, str(a.get("member_count", 1)))
			var insc := int(a.get("in_scope", 1)) != 0
			it.set_text(5, "in" if insc else "out")
			it.set_custom_color(5, Palette.GREEN if insc else Palette.DIM)
		else:
			it.set_text(0, str(a.get("label", "")))
			it.set_text(1, str(a.get("ip", "")) if a.get("ip", "") != "" else str(a.get("hostname", "")))
			it.set_text(2, str(a.get("os", "")))
			it.set_text(3, str(a.get("kind", "")))
			it.set_text(4, str(a.get("open_count", "")))
			it.set_text(5, str(a.get("source", "")))
			var insc2 := int(a.get("in_scope", 1)) != 0
			it.set_text(6, "in" if insc2 else "out")
			it.set_custom_color(6, Palette.GREEN if insc2 else Palette.DIM)
		it.set_metadata(0, i)
		if _cam_icon != null and Palette.host_in(_host_of(a), _shot_hosts):
			it.set_icon(0, _cam_icon)
			it.set_icon_max_width(0, 14)
			it.set_tooltip_text(0, "screenshot available -- hover to preview")
	if _hdr:
		_hdr.text = "INVENTORY (%d)" % _rows.size()
	if _rows.is_empty():
		var empty := _tree.create_item(root)
		empty.set_text(0, "no assets yet -- run a scan or ask RED to enumerate")
		empty.set_custom_color(0, Palette.DIMMER)
		empty.set_selectable(0, false)

# -- context menu ------------------------------------------------------------
func _on_click(_p: Vector2, button: int) -> void:
	var it := _tree.get_selected()
	if it == null:
		return
	_sel_idx = int(it.get_metadata(0))
	if button == MOUSE_BUTTON_RIGHT:
		_menu.clear()
		_menu.add_item("rescan (ports) via RED", 0)
		_menu.add_item("interrogate via RED", 1)
		_menu.add_item("label endpoints like this", 4)
		_menu.add_item("toggle in-scope", 3)
		if not _correlated:
			_menu.add_item("delete", 2)
		_menu.position = Vector2i(get_viewport().get_mouse_position())
		_menu.popup()

func _screenshot_web() -> void:
	# capture a gowitness screenshot of every in-scope web endpoint
	var payload := {"cmd": "batch_run", "tools": ["screenshot"],
		"target_key": "url", "ports": "web"}
	if _labels_opt.selected >= 0:
		payload["label"] = _labels_opt.get_item_metadata(_labels_opt.selected)
	else:
		payload["query"] = _q.text.strip_edges()
	Backend.send_command(payload)
	_toast("capturing web screenshots -- hover a row to preview")

func _on_tree_hover(e: InputEvent) -> void:
	if not (e is InputEventMouseMotion):
		return
	var it := _tree.get_item_at_position(e.position)
	if it == null:
		_shot.hide_preview()
		return
	var idx := int(it.get_metadata(0))
	if idx >= 0 and idx < _rows.size():
		_shot.show_for(_host_of(_rows[idx]), get_global_mouse_position())
	else:
		_shot.hide_preview()

func _host_of(a: Dictionary) -> String:
	var ip := str(a.get("ip", ""))
	if ip != "":
		return ip
	var hn := str(a.get("hostname", ""))
	return hn if hn != "" else str(a.get("label", ""))

func _member_ids(a: Dictionary) -> Array:
	return a.get("member_ids", [a.get("id", "")])

func _on_menu(id: int) -> void:
	if _sel_idx < 0 or _sel_idx >= _rows.size():
		return
	var a = _rows[_sel_idx]
	var host := _host_of(a)
	match id:
		0: directive.emit("Run a port scan against %s and report open services." % host)
		1: directive.emit("Tell me everything interesting about %s from what we've discovered." % host)
		4:
			await _label_like(_asset_id_of(a))
		3:
			var cur := int(a.get("in_scope", 1)) != 0
			for mid in _member_ids(a):
				await Backend.call_rpc("set_asset_scope", {"id": mid, "in_scope": not cur})
			refresh()
		2:
			await Backend.call_rpc("delete_asset", {"id": a.get("id", "")})
			refresh()

func _asset_id_of(a: Dictionary) -> String:
	# for a correlated row, use a member id (raw rows carry the ports)
	if _correlated:
		var mids = _member_ids(a)
		return str(mids[0]) if mids.size() > 0 else str(a.get("id", ""))
	return str(a.get("id", ""))

func _label_like(asset_id: String) -> void:
	if asset_id == "":
		return
	var r = await Backend.call_rpc_full("label_like", {"asset_id": asset_id})
	if r.get("ok", false):
		var res = r.get("result", {})
		if int(res.get("added", 0)) > 0:
			_toast("labelled %d endpoints as %s" % [res.get("added", 0), res.get("label", "")])
		else:
			_toast("no matching service/port to label")
	_reload_labels()

func _label_like_selected() -> void:
	if _sel_idx < 0 or _sel_idx >= _rows.size():
		_toast("select a host row first")
		return
	await _label_like(_asset_id_of(_rows[_sel_idx]))

func _auto_label() -> void:
	var r = await Backend.call_rpc("auto_label", {"ports": "web", "min": 2})
	if r is Array and r.size() > 0:
		_toast("auto-labelled %d group(s)" % r.size())
	else:
		_toast("no service groups of 2+ web endpoints found")
	_reload_labels()

func _toast(text: String) -> void:
	var l := Label.new()
	l.text = "  " + text
	l.add_theme_color_override("font_color", Palette.CYAN)
	add_child(l)
	l.position = Vector2(12, size.y - 28)
	await get_tree().create_timer(2.5).timeout
	l.queue_free()

# -- suggestions -------------------------------------------------------------
func _open_suggestions() -> void:
	_sugg_menu.clear()
	for i in _suggestions.size():
		var s = _suggestions[i]
		_sugg_menu.add_item("merge:  %s  <->  %s" % [s.get("a_label", "?"), s.get("b_label", "?")], i * 2)
		_sugg_menu.add_item("dismiss: %s  <->  %s" % [s.get("a_label", "?"), s.get("b_label", "?")], i * 2 + 1)
		_sugg_menu.add_separator()
	_sugg_menu.position = Vector2i(get_viewport().get_mouse_position())
	_sugg_menu.popup()

func _on_sugg_menu(id: int) -> void:
	var i := id / 2
	if i < 0 or i >= _suggestions.size():
		return
	var s = _suggestions[i]
	if id % 2 == 0:
		await Backend.call_rpc("merge_assets", {"a": s.get("a"), "b": s.get("b")})
	else:
		await Backend.call_rpc("dismiss_suggestion", {"a": s.get("a"), "b": s.get("b")})
	refresh()
