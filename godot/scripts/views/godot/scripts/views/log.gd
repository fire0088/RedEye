extends Control
## Activity log: audit trail + exports, scan snapshots/diffing, attack graph.
var _tree: Tree
var _last_export: String = ""
var _m_client: LineEdit
var _m_tester: LineEdit
var _m_window: LineEdit
var _m_contact: LineEdit

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)
	var top := HBoxContainer.new()
	var hdr := Label.new()
	hdr.text = "ACTIVITY LOG"
	hdr.add_theme_color_override("font_color", Palette.AMBER)
	hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	top.add_child(hdr)
	var clear := Button.new()
	clear.text = "clear"
	clear.pressed.connect(func(): await Backend.call_rpc("clear_activity"); refresh())
	top.add_child(clear)
	v.add_child(top)

	# --- change tracking + graph ---
	var ch := HBoxContainer.new()
	var chl := Label.new(); chl.text = "TRACK:"; chl.add_theme_color_override("font_color", Palette.AMBER)
	ch.add_child(chl)
	var snap := Button.new(); snap.text = "take snapshot"; snap.pressed.connect(_take_snapshot); ch.add_child(snap)
	var diff := Button.new(); diff.text = "diff vs latest"; diff.pressed.connect(_diff_latest); ch.add_child(diff)
	var graph := Button.new(); graph.text = "attack graph"; graph.pressed.connect(_attack_graph); ch.add_child(graph)
	v.add_child(ch)

	# --- exports ---
	var ex := HBoxContainer.new()
	var exl := Label.new(); exl.text = "EXPORT:"; exl.add_theme_color_override("font_color", Palette.AMBER)
	ex.add_child(exl)
	_add_export(ex, "report (HTML)", "export_report_html")
	_add_export(ex, "report (PDF)", "export_report_pdf")
	_add_export(ex, "report (MD)", "export_report_md")
	_add_export(ex, "inventory CSV", "export_inventory_csv")
	_add_export(ex, "findings CSV", "export_correlated_findings_csv")
	_add_export(ex, "full bundle", "export_bundle")
	var dl := Button.new(); dl.text = "download last"
	dl.tooltip_text = "Fetch the last exported file from the backend and save it locally (user:// dir)."
	dl.pressed.connect(_download_last)
	ex.add_child(dl)
	v.add_child(ex)

	# --- report cover metadata ---
	var me := HBoxContainer.new()
	var mel := Label.new(); mel.text = "REPORT META:"; mel.add_theme_color_override("font_color", Palette.AMBER)
	me.add_child(mel)
	_m_client = LineEdit.new(); _m_client.placeholder_text = "client"
	_m_tester = LineEdit.new(); _m_tester.placeholder_text = "tester"
	_m_window = LineEdit.new(); _m_window.placeholder_text = "window (dates)"
	_m_contact = LineEdit.new(); _m_contact.placeholder_text = "contact"
	for f in [_m_client, _m_tester, _m_window, _m_contact]:
		f.size_flags_horizontal = Control.SIZE_EXPAND_FILL
		me.add_child(f)
	var savem := Button.new(); savem.text = "save"
	savem.pressed.connect(_save_meta)
	me.add_child(savem)
	v.add_child(me)

	_tree = Tree.new()
	_tree.columns = 3
	_tree.column_titles_visible = true
	_tree.hide_root = true
	_tree.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_tree.set_column_title(0, "KIND")
	_tree.set_column_title(1, "EVENT")
	_tree.set_column_title(2, "DETAIL")
	_tree.set_column_expand(1, true)
	v.add_child(_tree)

func on_show() -> void:
	refresh()
	var e = await Backend.call_rpc("get_engagement")
	if e is Dictionary:
		_m_client.text = str(e.get("client", ""))
		_m_tester.text = str(e.get("tester", ""))
		_m_window.text = str(e.get("window", ""))
		_m_contact.text = str(e.get("contact", ""))

func _save_meta() -> void:
	await Backend.call_rpc("set_engagement", {
		"client": _m_client.text.strip_edges(),
		"tester": _m_tester.text.strip_edges(),
		"window": _m_window.text.strip_edges(),
		"contact": _m_contact.text.strip_edges()})
	_toast("report metadata saved")

func _add_export(bar: HBoxContainer, label: String, rpc: String) -> void:
	var b := Button.new()
	b.text = label
	b.pressed.connect(_do_export.bind(rpc))
	bar.add_child(b)

func _do_export(rpc: String) -> void:
	var r = await Backend.call_rpc(rpc)
	var where := ""
	if r is Dictionary:
		if r.has("error"):
			_toast(str(r.get("error")))
			return
		where = str(r.get("dir", r.get("path", "")))
		if r.has("path"):
			_last_export = str(r.get("path"))
	elif r is Array and r.size() >= 1:
		where = str(r[0])
		_last_export = str(r[0])
	if where != "":
		_toast("wrote " + where)
		refresh()
	else:
		_toast("export failed")

func _download_last() -> void:
	if _last_export == "":
		_toast("run an export first")
		return
	var r = await Backend.call_rpc("fetch_export", {"path": _last_export.get_file()})
	if not (r is Dictionary) or not r.has("b64"):
		_toast("download failed")
		return
	var bytes := Marshalls.base64_to_raw(str(r.get("b64")))
	var out := "user://" + str(r.get("name", "export.bin"))
	var f := FileAccess.open(out, FileAccess.WRITE)
	if f:
		f.store_buffer(bytes); f.close()
		_toast("saved " + ProjectSettings.globalize_path(out))
	else:
		_toast("could not write file")

func _take_snapshot() -> void:
	var r = await Backend.call_rpc("take_snapshot", {"label": ""})
	if r is Dictionary:
		_toast("snapshot #%s taken" % str(r.get("id", "?")))
	refresh()

func _diff_latest() -> void:
	var snaps = await Backend.call_rpc("list_snapshots")
	if not (snaps is Array) or snaps.is_empty():
		_toast("take a snapshot first")
		return
	var sid = snaps[0].get("id")
	var d = await Backend.call_rpc("diff_snapshot", {"id": sid})
	if d is Dictionary:
		var s = d.get("summary", {})
		_toast("since #%s: +%s hosts, +%s findings, %s port changes, %s resolved" % [
			str(sid), str(s.get("new_hosts", 0)), str(s.get("new_findings", 0)),
			str(s.get("port_changes", 0)), str(s.get("resolved_findings", 0))])

func _attack_graph() -> void:
	var g = await Backend.call_rpc("attack_graph")
	if g is Dictionary:
		var c = g.get("counts", {})
		var chains: Array = g.get("chains", [])
		var head : String = chains[0].get("text", "") if chains.size() > 0 else "no cred->asset->finding chains yet"
		_toast("graph: %s assets, %s findings, %s chains  |  %s" % [
			str(c.get("assets", 0)), str(c.get("findings", 0)), str(c.get("chains", 0)), head])

func _toast(text: String) -> void:
	var l := Label.new()
	l.text = "  " + text
	l.add_theme_color_override("font_color", Palette.CYAN)
	l.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	add_child(l)
	l.position = Vector2(12, size.y - 26)
	await get_tree().create_timer(4.0).timeout
	l.queue_free()

func on_event(msg: Dictionary) -> void:
	# any DB-affecting event may add activity; cheap refresh when visible
	if visible and msg.get("type", "") in ["HostUpsert", "FindingUpsert", "VaultUpsert", "ToolStart"]:
		refresh()

func refresh() -> void:
	var res = await Backend.call_rpc("list_activity", {"limit": 500})
	_tree.clear()
	var root := _tree.create_item()
	if not (res is Array):
		return
	for a in res:
		var it := _tree.create_item(root)
		var kind := str(a.get("kind", ""))
		it.set_text(0, kind)
		it.set_custom_color(0, Palette.kind(kind))
		it.set_text(1, str(a.get("text", "")))
		it.set_text(2, str(a.get("detail", "")))
