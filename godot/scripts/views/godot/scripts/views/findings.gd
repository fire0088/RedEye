extends Control
## Findings database view. A Tree fed by the daemon's list_findings RPC, with a
## right-click context menu (retest / export PoC / file Jira / ask RED / mark
## remediated / delete). This is the reference "table view" pattern -- inventory,
## vault and log follow the same shape.

signal directive(text: String)   ## hand a directive to RED (main routes to console)
signal goto(view: String)

var _tree: Tree
var _menu: PopupMenu
var _rows: Array = []            # cached finding dicts
var _hdr: Label
var _f_title: LineEdit
var _f_hosts: LineEdit
var _f_sev: OptionButton
var _sel_id: int = -1
var _mode_btn: Button
var _correlated := false

const ACT_RETEST := 0
const ACT_POC := 1
const ACT_JIRA := 2
const ACT_ASK := 3
const ACT_REMEDIATED := 4
const ACT_DELETE := 5
const SEV_LIST := ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
const STATUS_LIST := ["open", "confirmed", "remediated", "accepted_risk", "false_positive"]
var _sev_menu: PopupMenu
var _status_menu: PopupMenu
var _e_title: LineEdit
var _e_hosts: LineEdit
var _e_cvss: LineEdit
var _e_cwe: LineEdit
var _e_desc: TextEdit
var _e_rec: TextEdit
var _e_evi: TextEdit
var _e_sev: OptionButton
var _e_status: OptionButton

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)

	var bar := HBoxContainer.new()
	_hdr = Label.new()
	_hdr.text = "FINDINGS  --  right-click a row for actions"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	_hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	bar.add_child(_hdr)
	_mode_btn = Button.new()
	_mode_btn.toggle_mode = true
	_mode_btn.text = "RAW"
	_mode_btn.tooltip_text = "Toggle the merged view (same CVE on the same host from multiple tools = one row)."
	_mode_btn.toggled.connect(func(p): _correlated = p; _mode_btn.text = "CORRELATED" if p else "RAW"; refresh())
	bar.add_child(_mode_btn)
	v.add_child(bar)

	# --- add finding ---
	var add := HBoxContainer.new()
	_f_title = LineEdit.new(); _f_title.placeholder_text = "finding title"
	_f_title.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_f_title.text_submitted.connect(func(_t): _add_finding())
	_f_hosts = LineEdit.new(); _f_hosts.placeholder_text = "affected host / url"
	_f_sev = OptionButton.new()
	for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
		_f_sev.add_item(s)
	_f_sev.select(2)
	add.add_child(_f_title); add.add_child(_f_hosts); add.add_child(_f_sev)
	var addb := Button.new(); addb.text = "add finding"
	addb.pressed.connect(_add_finding)
	add.add_child(addb)
	v.add_child(add)

	_tree = Tree.new()
	_tree.columns = 6
	_tree.column_titles_visible = true
	_tree.hide_root = true
	_tree.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_tree.set_column_title(0, "#")
	_tree.set_column_title(1, "SEV")
	_tree.set_column_title(2, "TITLE")
	_tree.set_column_title(3, "HOSTS")
	_tree.set_column_title(4, "STATUS")
	_tree.set_column_title(5, "TICKET")
	_tree.set_column_expand(2, true)
	_tree.item_mouse_selected.connect(_on_row_clicked)
	v.add_child(_tree)

	# --- edit selected finding ---
	var ed := VBoxContainer.new()
	var edh := Label.new(); edh.text = "EDIT SELECTED FINDING"
	edh.add_theme_color_override("font_color", Palette.AMBER)
	ed.add_child(edh)
	var r1 := HBoxContainer.new()
	_e_title = LineEdit.new(); _e_title.placeholder_text = "title"; _e_title.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_e_hosts = LineEdit.new(); _e_hosts.placeholder_text = "hosts"; _e_hosts.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_e_sev = OptionButton.new()
	for s in SEV_LIST: _e_sev.add_item(s)
	_e_status = OptionButton.new()
	for s in STATUS_LIST: _e_status.add_item(s)
	r1.add_child(_e_title); r1.add_child(_e_hosts); r1.add_child(_e_sev); r1.add_child(_e_status)
	ed.add_child(r1)
	var r2 := HBoxContainer.new()
	_e_cvss = LineEdit.new(); _e_cvss.placeholder_text = "CVSS (e.g. 9.8)"
	_e_cwe = LineEdit.new(); _e_cwe.placeholder_text = "CWE (e.g. CWE-79)"
	r2.add_child(_e_cvss); r2.add_child(_e_cwe)
	var saveb := Button.new(); saveb.text = "save changes"; saveb.pressed.connect(_save_edit)
	r2.add_child(saveb)
	ed.add_child(r2)
	_e_desc = _mk_area("description"); ed.add_child(_e_desc)
	_e_rec = _mk_area("recommendation"); ed.add_child(_e_rec)
	_e_evi = _mk_area("evidence (raw output / notes)"); ed.add_child(_e_evi)
	v.add_child(ed)

	_menu = PopupMenu.new()
	_menu.add_item("retest via RED", ACT_RETEST)
	_menu.add_item("export Python PoC", ACT_POC)
	_menu.add_item("file Jira ticket", ACT_JIRA)
	_menu.add_item("ask RED about this", ACT_ASK)
	_sev_menu = PopupMenu.new(); _sev_menu.name = "sevmenu"
	for i in SEV_LIST.size():
		_sev_menu.add_item(SEV_LIST[i], i)
	_sev_menu.id_pressed.connect(_set_severity)
	_menu.add_child(_sev_menu)
	_menu.add_submenu_item("set severity", "sevmenu")
	_status_menu = PopupMenu.new(); _status_menu.name = "statusmenu"
	for i in STATUS_LIST.size():
		_status_menu.add_item(STATUS_LIST[i], i)
	_status_menu.id_pressed.connect(_set_status)
	_menu.add_child(_status_menu)
	_menu.add_submenu_item("set status", "statusmenu")
	_menu.add_separator()
	_menu.add_item("mark remediated", ACT_REMEDIATED)
	_menu.add_item("delete", ACT_DELETE)
	_menu.id_pressed.connect(_on_menu)
	add_child(_menu)

func _mk_area(placeholder: String) -> TextEdit:
	var t := TextEdit.new()
	t.placeholder_text = placeholder
	t.custom_minimum_size = Vector2(0, 46)
	t.wrap_mode = TextEdit.LINE_WRAPPING_BOUNDARY
	return t

func _set_severity(id: int) -> void:
	if _sel_id < 0 or _correlated:
		return
	await Backend.call_rpc("update_finding", {"id": _sel_id, "severity": SEV_LIST[id]})
	refresh()

func _set_status(id: int) -> void:
	if _sel_id < 0 or _correlated:
		return
	await Backend.call_rpc("update_finding", {"id": _sel_id, "status": STATUS_LIST[id]})
	refresh()

func _populate_edit(f: Dictionary) -> void:
	_e_title.text = str(f.get("title", ""))
	_e_hosts.text = str(f.get("hosts", ""))
	_e_cvss.text = str(f.get("cvss", ""))
	_e_cwe.text = str(f.get("cwe", ""))
	_e_desc.text = str(f.get("description", ""))
	_e_rec.text = str(f.get("recommendation", ""))
	_e_evi.text = str(f.get("evidence", ""))
	var si := SEV_LIST.find(str(f.get("severity", "")).to_upper())
	if si >= 0: _e_sev.select(si)
	var ti := STATUS_LIST.find(str(f.get("status", "")))
	if ti >= 0: _e_status.select(ti)

func _save_edit() -> void:
	if _sel_id < 0 or _correlated:
		return
	await Backend.call_rpc("update_finding", {
		"id": _sel_id, "title": _e_title.text.strip_edges(),
		"hosts": _e_hosts.text.strip_edges(),
		"severity": _e_sev.get_item_text(_e_sev.selected),
		"status": _e_status.get_item_text(_e_status.selected),
		"cvss": _e_cvss.text.strip_edges(), "cwe": _e_cwe.text.strip_edges(),
		"description": _e_desc.text, "recommendation": _e_rec.text,
		"evidence": _e_evi.text})
	refresh()

func on_show() -> void:
	refresh()

func on_event(msg: Dictionary) -> void:
	# a scan may have written new findings -- refresh when one lands
	var t = msg.get("type", "")
	if t == "FindingUpsert" or t == "CorrelationUpdated":
		refresh()

func _add_finding() -> void:
	var title := _f_title.text.strip_edges()
	if title == "":
		return
	await Backend.call_rpc("add_finding", {
		"title": title, "hosts": _f_hosts.text.strip_edges(),
		"severity": _f_sev.get_item_text(_f_sev.selected), "source": "manual"})
	_f_title.clear(); _f_hosts.clear()
	refresh()

func refresh() -> void:
	if _correlated:
		await _refresh_correlated()
		return
	var res = await Backend.call_rpc("list_findings")
	_rows = res if res is Array else []
	_tree.columns = 6
	for pair in [[0, "#"], [1, "SEV"], [2, "TITLE"], [3, "HOSTS"], [4, "STATUS"], [5, "TICKET"]]:
		_tree.set_column_title(pair[0], pair[1])
	_tree.clear()
	var root := _tree.create_item()
	for f in _rows:
		var it := _tree.create_item(root)
		it.set_text(0, str(f.get("id", "")))
		it.set_text(1, str(f.get("severity", "")))
		it.set_custom_color(1, Palette.severity(str(f.get("severity", ""))))
		it.set_text(2, str(f.get("title", "")))
		it.set_text(3, str(f.get("hosts", "")))
		it.set_text(4, str(f.get("status", "")))
		var ticket := str(f.get("ticket", ""))
		it.set_text(5, "*" if ticket != "" else "")
		it.set_metadata(0, int(f.get("id", -1)))
	_hdr.text = "FINDINGS (%d)  --  right-click a row for actions" % _rows.size()
	if _rows.is_empty():
		var e := _tree.create_item(root)
		e.set_text(2, "no findings yet -- add one above or run a scan")
		e.set_custom_color(2, Palette.DIMMER)
		e.set_selectable(2, false)

func _refresh_correlated() -> void:
	var res = await Backend.call_rpc("correlated_findings")
	_rows = res if res is Array else []
	_tree.columns = 5
	for pair in [[0, "SEV"], [1, "TITLE"], [2, "HOSTS"], [3, "SOURCES"], [4, "#"]]:
		_tree.set_column_title(pair[0], pair[1])
	_tree.set_column_expand(1, true)
	_tree.clear()
	var root := _tree.create_item()
	for i in _rows.size():
		var f = _rows[i]
		var it := _tree.create_item(root)
		it.set_text(0, str(f.get("severity", "")))
		it.set_custom_color(0, Palette.severity(str(f.get("severity", ""))))
		it.set_text(1, str(f.get("title", "")))
		it.set_text(2, str(f.get("hosts", "")))
		var srcs: Array = f.get("sources", [])
		it.set_text(3, ", ".join(srcs))
		if srcs.size() > 1:
			it.set_custom_color(3, Palette.CYAN)
		it.set_text(4, str(f.get("member_count", 1)))
		it.set_metadata(0, i)

func _on_row_clicked(_pos: Vector2, button: int) -> void:
	var it := _tree.get_selected()
	if it == null:
		return
	_sel_id = int(it.get_metadata(0))
	if not _correlated and _sel_id >= 0:
		for f in _rows:
			if int(f.get("id", -1)) == _sel_id:
				_populate_edit(f)
				break
	if button == MOUSE_BUTTON_RIGHT:
		if _correlated:
			# merged rows have no single finding id -- offer an ask directive only
			var f = _rows[_sel_id] if _sel_id >= 0 and _sel_id < _rows.size() else {}
			if f:
				directive.emit("Explain '%s' on %s and how to remediate it (seen by %s)." % [
					f.get("title", ""), f.get("hosts", ""), ", ".join(f.get("sources", []))])
			return
		_menu.position = Vector2i(get_viewport().get_mouse_position())
		_menu.popup()

func _find(fid: int) -> Dictionary:
	for f in _rows:
		if int(f.get("id", -1)) == fid:
			return f
	return {}

func _on_menu(id: int) -> void:
	if _sel_id < 0:
		return
	var f := _find(_sel_id)
	match id:
		ACT_RETEST:
			directive.emit("Retest this finding and confirm whether it still reproduces: %s (hosts: %s)"
				% [f.get("title", ""), f.get("hosts", "")])
		ACT_ASK:
			directive.emit("Explain finding #%d '%s' and how to exploit and remediate it."
				% [_sel_id, f.get("title", "")])
		ACT_POC:
			var path = await Backend.call_rpc("export_python_poc", {"id": _sel_id})
			_toast("PoC written: %s" % path if path else "PoC export failed")
		ACT_JIRA:
			var r = await Backend.call_rpc_full("jira_ticket", {"id": _sel_id})
			if r.get("ok", false):
				var res = r.get("result", {})
				_toast("Jira %s: %s" % [res.get("mode", "?"), res.get("key", res.get("path", ""))])
				refresh()
			else:
				_toast("Jira failed: %s" % r.get("error", ""))
		ACT_REMEDIATED:
			await Backend.call_rpc("update_finding", {"id": _sel_id, "status": "remediated"})
			refresh()
		ACT_DELETE:
			await Backend.call_rpc("delete_finding", {"id": _sel_id})
			refresh()

func _toast(text: String) -> void:
	# lightweight inline toast; a shared ToastStack can replace this later
	var l := Label.new()
	l.text = "  " + text
	l.add_theme_color_override("font_color", Palette.CYAN)
	add_child(l)
	l.position = Vector2(12, size.y - 30)
	await get_tree().create_timer(2.5).timeout
	l.queue_free()
