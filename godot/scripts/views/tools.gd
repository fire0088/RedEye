extends Control
## Tools: available integrations and their settings (URL, username, API key, ...).
## A tool type that supports it (AWS, Tenable, Wiz, CrowdStrike) can have several
## independent instances. Non-sensitive values save to config; sensitive values
## are stored in the encrypted key vault (config keeps only a vault reference),
## and can link an existing vault entry or create a new one.

var _list: VBoxContainer
var _hdr: Label
var _add_opt: OptionButton
var _vault: Array = []
var _last := 0

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)

	var bar := HBoxContainer.new()
	_hdr = Label.new()
	_hdr.text = "TOOLS & INTEGRATIONS"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	_hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	bar.add_child(_hdr)
	var addl := Label.new()
	addl.text = "add: "
	addl.add_theme_color_override("font_color", Palette.DIM)
	bar.add_child(addl)
	_add_opt = OptionButton.new()
	bar.add_child(_add_opt)
	var addb := Button.new()
	addb.text = "+ instance"
	addb.pressed.connect(_add_instance)
	bar.add_child(addb)
	var recheck := Button.new()
	recheck.text = "recheck"
	recheck.pressed.connect(_recheck)
	bar.add_child(recheck)
	v.add_child(bar)

	var note := Label.new()
	note.text = "Secrets live in the key vault (F5), never in config. Add multiple instances of a tool for separate tenants/accounts."
	note.add_theme_color_override("font_color", Palette.DIM)
	note.add_theme_font_size_override("font_size", 10)
	v.add_child(note)

	var sc := ScrollContainer.new()
	sc.size_flags_vertical = Control.SIZE_EXPAND_FILL
	sc.horizontal_scroll_mode = ScrollContainer.SCROLL_MODE_DISABLED
	_list = VBoxContainer.new()
	_list.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_list.add_theme_constant_override("separation", 6)
	sc.add_child(_list)
	v.add_child(sc)

func on_show() -> void:
	refresh()

func on_event(msg: Dictionary) -> void:
	var t := str(msg.get("type", ""))
	if t == "IntegrationUpdated" or t == "ServerStatus":
		var now := Time.get_ticks_msec()
		if now - _last > 1200:
			_last = now
			refresh()

func _recheck() -> void:
	Backend.send_command({"cmd": "recheck_tools", "install": false})

func _add_instance() -> void:
	if _add_opt.selected < 0:
		return
	var tool = _add_opt.get_item_metadata(_add_opt.selected)
	if tool == null or str(tool) == "":
		return
	await Backend.call_rpc("add_integration", {"tool": str(tool), "name": _add_opt.get_item_text(_add_opt.selected)})
	refresh()

func refresh() -> void:
	var vres = await Backend.call_rpc("list_vault")
	_vault = vres if vres is Array else []
	var res = await Backend.call_rpc("list_integrations")
	for c in _list.get_children():
		c.queue_free()
	var instances := []
	var available := []
	if res is Dictionary:
		instances = res.get("instances", [])
		available = res.get("available", [])
	# populate the add dropdown
	_add_opt.clear()
	for a in available:
		_add_opt.add_item(str(a.get("name", a.get("tool", ""))))
		_add_opt.set_item_metadata(_add_opt.item_count - 1, str(a.get("tool", "")))
	_hdr.text = "TOOLS & INTEGRATIONS (%d)" % instances.size()
	for inst in instances:
		_list.add_child(_instance_panel(inst))

func _status_color(status: String) -> Color:
	if status == "online":
		return Palette.GREEN
	if status == "mock":
		return Palette.AMBER
	if status == "error":
		return Palette.WARN
	return Palette.DIMMER

func _instance_panel(inst: Dictionary) -> Control:
	var box := VBoxContainer.new()
	box.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	box.add_theme_constant_override("separation", 3)

	var head := HBoxContainer.new()
	var title := Label.new()
	title.text = str(inst.get("name", inst.get("id", "")))
	title.add_theme_color_override("font_color", Palette.TEXT_BRIGHT)
	head.add_child(title)
	var ty := Label.new()
	ty.text = "  " + str(inst.get("type_name", inst.get("tool", ""))) + " · " + str(inst.get("category", ""))
	ty.add_theme_color_override("font_color", Palette.DIM)
	ty.add_theme_font_size_override("font_size", 10)
	ty.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	head.add_child(ty)
	var st := str(inst.get("status", "offline"))
	var status := Label.new()
	status.text = "[" + st + "]  "
	status.add_theme_color_override("font_color", _status_color(st))
	head.add_child(status)
	if bool(inst.get("multiple", false)):
		var rm := Button.new()
		rm.text = "remove"
		rm.pressed.connect(_remove_instance.bind(str(inst.get("id", ""))))
		head.add_child(rm)
	box.add_child(head)

	var iid := str(inst.get("id", ""))
	for field in inst.get("fields", []):
		if bool(field.get("sensitive", false)):
			box.add_child(_secret_row(iid, field))
		else:
			box.add_child(_text_row(iid, field))

	var pc := PanelContainer.new()
	pc.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	pc.add_child(box)
	return pc

func _text_row(iid: String, field: Dictionary) -> Control:
	var row := HBoxContainer.new()
	var lbl := Label.new()
	lbl.text = str(field.get("label", ""))
	lbl.custom_minimum_size = Vector2(150, 0)
	lbl.add_theme_color_override("font_color", Palette.DIM)
	row.add_child(lbl)
	var edit := LineEdit.new()
	edit.text = str(field.get("value", ""))
	edit.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	row.add_child(edit)
	var save := Button.new()
	save.text = "save"
	save.pressed.connect(_save_text.bind(iid, str(field.get("key", "")), edit))
	row.add_child(save)
	return row

func _secret_row(iid: String, field: Dictionary) -> Control:
	var col := VBoxContainer.new()
	col.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	var row := HBoxContainer.new()
	var lbl := Label.new()
	lbl.text = str(field.get("label", "")) + "  (secret)"
	lbl.custom_minimum_size = Vector2(150, 0)
	lbl.add_theme_color_override("font_color", Palette.CYAN)
	row.add_child(lbl)
	var opt := OptionButton.new()
	opt.add_item("link existing vault entry...")
	opt.set_item_metadata(0, "")
	for vrec in _vault:
		var vid = vrec.get("id")
		opt.add_item("%s @ %s [#%s]" % [str(vrec.get("username", "")), str(vrec.get("scope", "")), str(vid)])
		opt.set_item_metadata(opt.item_count - 1, vid)
	row.add_child(opt)
	var edit := LineEdit.new()
	edit.placeholder_text = "or enter a new secret"
	edit.secret = true
	edit.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	row.add_child(edit)
	var save := Button.new()
	save.text = "save"
	save.pressed.connect(_save_secret.bind(iid, str(field.get("key", "")), edit, opt))
	row.add_child(save)
	col.add_child(row)

	var stat := Label.new()
	if bool(field.get("linked", false)):
		stat.text = "  linked to vault entry #%s (%s)" % [str(field.get("vault_id", "")), str(field.get("vault_label", ""))]
		stat.add_theme_color_override("font_color", Palette.GREEN)
	else:
		stat.text = "  not set"
		stat.add_theme_color_override("font_color", Palette.DIMMER)
	stat.add_theme_font_size_override("font_size", 10)
	col.add_child(stat)
	return col

func _save_text(iid: String, field: String, edit: LineEdit) -> void:
	await Backend.call_rpc("set_integration_field", {"id": iid, "field": field, "value": edit.text})
	_toast("saved " + field)
	refresh()

func _save_secret(iid: String, field: String, edit: LineEdit, opt: OptionButton) -> void:
	if edit.text.strip_edges() != "":
		await Backend.call_rpc("save_integration_secret", {"id": iid, "field": field, "secret": edit.text})
		_toast("secret saved to vault")
	elif opt.selected > 0:
		var vid = opt.get_item_metadata(opt.selected)
		await Backend.call_rpc("link_integration_secret", {"id": iid, "field": field, "vault_id": vid})
		_toast("linked vault entry")
	else:
		_toast("enter a secret or pick a vault entry")
		return
	refresh()

func _remove_instance(iid: String) -> void:
	await Backend.call_rpc("remove_integration", {"id": iid})
	refresh()

func _toast(text: String) -> void:
	var l := Label.new()
	l.text = "  " + text
	l.add_theme_color_override("font_color", Palette.CYAN)
	add_child(l)
	l.position = Vector2(12, size.y - 26)
	await get_tree().create_timer(3.0).timeout
	l.queue_free()
