extends Control
## Console: talk to RED. Streaming chat, live tool-call trace, MCP server status,
## and scanner-tool health. The eye now lives behind the whole UI (see main.gd).
## This is the core interactive loop; every other view feeds directives back here.
signal suggestion(action: Dictionary)   ## top recommended next step (main dispatches)

var _sugg_btn: Button
var _sugg_action: Dictionary = {}
var _sugg_last := 0
var _chat: RichTextLabel
var _input: LineEdit
var _servers: VBoxContainer
var _server_rows: Dictionary = {}   # key -> Label
var _tools: VBoxContainer
var _tool_rows: Dictionary = {}     # key -> Label
var _appr_box: VBoxContainer
var _appr_seen: Array = []          # tool names seen via ServerTools
var _appr_patterns: Array = []
var _appr_armed: Array = []
var _scope_box: VBoxContainer
var _scope_add: LineEdit
var _scope: Array = []
var _roster_lbl: Label
var _streaming := false

func _ready() -> void:
	var h := HBoxContainer.new()
	h.set_anchors_preset(Control.PRESET_FULL_RECT)
	h.add_theme_constant_override("separation", 8)
	add_child(h)

	# left: chat + input
	var left := VBoxContainer.new()
	left.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	left.size_flags_vertical = Control.SIZE_EXPAND_FILL
	h.add_child(left)

	_sugg_btn = Button.new()
	_sugg_btn.flat = true
	_sugg_btn.alignment = HORIZONTAL_ALIGNMENT_LEFT
	_sugg_btn.add_theme_color_override("font_color", Palette.CYAN)
	_sugg_btn.visible = false
	_sugg_btn.pressed.connect(_emit_suggestion)
	left.add_child(_sugg_btn)

	_chat = RichTextLabel.new()
	_chat.bbcode_enabled = true
	_chat.scroll_following = true
	_chat.selection_enabled = true
	_chat.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_chat.add_theme_color_override("default_color", Palette.TEXT)
	left.add_child(_chat)
	_chat.append_text("[color=#5ac8ff]// link up . type a directive or 'scan localhost'. F2 -> map.[/color]\n\n")

	_input = LineEdit.new()
	_input.placeholder_text = "enter command"
	_input.text_submitted.connect(_on_submit)
	left.add_child(_input)

	# right: MCP servers + scanner tools + roster
	var right := VBoxContainer.new()
	right.custom_minimum_size = Vector2(320, 0)
	h.add_child(right)

	# --- engagement scope (guardrail) ---
	var shdr := Label.new()
	shdr.text = "SCOPE  (authorised targets)"
	shdr.add_theme_color_override("font_color", Palette.AMBER)
	right.add_child(shdr)
	_scope_box = VBoxContainer.new()
	right.add_child(_scope_box)
	var addrow := HBoxContainer.new()
	_scope_add = LineEdit.new()
	_scope_add.placeholder_text = "add CIDR / IP / host"
	_scope_add.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_scope_add.text_submitted.connect(func(t): _add_scope(t))
	addrow.add_child(_scope_add)
	var addbtn := Button.new()
	addbtn.text = "+"
	addbtn.pressed.connect(func(): _add_scope(_scope_add.text))
	addrow.add_child(addbtn)
	right.add_child(addrow)
	right.add_child(HSeparator.new())

	var hdr := Label.new()
	hdr.text = "MCP TOOL FABRIC"
	hdr.add_theme_color_override("font_color", Palette.AMBER)
	right.add_child(hdr)
	_servers = VBoxContainer.new()
	right.add_child(_servers)

	right.add_child(HSeparator.new())
	var thead := HBoxContainer.new()
	var thdr := Label.new()
	thdr.text = "SCANNER TOOLS"
	thdr.add_theme_color_override("font_color", Palette.AMBER)
	thdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	thead.add_child(thdr)
	var recheck := Button.new()
	recheck.text = "recheck"
	recheck.tooltip_text = "Re-check the scanner binaries and try to install any that are missing."
	recheck.pressed.connect(func(): Backend.send_command({"cmd": "recheck_tools", "install": true}))
	thead.add_child(recheck)
	right.add_child(thead)
	_tools = VBoxContainer.new()
	right.add_child(_tools)

	right.add_child(HSeparator.new())
	var ahdr := Label.new()
	ahdr.text = "DANGEROUS TOOLS (arm to run)"
	ahdr.add_theme_color_override("font_color", Palette.WARN)
	right.add_child(ahdr)
	_appr_box = VBoxContainer.new()
	right.add_child(_appr_box)

	right.add_child(HSeparator.new())
	_roster_lbl = Label.new()
	_roster_lbl.text = "operators: --"
	_roster_lbl.add_theme_color_override("font_color", Palette.CYAN)
	_roster_lbl.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	right.add_child(_roster_lbl)

func on_show() -> void:
	_input.grab_focus()
	# pull current scanner-tool health (in case we missed the stream)
	var reps = await Backend.call_rpc("tool_status")
	if reps is Array:
		for rep in reps:
			_set_tool(rep)
	_refresh_scope()
	var ap = await Backend.call_rpc("list_approvals")
	if ap is Dictionary:
		_appr_patterns = ap.get("patterns", [])
		_appr_armed = ap.get("armed", [])
		_render_approvals()
	_refresh_suggestion()

func _emit_suggestion() -> void:
	if not _sugg_action.is_empty():
		suggestion.emit(_sugg_action)

func _refresh_suggestion() -> void:
	var recs = await Backend.call_rpc("recommendations")
	if recs is Array and recs.size() > 0:
		var r = recs[0]
		_sugg_action = r.get("action", {})
		_sugg_btn.text = "  ▸ suggested: %s" % str(r.get("title", ""))
		_sugg_btn.visible = true
	else:
		_sugg_btn.visible = false

func _on_submit(text: String) -> void:
	text = text.strip_edges()
	if text == "":
		return
	# no local echo -- the daemon broadcasts a ChatEcho to everyone (incl. us),
	# so the shared session stays consistent across all connected operators.
	Backend.send_command({"cmd": "user_message", "text": text})
	_input.clear()

# -- inbound events ----------------------------------------------------------
func on_event(msg: Dictionary) -> void:
	match msg.get("type", ""):
		"ChatEcho":
			_chat.append_text("\n[color=#5ac8ff]%s[/color]\n  %s\n" % [
				msg.get("user", "operator"), msg.get("text", "")])
		"Presence":
			var u := str(msg.get("user", ""))
			var joined: bool = msg.get("event", "") == "join"
			_chat.append_text("[color=#8a8a96]  -- %s %s --[/color]\n" % [
				u, "joined" if joined else "left"])
			_set_roster(msg.get("users", []))
		"hello":
			_set_roster(msg.get("users", []))
			for rep in msg.get("tools", []):
				_set_tool(rep)
			_scope = msg.get("scope", [])
			_render_scope()
		"ScopeUpdated":
			_scope = msg.get("entries", [])
			_render_scope()
		"BatchStart":
			_chat.append_text("\n[color=#ffb000]== batch %s x%d %s ==[/color]\n" % [
				msg.get("tool", ""), msg.get("total", 0),
				("[" + str(msg.get("label", "")) + "]") if msg.get("label", "") != "" else ""])
		"BatchProgress":
			var mk := "[color=#46e682]ok[/color]" if msg.get("ok", false) else "[color=#ff5a3c]x[/color]"
			_chat.append_text("  %s (%d/%d) %s  %s\n" % [mk, msg.get("index", 0),
				msg.get("total", 0), msg.get("target", ""), str(msg.get("summary", "")).strip_edges()])
		"BatchEnd":
			_chat.append_text("[color=#ffb000]== batch done: %d ok, %d failed ==[/color]\n" % [
				msg.get("ok", 0), msg.get("fail", 0)])
			if str(msg.get("note", "")) != "":
				_chat.append_text("[color=#8a8a96]  %s[/color]\n" % msg.get("note"))
		"ToolStatus":
			_set_tool(msg)
		"AssistantStart":
			_streaming = true
			_chat.append_text("\n[color=#ff1e1e]RED[/color]\n  ")
		"AssistantDelta":
			_chat.append_text(msg.get("text", ""))
		"AssistantEnd":
			_streaming = false
			_chat.append_text("\n")
		"ToolStart":
			_chat.append_text("\n[color=#8a8a96]  -> %s.%s %s[/color]\n" % [
				msg.get("server", ""), msg.get("name", ""),
				_fmt_args(msg.get("args", {}))])
		"ToolEnd":
			var mark := "[color=#ff5a3c]  x[/color]" if msg.get("is_error", false) else "[color=#46e682]  ok[/color]"
			var body: String = str(msg.get("result", ""))
			if body.length() > 240:
				body = body.substr(0, 240) + " ..."
			_chat.append_text("%s %s\n" % [mark, body])
		"ServerStatus":
			_set_server(msg)
		"ServerTools":
			var key: String = msg.get("key", "")
			if _server_rows.has(key):
				_server_rows[key].text += "  (%d tools)" % msg.get("tools", []).size()
			for tn in msg.get("tools", []):
				if not _appr_seen.has(tn):
					_appr_seen.append(tn)
			_render_approvals()
		"ApprovalUpdated":
			_appr_patterns = msg.get("patterns", _appr_patterns)
			_appr_armed = msg.get("armed", _appr_armed)
			_render_approvals()
		"Connected":
			_chat.append_text("[color=#46e682]  LINK ESTABLISHED // %s[/color]\n" % msg.get("model_label", ""))
		"Status":
			_chat.append_text("[color=#5ac8ff]  %s[/color]\n" % msg.get("text", ""))
		"Error":
			_chat.append_text("[color=#ff5a3c]  ! %s[/color]\n" % msg.get("text", ""))
	var t := str(msg.get("type", ""))
	if t in ["HostUpsert", "FindingUpsert", "VaultUpsert", "CorrelationUpdated", "ScreenshotCaptured", "ScopeUpdated", "LabelUpdated"]:
		var now := Time.get_ticks_msec()
		if now - _sugg_last > 1500:
			_sugg_last = now
			_refresh_suggestion()

func _set_server(msg: Dictionary) -> void:
	var key: String = msg.get("key", "")
	var row: Label
	if _server_rows.has(key):
		row = _server_rows[key]
	else:
		row = Label.new()
		_servers.add_child(row)
		_server_rows[key] = row
	var status: String = msg.get("status", "")
	var col := Palette.DIM
	if status == "online":
		col = Palette.GREEN
	elif status == "connecting":
		col = Palette.AMBER
	elif status == "error":
		col = Palette.WARN
	row.text = "  %s .......... %s" % [msg.get("name", key), status.to_upper()]
	row.add_theme_color_override("font_color", col)

func _set_tool(rep: Dictionary) -> void:
	var key := str(rep.get("key", rep.get("tool", "")))
	if key == "":
		return
	var row: Label
	if _tool_rows.has(key):
		row = _tool_rows[key]
	else:
		row = Label.new()
		row.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
		_tools.add_child(row)
		_tool_rows[key] = row
	var status := str(rep.get("status", ""))
	var icon := ""
	var col := Palette.DIM
	match status:
		"ok", "installed":
			icon = "\u2714"; col = Palette.GREEN           # check
		"installing":
			icon = "\u2026"; col = Palette.CYAN            # ellipsis
		"mock":
			icon = "\u26A0"; col = Palette.AMBER           # warning (soft)
		"error":
			icon = "\u26A0"; col = Palette.WARN            # warning (failed)
		_:
			icon = "\u00B7"
	row.text = "  %s %s .......... %s" % [icon, rep.get("name", key), status.to_upper()]
	row.add_theme_color_override("font_color", col)
	var detail := str(rep.get("detail", ""))
	row.tooltip_text = detail if detail != "" else ""

func _refresh_scope() -> void:
	var e = await Backend.call_rpc("get_scope")
	_scope = e if e is Array else []
	_render_scope()

func _render_scope() -> void:
	if _scope_box == null:
		return
	for c in _scope_box.get_children():
		c.queue_free()
	if _scope.is_empty():
		var l := Label.new()
		l.text = "  (unrestricted -- add a target to enforce)"
		l.add_theme_color_override("font_color", Palette.DIMMER)
		_scope_box.add_child(l)
		return
	for entry in _scope:
		var row := HBoxContainer.new()
		var lbl := Label.new()
		lbl.text = "  " + str(entry)
		lbl.size_flags_horizontal = Control.SIZE_EXPAND_FILL
		lbl.add_theme_color_override("font_color", Palette.GREEN)
		row.add_child(lbl)
		var x := Button.new()
		x.text = "\u2715"
		x.pressed.connect(_remove_scope.bind(str(entry)))
		row.add_child(x)
		_scope_box.add_child(row)

func _add_scope(text: String) -> void:
	text = text.strip_edges()
	if text == "":
		return
	var next := _scope.duplicate()
	if not next.has(text):
		next.append(text)
	_scope_add.clear()
	var e = await Backend.call_rpc("set_scope", {"entries": next})
	_scope = e if e is Array else next
	_render_scope()

func _remove_scope(entry: String) -> void:
	var next := []
	for x in _scope:
		if str(x) != entry:
			next.append(x)
	var e = await Backend.call_rpc("set_scope", {"entries": next})
	_scope = e if e is Array else next
	_render_scope()

func _is_dangerous(tool: String) -> bool:
	var t := tool.to_lower()
	for p in _appr_patterns:
		if t.find(str(p)) != -1:
			return true
	return false

func _render_approvals() -> void:
	if _appr_box == null:
		return
	for c in _appr_box.get_children():
		c.queue_free()
	var any := false
	for tn in _appr_seen:
		if not _is_dangerous(str(tn)):
			continue
		any = true
		var cb := CheckButton.new()
		cb.text = str(tn)
		cb.button_pressed = _appr_armed.has(tn)
		cb.toggled.connect(func(on): Backend.call_rpc("arm_tool", {"tool": tn, "on": on}))
		_appr_box.add_child(cb)
	if not any:
		var l := Label.new()
		l.text = "  (none detected yet)"
		l.add_theme_color_override("font_color", Palette.DIMMER)
		_appr_box.add_child(l)

func _set_roster(users: Array) -> void:
	if _roster_lbl:
		_roster_lbl.text = "operators: " + (", ".join(users) if users.size() > 0 else "--")

func _fmt_args(args: Dictionary) -> String:
	if args.is_empty():
		return ""
	var parts := []
	for k in args:
		var v := str(args[k])
		if v.length() > 40:
			v = v.substr(0, 38) + ".."
		parts.append("%s=%s" % [k, v])
	return ", ".join(parts)
