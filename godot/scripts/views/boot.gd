extends Control
## Boot / login view. First sign in (any username + the server's access key from
## config.cfg [server]password), then pick an AWS profile, region and Bedrock
## model. Everyone who signs in shares one RED session.
const Eye = preload("res://scripts/eye.gd")

var _user: LineEdit
var _key: LineEdit
var _status: Label
var _profile: OptionButton
var _region: LineEdit
var _model: OptionButton
var _list_btn: Button
var _connect_btn: Button
var _authed := false

func _ready() -> void:
	var center := CenterContainer.new()
	center.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(center)
	var box := VBoxContainer.new()
	box.custom_minimum_size = Vector2(540, 0)
	box.add_theme_constant_override("separation", 8)
	center.add_child(box)

	var eye := Eye.new()
	eye.custom_minimum_size = Vector2(200, 200)
	eye.size_flags_horizontal = Control.SIZE_SHRINK_CENTER
	box.add_child(eye)

	var title := Label.new()
	title.text = "REDEYE // RED red-team console"
	title.add_theme_color_override("font_color", Palette.RED)
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(title)

	# --- sign in ---
	var _endpoint := LineEdit.new()
	_endpoint.placeholder_text = "127.0.0.1:8787"
	_endpoint.text = "%s:%d" % [Backend.host, Backend.port]
	_endpoint.text_submitted.connect(func(t): _apply_endpoint(t))
	var epbtn := Button.new()
	epbtn.text = "connect"
	epbtn.pressed.connect(func(): _apply_endpoint(_endpoint.text))
	var eprow := HBoxContainer.new()
	_endpoint.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	eprow.add_child(_endpoint)
	eprow.add_child(epbtn)
	box.add_child(_row("BACKEND", eprow))
	_user = LineEdit.new()
	_user.text = "operator"
	box.add_child(_row("CALLSIGN", _user))
	_key = LineEdit.new()
	_key.secret = true
	_key.placeholder_text = "access key (config.cfg [server]password)"
	_key.text_submitted.connect(func(_t): _sign_in())
	box.add_child(_row("ACCESS KEY", _key))
	var signin := Button.new()
	signin.text = "SIGN IN"
	signin.pressed.connect(_sign_in)
	box.add_child(signin)

	_status = Label.new()
	_status.text = "  offline -- start the backend (python serve.py)"
	_status.add_theme_color_override("font_color", Palette.AMBER)
	box.add_child(_status)

	box.add_child(HSeparator.new())

	# --- session (disabled until authed) ---
	_profile = OptionButton.new()
	box.add_child(_row("PROFILE", _profile))
	_region = LineEdit.new()
	_region.text = "us-east-1"
	box.add_child(_row("REGION", _region))
	_list_btn = Button.new()
	_list_btn.text = "LIST MODELS"
	_list_btn.pressed.connect(_on_list_models)
	box.add_child(_list_btn)
	_model = OptionButton.new()
	box.add_child(_row("MODEL", _model))
	_connect_btn = Button.new()
	_connect_btn.text = "ESTABLISH LINK"
	_connect_btn.pressed.connect(_on_connect)
	box.add_child(_connect_btn)

	_gate(false)

	Backend.link_changed.connect(_on_link)
	Backend.authed.connect(_on_authed)
	Backend.auth_failed.connect(_on_auth_failed)
	Backend.need_login.connect(_on_need_login)
	if Backend.is_up():
		_status.text = "  linked to backend -- sign in"
		_status.add_theme_color_override("font_color", Palette.CYAN)

func _row(label: String, node: Control) -> HBoxContainer:
	var h := HBoxContainer.new()
	var l := Label.new()
	l.text = label
	l.custom_minimum_size = Vector2(110, 0)
	l.add_theme_color_override("font_color", Palette.DIM)
	h.add_child(l)
	node.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	h.add_child(node)
	return h

func _gate(on: bool) -> void:
	_authed = on
	_profile.disabled = not on
	_region.editable = on
	_list_btn.disabled = not on
	_model.disabled = not on
	_connect_btn.disabled = not on

func _apply_endpoint(text: String) -> void:
	var h := "127.0.0.1"
	var p := 8787
	text = text.strip_edges()
	if text != "":
		var parts := text.rsplit(":", false, 1)
		h = parts[0]
		if parts.size() > 1 and parts[1].is_valid_int():
			p = int(parts[1])
	Backend.set_endpoint(h, p)
	_set_status("connecting to %s:%d ..." % [h, p], Palette.CYAN)

func _sign_in() -> void:
	if not Backend.is_up():
		_set_status("backend offline -- is serve.py running?", Palette.WARN)
		return
	Backend.login(_user.text, _key.text)
	_set_status("authenticating...", Palette.CYAN)

func _set_status(text: String, col: Color) -> void:
	_status.text = "  " + text
	_status.add_theme_color_override("font_color", col)

# -- backend signals ---------------------------------------------------------
func _on_link(up: bool) -> void:
	if up:
		_set_status("linked to backend -- sign in", Palette.CYAN)
	else:
		_gate(false)
		_set_status("backend link lost -- retrying...", Palette.WARN)

func _on_need_login() -> void:
	_set_status("enter your callsign + access key", Palette.AMBER)
	_key.grab_focus()

func _on_authed(info: Dictionary) -> void:
	_gate(true)
	var users: Array = info.get("users", [])
	_set_status("signed in as %s  --  %d online" % [info.get("user", "?"), users.size()], Palette.GREEN)
	_load_profiles()

func _on_auth_failed(err: String) -> void:
	_gate(false)
	_set_status("sign-in failed: %s" % err, Palette.WARN)

func _load_profiles() -> void:
	var res = await Backend.call_rpc("available_profiles")
	_profile.clear()
	if res is Array and res.size() > 0:
		for p in res:
			_profile.add_item(str(p))
	else:
		_profile.add_item("default")

func _on_list_models() -> void:
	Backend.send_command({
		"cmd": "list_models",
		"profile": _profile.get_item_text(_profile.selected) if _profile.selected >= 0 else "default",
		"region": _region.text,
	})
	_set_status("querying available models...", Palette.CYAN)

func _on_connect() -> void:
	if _model.selected < 0:
		_set_status("pick a model first (LIST MODELS)", Palette.AMBER)
		return
	var mid: String = _model.get_item_metadata(_model.selected)
	Backend.send_command({
		"cmd": "connect",
		"profile": _profile.get_item_text(_profile.selected) if _profile.selected >= 0 else "default",
		"region": _region.text,
		"model_id": mid,
		"model_label": _model.get_item_text(_model.selected),
	})
	_set_status("establishing link...", Palette.CYAN)

func on_event(msg: Dictionary) -> void:
	match msg.get("type", ""):
		"ModelsList":
			_model.clear()
			var err = msg.get("error", "")
			if err != "":
				_set_status(str(err), Palette.WARN)
				return
			for m in msg.get("models", []):
				_model.add_item(m.get("label", m.get("id", "?")))
				_model.set_item_metadata(_model.item_count - 1, m.get("id", ""))
			_set_status("%d models available" % _model.item_count, Palette.GREEN)
		"Presence":
			if _authed:
				var users: Array = msg.get("users", [])
				_set_status("%d operator(s) online" % users.size(), Palette.GREEN)
