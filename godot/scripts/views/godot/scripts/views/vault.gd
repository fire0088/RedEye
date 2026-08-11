extends Control
## Key vault: captured / manual credentials. Secrets are masked until revealed
## (reveal_secret pulls the plaintext from the daemon, which decrypts at rest).
signal directive(text: String)

var _tree: Tree
var _menu: PopupMenu
var _rows: Array = []
var _sel: int = -1
var _c_user: LineEdit
var _c_secret: LineEdit
var _c_scope: LineEdit
var _hdr: Label

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)
	_hdr = Label.new()
	_hdr.text = "KEY VAULT  --  right-click to reveal / use"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	v.add_child(_hdr)

	# --- add credential ---
	var add := HBoxContainer.new()
	_c_user = LineEdit.new(); _c_user.placeholder_text = "username"
	_c_secret = LineEdit.new(); _c_secret.placeholder_text = "secret / password"; _c_secret.secret = true
	_c_scope = LineEdit.new(); _c_scope.placeholder_text = "scope (host / url / realm)"
	_c_secret.text_submitted.connect(func(_t): _add_credential())
	_c_scope.text_submitted.connect(func(_t): _add_credential())
	_c_user.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_c_secret.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_c_scope.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	add.add_child(_c_user); add.add_child(_c_secret); add.add_child(_c_scope)
	var addb := Button.new(); addb.text = "add credential"
	addb.pressed.connect(_add_credential)
	add.add_child(addb)
	v.add_child(add)

	_tree = Tree.new()
	_tree.columns = 6
	_tree.column_titles_visible = true
	_tree.hide_root = true
	_tree.size_flags_vertical = Control.SIZE_EXPAND_FILL
	var cols := ["KIND", "LABEL", "USERNAME", "SECRET", "SCOPE", "STATUS"]
	for i in cols.size():
		_tree.set_column_title(i, cols[i])
	_tree.set_column_expand(4, true)
	_tree.item_mouse_selected.connect(_on_click)
	v.add_child(_tree)
	_menu = PopupMenu.new()
	_menu.add_item("reveal secret", 0)
	_menu.add_item("attempt via RED", 1)
	_menu.add_separator()
	_menu.add_item("mark valid", 2)
	_menu.add_item("mark invalid", 3)
	_menu.add_item("delete", 4)
	_menu.id_pressed.connect(_on_menu)
	add_child(_menu)

func on_show() -> void:
	refresh()

func _add_credential() -> void:
	var u := _c_user.text.strip_edges()
	var sec := _c_secret.text
	if u == "" and sec == "":
		return
	await Backend.call_rpc("add_credential", {
		"kind": "credential", "username": u, "secret": sec,
		"scope": _c_scope.text.strip_edges(), "source": "manual"})
	_c_user.clear(); _c_secret.clear(); _c_scope.clear()
	refresh()

func on_event(msg: Dictionary) -> void:
	if msg.get("type", "") == "VaultUpsert":
		refresh()

func refresh() -> void:
	var res = await Backend.call_rpc("list_vault")
	_rows = res if res is Array else []
	_tree.clear()
	var root := _tree.create_item()
	for c in _rows:
		var it := _tree.create_item(root)
		it.set_text(0, str(c.get("kind", "")))
		it.set_text(1, str(c.get("label", "")))
		it.set_text(2, str(c.get("username", "")))
		it.set_text(3, "........")   # masked until revealed
		it.set_text(4, str(c.get("scope", "")))
		it.set_text(5, str(c.get("status", "")))
		it.set_metadata(0, int(c.get("id", -1)))
	if _hdr:
		_hdr.text = "KEY VAULT (%d)  --  right-click to reveal / use" % _rows.size()
	if _rows.is_empty():
		var e := _tree.create_item(root)
		e.set_text(2, "no credentials yet -- add one above")
		e.set_custom_color(2, Palette.DIMMER)
		e.set_selectable(2, false)

func _on_click(_p: Vector2, button: int) -> void:
	var it := _tree.get_selected()
	if it == null:
		return
	_sel = int(it.get_metadata(0))
	if button == MOUSE_BUTTON_RIGHT:
		_menu.position = Vector2i(get_viewport().get_mouse_position())
		_menu.popup()

func _on_menu(id: int) -> void:
	if _sel < 0:
		return
	match id:
		0:
			var secret = await Backend.call_rpc("reveal_secret", {"id": _sel})
			var it := _tree.get_selected()
			if it and secret != null:
				it.set_text(3, str(secret))
				it.set_custom_color(3, Palette.WARN)
		1:
			directive.emit("Attempt authentication against the target for vault credential #%d and report the result." % _sel)
		2:
			await Backend.call_rpc("set_cred_status", {"id": _sel, "status": "valid"}); refresh()
		3:
			await Backend.call_rpc("set_cred_status", {"id": _sel, "status": "invalid"}); refresh()
		4:
			await Backend.call_rpc("delete_credential", {"id": _sel}); refresh()
