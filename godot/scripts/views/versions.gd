extends Control
## Vulnerable version search: every software + version detected across all tool
## sources (nmap, httpx, ...), aggregated with the hosts/ports where it was seen,
## which tools reported it, and any findings on those hosts (so likely-vulnerable
## builds surface at the top). Filterable; double-click a row to ask RED.
signal directive(text: String)

var _tree: Tree
var _query: LineEdit
var _hdr: Label
var _rows: Array = []

func _ready() -> void:
	var v := VBoxContainer.new()
	v.set_anchors_preset(Control.PRESET_FULL_RECT)
	add_child(v)

	var bar := HBoxContainer.new()
	_hdr = Label.new()
	_hdr.text = "VULNERABLE VERSIONS"
	_hdr.add_theme_color_override("font_color", Palette.AMBER)
	_hdr.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	bar.add_child(_hdr)
	_query = LineEdit.new()
	_query.placeholder_text = "search product / version / host / source / CVE"
	_query.custom_minimum_size = Vector2(280, 0)
	_query.text_changed.connect(func(_t): refresh())
	bar.add_child(_query)
	var rb := Button.new()
	rb.text = "refresh"
	rb.pressed.connect(refresh)
	bar.add_child(rb)
	v.add_child(bar)

	_tree = Tree.new()
	_tree.columns = 5
	_tree.set_column_titles_visible(true)
	_tree.set_column_title(0, "PRODUCT")
	_tree.set_column_title(1, "VERSION")
	_tree.set_column_title(2, "HOSTS")
	_tree.set_column_title(3, "SOURCES")
	_tree.set_column_title(4, "FINDINGS")
	_tree.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_tree.item_activated.connect(_on_activate)
	v.add_child(_tree)

func on_show() -> void:
	refresh()

func on_event(msg: Dictionary) -> void:
	var t := str(msg.get("type", ""))
	if t in ["HostUpsert", "FindingUpsert", "CorrelationUpdated"]:
		refresh()

func refresh() -> void:
	var res = await Backend.call_rpc("components", {"query": _query.text.strip_edges()})
	_rows = res if res is Array else []
	_tree.clear()
	var root := _tree.create_item()
	var vulns := 0
	for i in _rows.size():
		var c = _rows[i]
		var it := _tree.create_item(root)
		it.set_text(0, str(c.get("product", "")))
		it.set_text(1, str(c.get("version", "")) if str(c.get("version", "")) != "" else "-")
		it.set_text(2, str(c.get("host_count", 0)))
		it.set_text(3, ", ".join(c.get("sources", [])))
		var finds = c.get("findings", [])
		it.set_text(4, ", ".join(finds) if finds is Array and finds.size() > 0 else "-")
		it.set_metadata(0, i)
		if c.get("vuln", false):
			vulns += 1
			for col in 5:
				it.set_custom_color(col, Palette.severity("HIGH"))
		it.set_tooltip_text(0, "seen on: " + ", ".join(c.get("hosts", [])))
	_hdr.text = "VULNERABLE VERSIONS (%d builds, %d flagged)" % [_rows.size(), vulns]
	if _rows.is_empty():
		var e := _tree.create_item(root)
		e.set_text(0, "no software detected yet -- fingerprint services (httpx) or run a version scan")
		e.set_custom_color(0, Palette.DIMMER)
		e.set_selectable(0, false)

func _on_activate() -> void:
	var it := _tree.get_selected()
	if it == null:
		return
	var i := int(it.get_metadata(0))
	if i < 0 or i >= _rows.size():
		return
	var c = _rows[i]
	directive.emit("Check %s %s (detected on %s via %s) for known CVEs and whether it's exploitable in this environment." % [
		str(c.get("product", "")), str(c.get("version", "")),
		", ".join(c.get("hosts", [])), ", ".join(c.get("sources", []))])
