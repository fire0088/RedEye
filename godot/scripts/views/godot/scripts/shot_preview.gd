extends Control
## A floating screenshot thumbnail shown on hover. Fetches a stored gowitness
## screenshot for a host (get_screenshot RPC), caches the decoded texture, and
## positions a small panel near the cursor. Add one as a child of any view and
## call show_for(host, global_mouse_pos) on hover / hide_preview() on exit.

var _cache: Dictionary = {}      # host -> ImageTexture (or null when none)
var _panel: PanelContainer
var _rect: TextureRect
var _cap: Label
var _cur: String = ""

func _ready() -> void:
	mouse_filter = Control.MOUSE_FILTER_IGNORE
	set_anchors_preset(Control.PRESET_FULL_RECT)
	_panel = PanelContainer.new()
	_panel.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_panel.z_index = 100
	var vb := VBoxContainer.new()
	vb.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_panel.add_child(vb)
	_rect = TextureRect.new()
	_rect.custom_minimum_size = Vector2(320, 180)
	_rect.stretch_mode = TextureRect.STRETCH_KEEP_ASPECT
	_rect.mouse_filter = Control.MOUSE_FILTER_IGNORE
	vb.add_child(_rect)
	_cap = Label.new()
	_cap.add_theme_font_size_override("font_size", 10)
	_cap.add_theme_color_override("font_color", Palette.DIM)
	vb.add_child(_cap)
	_panel.visible = false
	add_child(_panel)

func hide_preview() -> void:
	_cur = ""
	if _panel:
		_panel.visible = false

func show_for(host: String, gpos: Vector2) -> void:
	host = host.strip_edges().to_lower()
	if host == "":
		hide_preview()
		return
	if host == _cur and _panel.visible:
		_reposition(gpos)
		return
	_cur = host
	if _cache.has(host):
		_apply(_cache[host], gpos)
		return
	var r = await Backend.call_rpc("get_screenshot", {"host": host})
	var tex: Texture2D = null
	if r is Dictionary and str(r.get("image_b64", "")) != "":
		var img := Image.new()
		var err := img.load_png_from_buffer(Marshalls.base64_to_raw(str(r["image_b64"])))
		if err == OK:
			tex = ImageTexture.create_from_image(img)
	_cache[host] = tex
	if host == _cur:            # still hovering the same host after the await
		_apply(tex, gpos)

func _apply(tex: Texture2D, gpos: Vector2) -> void:
	if tex == null:
		_panel.visible = false
		return
	_rect.texture = tex
	_cap.text = _cur
	_panel.visible = true
	_reposition(gpos)

func _reposition(gpos: Vector2) -> void:
	var p := gpos + Vector2(18, 18)
	var vp := get_viewport_rect().size
	if p.x + 340 > vp.x:
		p.x = gpos.x - 340
	if p.y + 210 > vp.y:
		p.y = gpos.y - 210
	_panel.global_position = p
