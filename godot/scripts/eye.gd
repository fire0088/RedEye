extends Control
## The RED eye widget. Wraps a ColorRect running red_eye.gdshader.
## mode: 0 idle, 1 thinking, 2 speaking, 3 alert.
var _mat: ShaderMaterial

func _ready() -> void:
	var rect := ColorRect.new()
	rect.set_anchors_preset(Control.PRESET_FULL_RECT)
	rect.color = Color(0, 0, 0, 0)
	rect.mouse_filter = Control.MOUSE_FILTER_IGNORE
	_mat = ShaderMaterial.new()
	_mat.shader = load("res://shaders/red_eye.gdshader")
	rect.material = _mat
	add_child(rect)

func set_mode(m: int) -> void:
	if _mat:
		_mat.set_shader_parameter("mode", m)

func set_intensity(v: float) -> void:
	if _mat:
		_mat.set_shader_parameter("intensity", v)
