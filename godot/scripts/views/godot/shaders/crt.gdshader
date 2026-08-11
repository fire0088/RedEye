shader_type canvas_item;
// CRT post-process, kept subtle. Applied to a full-rect ColorRect on a
// CanvasLayer above the UI. `strength` blends the whole effect back toward the
// untouched screen -- lower it (or the individual amounts) to make it fainter,
// raise it toward 1.0 for a heavier look.
uniform sampler2D screen_tex : hint_screen_texture, filter_linear_mipmap;
uniform float strength   = 0.28;   // overall visibility of the effect (0 = off)
uniform float scanline   = 0.05;
uniform float vignette   = 0.14;
uniform float aberration = 0.35;   // in pixels
uniform float flicker    = 0.008;
uniform float bar_speed  = 0.10;
uniform float bar_amount = 0.010;

void fragment() {
	vec2 uv = SCREEN_UV;
	vec2 px = 1.0 / vec2(textureSize(screen_tex, 0));
	vec3 orig = texture(screen_tex, uv).rgb;

	// chromatic aberration
	vec2 off = vec2(aberration, 0.0) * px;
	float r = texture(screen_tex, uv + off).r;
	float g = texture(screen_tex, uv).g;
	float b = texture(screen_tex, uv - off).b;
	vec3 col = vec3(r, g, b);

	// scanlines
	col *= 1.0 - scanline * (0.5 + 0.5 * sin(FRAGCOORD.y * 3.14159265));

	// faint rolling bar
	float bar = fract(uv.y - TIME * bar_speed);
	col += bar_amount * smoothstep(0.02, 0.0, abs(bar - 0.5) - 0.02);

	// vignette
	vec2 c = uv - vec2(0.5);
	float vig = 1.0 - dot(c, c) * vignette * 2.2;
	col *= clamp(vig, 0.0, 1.0);

	// flicker
	col *= 1.0 - flicker * fract(sin(TIME * 120.0) * 43758.5453);

	// blend back toward the untouched screen so the whole thing stays subtle
	COLOR = vec4(mix(orig, col, clamp(strength, 0.0, 1.0)), 1.0);
}
