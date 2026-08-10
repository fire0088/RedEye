shader_type canvas_item;
// The RED eye -- a procedural glowing lens. Apply to a SQUARE ColorRect (a
// non-square rect stretches the iris into an ellipse). Reacts to `mode`:
//   0 idle  1 thinking  2 speaking  3 alert
// `intensity` dims it for background use.
render_mode blend_add;

uniform vec4  red       : source_color = vec4(1.0, 0.10, 0.10, 1.0);
uniform vec4  core      : source_color = vec4(1.0, 0.75, 0.62, 1.0);
uniform int   mode      = 0;
uniform float intensity = 1.0;

float hash(vec2 p) { return fract(sin(dot(p, vec2(41.3, 289.1))) * 43758.5453); }

float noise(vec2 p) {
	vec2 i = floor(p), f = fract(p);
	float a = hash(i), b = hash(i + vec2(1, 0));
	float c = hash(i + vec2(0, 1)), d = hash(i + vec2(1, 1));
	vec2 u = f * f * (3.0 - 2.0 * f);
	return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}

void fragment() {
	vec2 p = UV - 0.5;
	float d = length(p) * 2.0;          // 0 centre .. 1 edge
	float ang = atan(p.y, p.x);

	float speed = 2.0;
	if (mode == 1) { speed = 8.0; }     // thinking
	else if (mode == 2) { speed = 4.5; } // speaking
	float pulse = 0.5 + 0.5 * sin(TIME * speed);
	if (mode == 3) { pulse = step(0.5, fract(TIME * 3.0)); } // alert strobe

	// housing ring, lens body, halo
	float rim  = smoothstep(1.0, 0.92, d) - smoothstep(0.92, 0.80, d);
	float body = smoothstep(0.90, 0.80, d);
	float halo = smoothstep(1.15, 0.0, d);

	// textured iris: radial striations + fine grain + concentric rings
	float stri  = 0.5 + 0.5 * sin(ang * 80.0 + d * 6.0);
	float grain = noise(vec2(ang * 20.0, d * 40.0));
	float rings = 0.5 + 0.5 * sin(d * 46.0 - TIME * 0.6);
	float iris  = mix(0.55, 1.0, stri * 0.5 + grain * 0.5) * mix(0.75, 1.0, rings);
	float irisMask = smoothstep(0.80, 0.28, d) - smoothstep(0.28, 0.14, d);

	// aperture / hot core
	float hot = pow(smoothstep(0.26, 0.0, d), 1.6);

	// glassy specular highlight (offset reflection) + fresnel rim light
	float spec = smoothstep(0.16, 0.0, length(p - vec2(-0.14, 0.16))) * body;
	float fres = smoothstep(0.60, 0.90, d) * (1.0 - smoothstep(0.90, 1.0, d));

	vec3 col = vec3(0.0);
	col += red.rgb * halo * 0.20;                          // ambient glow
	col += red.rgb * body * (0.35 + 0.25 * pulse);         // lens fill
	col += red.rgb * iris * irisMask * (0.70 + 0.30 * pulse); // textured iris
	col += mix(red.rgb, core.rgb, hot) * hot * 1.6;        // hot aperture
	col += red.rgb * fres * 0.5;                           // rim light
	col += vec3(1.0) * spec * 0.35;                        // glass highlight
	col *= mix(0.6, 1.0, 1.0 - rim * 0.8);                 // darken housing

	float a = clamp(max(halo * 0.5, body) + hot, 0.0, 1.2);
	COLOR = vec4(col * intensity, a);
}
