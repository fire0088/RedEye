"""Minimal 3D camera for the network map. Pinhole projection with yaw/pitch."""
from __future__ import annotations

import math


class Camera:
    def __init__(self, pos=(0.0, 4.0, 46.0), yaw=math.pi, pitch=-0.05):
        self.x, self.y, self.z = pos
        self.yaw = yaw          # 0 looks toward +Z; pi looks toward -Z origin
        self.pitch = pitch
        self.fov = 65.0         # degrees
        self.move_speed = 22.0
        self.look_speed = 1.6
        self.mouse_sensitivity = 0.0032

    # -- basis vectors ------------------------------------------------------
    def _forward(self):
        cp = math.cos(self.pitch)
        return (math.sin(self.yaw) * cp, math.sin(self.pitch), math.cos(self.yaw) * cp)

    def _right(self):
        return (math.cos(self.yaw), 0.0, -math.sin(self.yaw))

    # -- movement -----------------------------------------------------------
    def move(self, fwd, right, up, dt):
        fx, fy, fz = self._forward()
        rx, ry, rz = self._right()
        s = self.move_speed * dt
        self.x += (fx * fwd + rx * right) * s
        self.y += (fy * fwd + up) * s
        self.z += (fz * fwd + rz * right) * s

    def look(self, dyaw, dpitch, dt):
        self.yaw += dyaw * self.look_speed * dt
        self.pitch += dpitch * self.look_speed * dt
        self.pitch = max(-1.45, min(1.45, self.pitch))

    def look_at(self, tx, ty, tz):
        dx, dy, dz = tx - self.x, ty - self.y, tz - self.z
        self.yaw = math.atan2(dx, dz)
        self.pitch = math.atan2(dy, math.hypot(dx, dz))

    def mouse_look(self, dx, dy):
        """Apply raw mouse deltas (pixels) as yaw/pitch, matching arrow-key sense."""
        self.yaw += dx * self.mouse_sensitivity
        self.pitch -= dy * self.mouse_sensitivity
        self.pitch = max(-1.45, min(1.45, self.pitch))

    def frame(self, points):
        """Reposition to see all given world points (used by 'frame all')."""
        pts = list(points)
        if not pts:
            self.x, self.y, self.z = 0.0, 4.0, 46.0
            self.yaw, self.pitch = math.pi, -0.05
            return
        n = len(pts)
        cx = sum(p[0] for p in pts) / n
        cy = sum(p[1] for p in pts) / n
        cz = sum(p[2] for p in pts) / n
        radius = max((math.dist((cx, cy, cz), p) for p in pts), default=8.0)
        radius = max(radius, 8.0)
        dist = radius / math.tan(math.radians(self.fov) / 2) * 1.25 + 12.0
        self.x, self.y, self.z = cx, cy + radius * 0.35, cz + dist
        self.look_at(cx, cy, cz)

    # -- projection ---------------------------------------------------------
    def project(self, point, screen):
        """World point -> (sx, sy, depth, scale) or None if behind camera."""
        px, py, pz = point
        dx, dy, dz = px - self.x, py - self.y, pz - self.z

        # rotate into camera space (inverse yaw then pitch)
        cy, sy = math.cos(-self.yaw), math.sin(-self.yaw)
        ex = dx * cy - dz * sy
        ez = dx * sy + dz * cy
        cp, sp = math.cos(-self.pitch), math.sin(-self.pitch)
        ey = dy * cp - ez * sp
        ez = dy * sp + ez * cp

        if ez <= 0.05:
            return None
        w, h = screen
        f = (h / 2) / math.tan(math.radians(self.fov) / 2)
        sx = w / 2 + (ex * f) / ez
        sy2 = h / 2 - (ey * f) / ez
        scale = f / ez
        return (sx, sy2, ez, scale)
