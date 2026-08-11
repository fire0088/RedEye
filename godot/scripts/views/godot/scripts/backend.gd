extends Node
## Backend client (autoload). Speaks the newline-delimited JSON protocol of the
## Python daemon (redeye/daemon.py) over a local TCP socket.
##
##   commands  -> send_command({"cmd": "...", ...})
##   rpc calls -> await call_rpc("list_findings")   (returns the "result", or null)
##   events    -> connect to the `event` signal (worker events + hello)
##
## The daemon does everything real; this just relays. Start it with
##   python serve.py
## before running the Godot project.

signal event(msg: Dictionary)           ## any worker event: {"type": ..., ...}
signal hello(info: Dictionary)          ## first message after successful auth
signal authed(info: Dictionary)         ## alias of hello, for login UIs
signal auth_failed(error: String)       ## bad password
signal need_login()                     ## server wants credentials we don't have
signal link_changed(up: bool)           ## socket up/down
signal _rpc_returned(rid: int, msg: Dictionary)   ## internal

const DEFAULT_HOST := "127.0.0.1"
const DEFAULT_PORT := 8787
const RECONNECT_EVERY := 1.5            ## seconds between reconnect attempts

var host := DEFAULT_HOST
var port := DEFAULT_PORT
var username := "operator"
var password := ""
var _authed := false

var _peer := StreamPeerTCP.new()
var _inbuf := PackedByteArray()
var _rid := 0
var _connected := false
var _retry := 0.0

func _ready() -> void:
	set_process(true)
	_try_connect()

func set_endpoint(h: String, p: int) -> void:
	# point at a (possibly remote) daemon; reconnects on the new address
	if h.strip_edges() != "":
		host = h.strip_edges()
	if p > 0:
		port = p
	_connected = false
	_authed = false
	if _peer:
		_peer.disconnect_from_host()
	_try_connect()

func _try_connect() -> void:
	_peer = StreamPeerTCP.new()
	_peer.connect_to_host(host, port)

func is_up() -> bool:
	return _connected

# -- outgoing ----------------------------------------------------------------
func login(user: String, pass_: String) -> void:
	username = user if user.strip_edges() != "" else "operator"
	password = pass_
	if _connected:
		_send_auth()

func _send_auth() -> void:
	_write({"cmd": "auth", "user": username, "password": password})

func send_command(d: Dictionary) -> void:
	_write(d)

## Fire an RPC and await its reply. Returns the "result" value on success,
## or null on error/timeout. Callers that need error detail can use call_rpc_full.
func call_rpc(name: String, args: Dictionary = {}) -> Variant:
	var msg: Dictionary = await call_rpc_full(name, args)
	return msg.get("result", null) if msg.get("ok", false) else null

func call_rpc_full(name: String, args: Dictionary = {}) -> Dictionary:
	_rid += 1
	var rid := _rid
	var payload := {"rpc": name, "rid": rid}
	for k in args:
		payload[k] = args[k]
	_write(payload)
	# wait for the matching reply (or give up after ~6s)
	var deadline := Time.get_ticks_msec() + 6000
	while Time.get_ticks_msec() < deadline:
		var r: Array = await _rpc_returned
		if int(r[0]) == rid:
			return r[1]
	return {"ok": false, "error": "rpc timeout"}

func _write(d: Dictionary) -> void:
	if not _connected:
		return
	var line := JSON.stringify(d) + "\n"
	_peer.put_data(line.to_utf8_buffer())

# -- polling / incoming ------------------------------------------------------
func _process(delta: float) -> void:
	_peer.poll()
	var st := _peer.get_status()
	if st == StreamPeerTCP.STATUS_CONNECTED:
		if not _connected:
			_connected = true
			emit_signal("link_changed", true)
		var n := _peer.get_available_bytes()
		if n > 0:
			var res: Array = _peer.get_data(n)
			if res[0] == OK:
				_inbuf.append_array(res[1])
				_drain_lines()
	else:
		if _connected:
			_connected = false
			_authed = false
			emit_signal("link_changed", false)
		# not connected -- retry periodically
		if st == StreamPeerTCP.STATUS_ERROR or st == StreamPeerTCP.STATUS_NONE:
			_retry -= delta
			if _retry <= 0.0:
				_retry = RECONNECT_EVERY
				_try_connect()

func _drain_lines() -> void:
	while true:
		var nl := _inbuf.find(10)   # '\n'
		if nl == -1:
			break
		var line := _inbuf.slice(0, nl)
		_inbuf = _inbuf.slice(nl + 1)
		if line.size() == 0:
			continue
		var txt := line.get_string_from_utf8()
		var msg = JSON.parse_string(txt)
		if typeof(msg) != TYPE_DICTIONARY:
			continue
		_dispatch(msg)

func _dispatch(msg: Dictionary) -> void:
	match msg.get("type", ""):
		"rpc_result":
			emit_signal("_rpc_returned", int(msg.get("rid", -1)), msg)
		"auth_required":
			if password != "":
				_send_auth()
			else:
				emit_signal("need_login")
			emit_signal("event", msg)
		"auth_error":
			_authed = false
			password = ""   # drop the bad key so we don't auto-retry it forever
			emit_signal("auth_failed", str(msg.get("error", "auth failed")))
			emit_signal("event", msg)
		"hello":
			_authed = true
			emit_signal("hello", msg)
			emit_signal("authed", msg)
			emit_signal("event", msg)
		_:
			emit_signal("event", msg)
