# modules/consent_server.py — Remote Consent Server
# ─────────────────────────────────────────────────
# HOW IT WORKS:
#   1. Flask starts on localhost:8765
#   2. ngrok creates a public https:// URL automatically
#   3. QR code is generated from that public URL
#   4. QR shown in terminal + saved as qr_consent.png
#   5. You send that PNG to client via WhatsApp / email / any messenger
#   6. Client scans QR → opens consent page → clicks Authorize or Deny
#   7. CyberShield receives response and proceeds accordingly
#
# REQUIREMENTS (one-time setup):
#   pip install flask pyngrok qrcode[pil] rich
#   Sign up free at https://ngrok.com → Dashboard → Your Authtoken
#   Run once in terminal: ngrok config add-authtoken YOUR_TOKEN
# ─────────────────────────────────────────────────

import socket
import secrets
import threading
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

console = Console()

# ── optional imports ──────────────────────────────────────────────────────────
try:
    from flask import Flask, request, jsonify, render_template_string
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

try:
    from pyngrok import ngrok
    NGROK_OK = True
except ImportError:
    NGROK_OK = False

try:
    import qrcode
    QR_OK = True
except ImportError:
    QR_OK = False

CONSENT_TIMEOUT = 300   # 5 minutes
PORT            = 8765


# ── consent webpage ───────────────────────────────────────────────────────────
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CyberShield – Security Scan Consent</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;700&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --green:  #00ff88;
      --red:    #ff3b5c;
      --yellow: #ffc107;
      --bg:     #080c10;
      --card:   #0d1117;
      --border: rgba(0,255,136,0.15);
      --dim:    rgba(255,255,255,0.35);
    }
    body {
      font-family: 'Rajdhani', sans-serif;
      background: var(--bg);
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 24px;
    }
    body::before {
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,255,136,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,136,0.025) 1px, transparent 1px);
      background-size: 36px 36px;
      pointer-events: none;
    }
    .card {
      position: relative;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 32px 26px;
      max-width: 420px; width: 100%;
      box-shadow: 0 0 60px rgba(0,255,136,0.05);
    }
    .card::before {
      content: '';
      position: absolute;
      top: -1px; left: 20%; right: 20%;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--green), transparent);
    }
    .header {
      display: flex; align-items: center; gap: 14px;
      margin-bottom: 22px; padding-bottom: 18px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    .shield {
      width: 46px; height: 46px;
      border: 1.5px solid var(--green); border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      font-size: 20px;
      background: rgba(0,255,136,0.07);
      flex-shrink: 0;
      animation: glow 3s ease-in-out infinite;
    }
    @keyframes glow {
      0%,100% { box-shadow: 0 0 0 0 rgba(0,255,136,0.25); }
      50%      { box-shadow: 0 0 0 8px rgba(0,255,136,0); }
    }
    .title { color: #fff; font-size: 17px; font-weight: 700; }
    .mono  { font-family: 'Share Tech Mono', monospace; color: var(--green); font-size: 10px; letter-spacing: 2px; margin-top: 3px; }
    .info-block {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.05);
      border-radius: 4px; padding: 14px; margin-bottom: 14px;
    }
    .row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      font-size: 13px;
    }
    .row:last-child { border-bottom: none; }
    .lbl { font-family: 'Share Tech Mono', monospace; color: var(--dim); font-size: 10px; letter-spacing: 1px; text-transform: uppercase; }
    .val { color: #e6edf3; font-weight: 600; }
    .val.green { color: var(--green); }
    .timer-row {
      display: flex; justify-content: space-between; align-items: center;
      border: 1px solid rgba(255,193,7,0.2);
      background: rgba(255,193,7,0.04);
      border-radius: 4px; padding: 9px 14px; margin-bottom: 14px;
    }
    .tlabel { font-family: 'Share Tech Mono', monospace; color: var(--yellow); font-size: 10px; letter-spacing: 1.5px; }
    #timer  { font-family: 'Share Tech Mono', monospace; color: var(--yellow); font-size: 20px; font-weight: 700; letter-spacing: 3px; }
    #timer.urgent { color: var(--red); animation: blink 1s step-end infinite; }
    @keyframes blink { 50% { opacity: 0.3; } }
    .legal {
      font-family: 'Share Tech Mono', monospace;
      font-size: 10px; color: var(--dim); line-height: 1.9;
      margin-bottom: 18px; padding: 10px 12px;
      border-left: 2px solid rgba(0,255,136,0.2);
      background: rgba(0,255,136,0.015);
    }
    .btn {
      display: block; width: 100%; padding: 15px;
      border: none; border-radius: 4px;
      font-family: 'Rajdhani', sans-serif;
      font-size: 15px; font-weight: 700;
      letter-spacing: 2.5px; text-transform: uppercase;
      cursor: pointer; margin-bottom: 10px;
      transition: all 0.15s;
    }
    .btn:active { transform: scale(0.98); }
    .btn-yes {
      background: rgba(0,255,136,0.08);
      border: 1.5px solid var(--green); color: var(--green);
    }
    .btn-yes:hover { background: rgba(0,255,136,0.14); box-shadow: 0 0 24px rgba(0,255,136,0.15); }
    .btn-no {
      background: rgba(255,59,92,0.06);
      border: 1.5px solid rgba(255,59,92,0.4); color: var(--red);
    }
    .btn-no:hover { background: rgba(255,59,92,0.12); }
    .result { display: none; text-align: center; padding: 28px 20px; border-radius: 4px; }
    .r-icon  { font-size: 34px; margin-bottom: 10px; }
    .r-title { font-family: 'Rajdhani', sans-serif; font-size: 20px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 5px; }
    .r-sub   { font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--dim); }
    .result-yes { background: rgba(0,255,136,0.05); border: 1px solid rgba(0,255,136,0.25); }
    .result-yes .r-title { color: var(--green); }
    .result-no  { background: rgba(255,59,92,0.05); border: 1px solid rgba(255,59,92,0.25); }
    .result-no  .r-title { color: var(--red); }
    .expired { text-align: center; padding: 32px 10px; }
    .expired p { font-family: 'Share Tech Mono', monospace; color: var(--dim); font-size: 11px; line-height: 2; }
    .footer { margin-top: 18px; text-align: center; font-family: 'Share Tech Mono', monospace; font-size: 9px; color: rgba(255,255,255,0.12); letter-spacing: 2px; }
  </style>
</head>
<body>
<div class="card" id="mainCard">
  <div class="header">
    <div class="shield">🛡️</div>
    <div>
      <div class="title">Security Scan Consent</div>
      <div class="mono">CYBERSHIELD // REMOTE SESSION</div>
    </div>
  </div>
  <div class="info-block">
    <div class="row"><span class="lbl">Target Device</span><span class="val green">{{ target_ip }}</span></div>
    <div class="row"><span class="lbl">Hostname</span><span class="val">{{ hostname }}</span></div>
    <div class="row"><span class="lbl">Requested By</span><span class="val">{{ requester }}</span></div>
    <div class="row"><span class="lbl">Operation</span><span class="val">{{ operation }}</span></div>
    <div class="row"><span class="lbl">Time</span><span class="val">{{ timestamp }}</span></div>
  </div>
  <div class="timer-row">
    <span class="tlabel">⏱ EXPIRES IN</span>
    <span id="timer">5:00</span>
  </div>
  <div class="legal">
    ▸ You confirm you are the owner or authorized administrator of the device listed above.<br/>
    ▸ You consent to a defensive security audit for vulnerability detection only.<br/>
    ▸ No personal data leaves your machine. You may deny at any time.
  </div>
  <button class="btn btn-yes" onclick="respond('yes')">✔ &nbsp;Authorize Scan</button>
  <button class="btn btn-no"  onclick="respond('no')">✖ &nbsp;Deny Request</button>
  <div class="result result-yes" id="res-yes">
    <div class="r-icon">✅</div>
    <div class="r-title">Scan Authorized</div>
    <div class="r-sub">Response recorded. You may close this page.</div>
  </div>
  <div class="result result-no" id="res-no">
    <div class="r-icon">🚫</div>
    <div class="r-title">Request Denied</div>
    <div class="r-sub">No scan will be performed.</div>
  </div>
  <div class="footer">CYBERSHIELD // DEFENSIVE USE ONLY</div>
</div>
<script>
  let seconds = {{ timeout }};
  const el = document.getElementById('timer');
  const tick = setInterval(() => {
    seconds--;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    el.textContent = m + ':' + String(s).padStart(2, '0');
    if (seconds <= 60) el.classList.add('urgent');
    if (seconds <= 0) {
      clearInterval(tick);
      document.getElementById('mainCard').innerHTML =
        '<div class="expired"><p>⏰ REQUEST EXPIRED<br/><br/>This consent link has timed out.<br/>Ask the operator to resend.</p></div>';
    }
  }, 1000);
  function respond(choice) {
    clearInterval(tick);
    document.querySelectorAll('.btn, .timer-row, .legal').forEach(e => e.style.display = 'none');
    document.getElementById('res-' + choice).style.display = 'block';
    fetch('/respond/{{ token }}/' + choice, { method: 'POST' }).catch(() => {});
  }
</script>
</body>
</html>
"""


# ── QR code generator ─────────────────────────────────────────────────────────
def _generate_qr(url: str, save_path: str = "qr_consent.png") -> None:
    """Print QR to terminal and save as PNG."""
    if not QR_OK:
        console.print("[yellow]  qrcode not installed. Run: pip install qrcode[pil][/yellow]")
        console.print(f"  [dim]Share this URL manually: {url}[/dim]")
        return

    # terminal display (small, ASCII)
    qr_t = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=1, border=0)
    qr_t.add_data(url)
    qr_t.make(fit=True)
    console.print("\n[bold green]  Scan this QR with client's phone:[/bold green]\n")
    qr_t.print_ascii(invert=True)

    # save as PNG (larger, green on dark — matches CyberShield theme)
    qr_p = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=12, border=3)
    qr_p.add_data(url)
    qr_p.make(fit=True)
    img = qr_p.make_image(fill_color="#00ff88", back_color="#0d1117")
    img.save(save_path)

    console.print(f"\n[green]  QR saved → [bold]{save_path}[/bold][/green]")
    console.print(f"[dim]  Send this PNG to your client via WhatsApp, email, or any messenger.[/dim]\n")


# ── ngrok tunnel ──────────────────────────────────────────────────────────────
def _start_ngrok(port: int) -> str | None:
    """Open ngrok tunnel, return public https:// URL or None on failure."""
    if not NGROK_OK:
        console.print("[red]  pyngrok not installed. Run: pip install pyngrok[/red]")
        return None
    try:
        console.print("[dim]  Opening ngrok tunnel...[/dim]")
        tunnel     = ngrok.connect(port, "http")
        public_url = tunnel.public_url.replace("http://", "https://", 1)
        console.print(f"[green]  Tunnel active → [bold]{public_url}[/bold][/green]")
        return public_url
    except Exception as e:
        console.print(f"[red]  ngrok failed: {e}[/red]")
        console.print("[dim]  Did you run: ngrok config add-authtoken YOUR_TOKEN ?[/dim]")
        return None


# ── Flask server class ────────────────────────────────────────────────────────
class ConsentServer:

    def __init__(self):
        self.app      = Flask(__name__) if FLASK_OK else None
        self.response = None
        self.token    = secrets.token_urlsafe(16)
        self._setup_routes()

    def _setup_routes(self):
        if not FLASK_OK:
            return

        app   = self.app
        token = self.token

        @app.route(f"/consent/{token}")
        def consent_page():
            return render_template_string(
                HTML_PAGE,
                target_ip = request.args.get("ip",   "Unknown"),
                hostname  = request.args.get("host", "Unknown"),
                requester = request.args.get("req",  socket.gethostname()),
                operation = request.args.get("op",   "Full Security Audit"),
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                token     = token,
                timeout   = CONSENT_TIMEOUT,
            )

        @app.route(f"/respond/{token}/<choice>", methods=["POST"])
        def receive_response(choice):
            if choice in ("yes", "no"):
                self.response = choice
            return jsonify({"status": "received"})

        @app.route("/ping")
        def ping():
            return jsonify({"status": "ok"})

    def _run_flask(self):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        self.app.run(host="0.0.0.0", port=PORT, debug=False,
                     use_reloader=False, threaded=True)

    def _wait_for_response(self) -> bool:
        """Block until client responds or timeout. Returns True if authorized."""
        start = time.time()
        console.print("[cyan]Waiting for client response[/cyan]", end="")

        while self.response is None:
            if time.time() - start >= CONSENT_TIMEOUT:
                console.print("\n\n[yellow]⏰ Timed out — no response received.[/yellow]")
                try: ngrok.kill()
                except: pass
                return False
            console.print(".", end="", highlight=False)
            time.sleep(3)

        console.print()

        try: ngrok.kill()
        except: pass

        if self.response == "yes":
            console.print(Panel(
                f"[bold green]✔ AUTHORIZED[/bold green]\n"
                f"Client approved at [bold]{datetime.now().strftime('%H:%M:%S')}[/bold].\n"
                f"Proceeding with remote session...",
                border_style="green"
            ))
            return True
        else:
            console.print(Panel(
                "[bold red]✖ DENIED[/bold red]\n"
                "Client rejected the request. No scan will be performed.",
                border_style="red"
            ))
            return False


# ── main public function ──────────────────────────────────────────────────────
def get_remote_consent(
    target_ip : str,
    hostname  : str,
    operation : str = "Full Security Audit",
    qr_path   : str = "qr_consent.png",
) -> bool:
    """
    Remote consent flow:
      1. Starts local Flask server
      2. Opens ngrok tunnel → gets public https:// URL
      3. Generates QR code (shown in terminal + saved as PNG)
      4. You send PNG to client via WhatsApp/email
      5. Client scans QR → opens consent page → clicks Authorize/Deny
      6. Returns True if authorized, False if denied or timed out

    Args:
        target_ip : IP/hostname of client's device
        hostname  : Human-readable device name
        operation : What CyberShield will do (shown on consent page)
        qr_path   : Where to save QR PNG file
    """
    if not FLASK_OK:
        return _terminal_fallback(target_ip, operation)

    server = ConsentServer()

    # start Flask
    threading.Thread(target=server._run_flask, daemon=True).start()
    time.sleep(1.5)

    # start ngrok
    public_base = _start_ngrok(PORT)
    if not public_base:
        console.print("[yellow]Falling back to terminal consent.[/yellow]")
        return _terminal_fallback(target_ip, operation)

    # build consent URL
    consent_url = (
        f"{public_base}/consent/{server.token}"
        f"?ip={target_ip}"
        f"&host={hostname}"
        f"&req={socket.gethostname()}"
        f"&op={operation.replace(' ', '+')}"
    )

    # show summary panel
    console.print(Panel(
        f"[bold]Client Device:[/bold] {target_ip} ({hostname})\n"
        f"[bold]Operation:[/bold]     {operation}\n"
        f"[bold]Consent URL:[/bold]   [underline cyan]{consent_url}[/underline cyan]\n\n"
        f"[dim]QR code below — save PNG and send to client.[/dim]\n"
        f"[dim]Client scans it → opens page → clicks Authorize.[/dim]\n"
        f"[dim]Timeout: 5 minutes.[/dim]",
        title="[bold cyan]🛡  Remote Consent Request[/bold cyan]",
        border_style="cyan"
    ))

    # generate QR
    _generate_qr(consent_url, save_path=qr_path)

    # wait for response
    return server._wait_for_response()


# ── terminal fallback ─────────────────────────────────────────────────────────
def _terminal_fallback(target_ip: str, operation: str) -> bool:
    from rich.prompt import Confirm
    console.print("[yellow]Running in terminal fallback mode.[/yellow]")
    return Confirm.ask(
        f"Authorize [cyan]{operation}[/cyan] on [cyan]{target_ip}[/cyan]?",
        default=False
    )
