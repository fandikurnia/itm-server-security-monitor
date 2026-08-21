# Run the real security-notify script end to end (its own TEXT
# construction, not a hand built curl config) against a local
# HTTP server, and print back the message body it delivered.
#
# Used to confirm the "Created by ITM Team" attribution line
# rides along on every alert without having to inspect the
# script's source text alone - source text can drift from what
# actually gets sent.
import http.server, threading, subprocess, sys, os, urllib.parse

repo = sys.argv[1]
case = sys.argv[2]
seen = {}


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        seen['d'] = self.rfile.read(n).decode()
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(('127.0.0.1', 0), H)
port = srv.server_address[1]
t = threading.Thread(target=srv.handle_request)
t.start()

src = open(os.path.join(repo, 'bin', 'security-notify')).read()
src = src.replace(
    'https://api.telegram.org/bot${BOT_TOKEN}/sendMessage',
    'http://127.0.0.1:%d/send' % port,
)
conf = os.path.join(case, 'telegram.conf')
src = src.replace('/etc/security-monitor/telegram.conf', conf)

sh = os.path.join(case, 'notify')
open(sh, 'w').write(src)
os.chmod(sh, 0o755)
open(conf, 'w').write('BOT_TOKEN="1234:X"\nCHAT_ID="-1"\n')

r = subprocess.run(
    [sh, 'HIGH finding: dormant pam_exec hook\npath: /etc/pam.d/common-auth'],
    capture_output=True, text=True,
)
t.join()

if r.returncode != 0:
    print('EXIT=%d STDERR=%s' % (r.returncode, r.stderr.strip()), file=sys.stderr)

for k, v in urllib.parse.parse_qsl(seen.get('d', '')):
    if k == 'text':
        print(v)
