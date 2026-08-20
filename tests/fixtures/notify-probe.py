# Send a multi-line body through the same curl config form that
# security-notify uses, and report how many lines came back.
import http.server, threading, subprocess, sys, os, urllib.parse
case = sys.argv[1]
seen = {}
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        seen['d'] = self.rfile.read(n).decode()
        self.send_response(200); self.send_header('Content-Length', '2')
        self.end_headers(); self.wfile.write(b'{}')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
port = srv.server_address[1]
t = threading.Thread(target=srv.handle_request); t.start()
body = os.path.join(case, 'body.txt')
open(body, 'w').write('ALERT\n\nServer : jdih\nfinding : dormant pam_exec\n')
cfg = ('url = "http://127.0.0.1:%d/s"\nrequest = "POST"\n'
       'data = "chat_id=-1"\ndata-urlencode = "text@%s"\n' % (port, body))
subprocess.run(['curl', '-fsS', '--max-time', '5', '--config', '-'],
               input=cfg.encode(), capture_output=True)
t.join()
for k, v in urllib.parse.parse_qsl(seen.get('d', '')):
    if k == 'text':
        print(len(v.splitlines()))
