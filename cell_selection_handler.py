#!/usr/bin/env python3

import http.server
import socketserver
import os
import json
import cgi
import time

PORT = 8001

class CellSelectionHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/cell_selection.json':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                cell_selection = json.loads(post_data.decode('utf-8'))
                
                # Save the selection to a file
                output_dir = os.path.dirname(os.path.abspath(__file__))
                cell_selection_file = os.path.join(output_dir, "cell_selection.json")
                
                with open(cell_selection_file, 'w') as f:
                    json.dump(cell_selection, f)
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success'}).encode())
                
                print(f"[INFO] Cell selection updated to cell {cell_selection['selected_cell']}")
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'error', 'message': str(e)}).encode())
                print(f"[ERROR] Error handling cell selection: {e}")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'error', 'message': 'Not found'}).encode())

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        return super().end_headers()

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), CellSelectionHandler) as httpd:
        print(f"Cell selection handler running at http://localhost:{PORT}")
        httpd.serve_forever()
