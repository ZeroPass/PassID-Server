#!/usr/bin/env python3
__version__ = "0.1"
__all__ = ["WebApp"]

import argparse, os, ssl, sys
from pathlib import Path
import logging

_script_path = Path(os.path.dirname(sys.argv[0]))
sys.path.append(str(_script_path / Path("../")))


logger = logging.getLogger(__name__)
from management.builder import Builder

import os
import posixpath
import http.server
import socketserver
import urllib.request, urllib.parse, urllib.error
import html
import shutil
import mimetypes
import re
import argparse
from settings import *
import base64

from io import BytesIO


class WebApp(http.server.BaseHTTPRequestHandler):
    """Web app class"""

    server_version = "WebApp/" + __version__

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def do_POST(self):
        """Serve a POST request."""
        r, info = self.deal_post_data()
        print((r, info, "by: ", self.client_address))
        f = BytesIO()
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Upload Result Page</title>\n")
        f.write(b"<body>\n<h2>Upload Result Page</h2>\n")
        f.write(b"<hr>\n")
        if r:
            f.write(b"<strong>Success:</strong>")
        else:
            f.write(b"<strong>Failed:</strong>")
        f.write(info.encode())
        f.write(("<br><a href=\"%s\">back</a>" % self.headers['referer']).encode())
        f.write(b"<hr><small>Powered By: bones7456, check new version at ")
        f.write(b"<a href=\"https://gist.github.com/UniIsland/3346170\">")
        f.write(b"here</a>.</small></body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def deal_post_data(self):
        uploaded_files = []
        content_type = self.headers['content-type']
        if not content_type:
            return (False, "Content-Type header doesn't contain boundary")
        boundary = content_type.split("=")[1].encode()
        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)
        if not boundary in line:
            return (False, "Content NOT begin with boundary")

        containsMasterList = False
        containsDSCCRL = False

        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)

            fn =re.findall(r'Content-Disposition.*name="file(ML|DSC)"; filename="(.*)"', line.decode())

            isMasterList = False
            isDSCCRL = False

            if fn[0][0] == "ML" and fn[0][1] != "":
                containsMasterList = True
                isMasterList = True

            if fn[0][0] == "DSC" and fn[0][1] != "":
                containsDSCCRL = True
                isDSCCRL = True

            if not fn:
                return (False, "Can't find out file name...")
            path = self.translate_path(self.path + "/src/WebApp/uploadedFiles")
            fn = None
            if isMasterList == True:
                fn = os.path.join(path, "MasterList.ldif")
            elif isDSCCRL == True:
                fn = os.path.join(path, "DSC_CRL.ldif")

            line = self.rfile.readline()
            remainbytes -= len(line)
            line = self.rfile.readline()
            remainbytes -= len(line)
            try:
                out = open(fn, 'wb')
            except IOError:
                return (False, "Can't create file to write, do you have permission to write?")
            else:
                with out:
                    preline = self.rfile.readline()
                    remainbytes -= len(preline)
                    while remainbytes > 0:
                        line = self.rfile.readline()
                        remainbytes -= len(line)
                        if boundary in line:
                            preline = preline[0:-1]
                            if preline.endswith(b'\r'):
                                preline = preline[0:-1]
                            out.write(preline)
                            uploaded_files.append(fn)
                            break
                        else:
                            out.write(preline)
                            preline = line

        if containsDSCCRL == False and containsMasterList == False:
            return (False, "There is no master list and DSC/CRL files.")
        elif containsDSCCRL == False:
            return (False, "There is no DSC/CRL file.")
        elif containsMasterList == False:
            return (False, "There is no master list file.")
        else:
            fnDSC_CRL = os.path.join(path, "DSC_CRL.ldif")
            fnMasterList = os.path.join(path, "MasterList.ldif")

            fnDSC_CRL_open = open(fnDSC_CRL, 'rb')
            fnMasterList_open = open(fnMasterList, 'rb')

            try:
                Builder(fnMasterList_open, fnDSC_CRL_open, config)
            except Exception as e:
                logger.info("There is an exception. Error: " + str(e))
            return (True, "File '%s' upload success!" % ",".join(uploaded_files))

    def send_head(self):
        """Add haead"""
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = BytesIO()
        displaypath = html.escape(urllib.parse.unquote(self.path))
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(("<html>\n<title>Directory listing for %s</title>\n" % displaypath).encode())
        f.write(b'<style type="text/css">\n')
        f.write(b'a { text-decoration: none; }\n')
        f.write(b'a:link { text-decoration: none; font-weight: bold; color: #0000ff; }\n')
        f.write(b'a:visited { text-decoration: none; font-weight: bold; color: #0000ff; }\n')
        f.write(b'a:active { text-decoration: none; font-weight: bold; color: #0000ff; }\n')
        f.write(b'a:hover { text-decoration: none; font-weight: bold; color: #ff0000; }\n')
        f.write(b'</style>\n')
        f.write(("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath).encode())
        f.write(b"""<html>
                <head>
                    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                    <title>2 Column Frames Layout &mdash; Left Menu</title>
                    <style type="text/css">
                    
                    body{
                        margin: 0;
                        padding: 0;
                        overflow: hidden;
                        height: 100%; 
                        max-height: 100%; 
                        font-family:Sans-serif;
                        line-height: 1.5em;
                    }
                    
                    #nav{
                        position: absolute;
                        top: 0;
                        bottom: 0; 
                        left: 0;
                        width: 230px; /* Width of navigation frame */
                        height: 100%;
                        overflow: hidden; /* Disables scrollbars on the navigation frame. To enable scrollbars, change "hidden" to "scroll" */
                        background: #eee;
                    }
                    
                    main{
                        position: fixed;
                        top: 0; 
                        left: 230px; /* Set this to the width of the navigation frame */
                        right: 0;
                        bottom: 0;
                        overflow: auto; 
                        background: #fff;
                    }
                    
                    #bottom{
                        text-align: right;
                        position:absolute;
                        bottom:0;
                        right:5%;
                    }
                    
                    .innertube{
                        margin: 15px; /* Provides padding for the content */
                    }
                    
                    .uploadButton {
                        box-shadow:inset 0px 1px 0px 0px #ffffff;
                        background:linear-gradient(to bottom, #f9f9f9 5%, #e9e9e9 100%);
                        background-color:#f9f9f9;
                        border-radius:6px;
                        border:1px solid #dcdcdc;
                        display:inline-block;
                        cursor:pointer;
                        color:#666666;
                        font-family:Arial;
                        font-size:15px;
                        font-weight:bold;
                        padding:6px 24px;
                        text-decoration:none;
                        text-shadow:0px 1px 0px #ffffff;
                    }
                    .uploadButton:hover {
                        background:linear-gradient(to bottom, #e9e9e9 5%, #f9f9f9 100%);
                        background-color:#e9e9e9;
                    }
                    .uploadButton:active {
                        position:relative;
                        top:1px;
                    }
                    
                    p {
                        color: #555;
                    }
            
                    nav ul {
                        list-style-type: none;
                        margin: 0;
                        padding: 0;
                    }
                    
                    nav ul a {
                        color: darkgreen;
                        text-decoration: none;
                    }
                            
                    /*IE6 fix*/
                    * html body{
                        padding: 0 0 0 230px; /* Set the last value to the width of the navigation frame */
                    }
                    
                    * html main{ 
                        height: 100%; 
                        width: 100%; 
                    }
                    
                    </style>
                    
                    <script type="text/javascript">
                        /* =============================
                        This script generates sample text for the body content. 
                        You can remove this script and any reference to it. 
                         ============================= */
                        var bodyText=["Remember, you are unique, just like everybody else.", "Too much agreement kills a good chat.", "Get your facts first, then you can distort them as you please.", "I intend to live forever. So far, so good.", "</p><p>A clear conscience is usually a sign of a bad memory.", "What's another word for Thesaurus?", "<h3>Heading</h3><p>Experience is something you don't get until just after you need it."]
                        function generateText(sentenceCount){
                            for (var i=0; i<sentenceCount; i++)
                            document.write(bodyText[Math.floor(Math.random()*7)]+" ")
                        }
                    </script>	
                
                </head>
                
                <body>		
                            
                    <main>
                        <div class="innertube">
                            
                            <h1>Upload ICAO data</h1>
                            <!--<p><script>generateText(300)</script></p>-->
                                <form ENCTYPE=\"multipart/form-data\" method=\"post\">
                                <h4>ICAO master list</h4>
                                <input name=\"fileML\" type=\"file\" multiple/>
                                <h4>ICAO DSC/CRL list</h4>
                                <input name=\"fileDSC\" type=\"file\" multiple/>
                                </br></br>
                                <input class="uploadButton" type=\"submit\" value=\"Upload both files\"/></form>
        
                        </div>
                    </main>
                
                    <nav id="nav">
                        <div class="innertube">
                        
                        <h3>EOSIO PassID</h3>
                        <h5>On-chain ePassport Active Authentication</h5>
                        </br></br></br></br>
                        
                        <div id="bottom">Block.one/ZeroPass </div>
                        
                        </div>
                    </nav>
                
                </body>
            </html>
            """)
        f.write(b"</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self, path):
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        path = os.getcwd()
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


ap = argparse.ArgumentParser()

ap.add_argument("-u", "--url", default='127.0.0.1',
                type=str, help="Server http address. Default is localhost. The value '*' set the server open to worldwide.")

ap.add_argument("-p", "--port", default=8000,
                type=int, help="server listening port. Default is 8000.")

ap.add_argument("--db-user", default="",
                type=str, help="database user name")

ap.add_argument("--db-pwd", default="",
                type=str, help="database password")

ap.add_argument("--db-name", default="",
                type=str, help="database name")

args = vars(ap.parse_args())

if args['url'] == '*':
    args['url'] = "0.0.0.0"
elif args['url'] == "localhost":
    args['url'] = "127.0.0.1"

#print(args)

if args['db_user'] == None or args['db_pwd'] == None or args['db_name'] == None:
    raise Exception("Parameters 'db-user', 'db-pwd' and 'db-name' are necessary.")

config = Config(
        database=DbConfig(
            user=args['db_user'],
            pwd=args['db_pwd'],
            db=args['db_name']
        ),
        api_server=ServerConfig(
            host=None,
            port=None,
            ssl_ctx=None
        ),
        web_app=WebAppConfig(
            host=args['url'],
            port=args['port']
        ),
        challenge_ttl=0
    )

print (config)

Handler = WebApp

with socketserver.TCPServer((config.web_app.host, config.web_app.port), Handler) as httpd:
    serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
    print(serve_message.format(host=config.web_app.host, port=config.web_app.port))
    httpd.serve_forever()
