"""

Gnutalla library and console monitor

Version and contact info is after this docstring.

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

This file contains a large number of classes designed to make monitoring and
searching the gnutella network easier, as well as a complete gnutella daemon
for running in the background.

##
## Daemon usage:
##

This library can be run as a forking background process. Example usage:

$ python gnutellalib.py --listen <ip> --recurse <path>

Command-line arguments:
	-h, --help		this help page
	-s, --stdin		accept input from the stdin
	-t, --terminal		start a full terminal emulation session
	-l, --listen PORT	start a gnutella/http server [default=6346]
	-o, --open IP:PORT	open a full gnutellanet connection
	-m, --monitor IP:PORT	open a monitoring only connection
	-n, --maintain NUM	number of connection to keep open

File system options:
	-i, --index PATH	index directory
	-r, --recurse PATH	index directory, recursive

More controlling options are:
	--set-localip IP:PORT	local ip and port to use in replies
	--set-speed NUM		local speed to use in query replies

Note that if the --console option is NOT given, then the program will simply
connect to the network and try to maintain links.

##
## Library usage:
##

class GnutellaHTTPServer(SocketServer.ThreadingTCPServer)

	This is a listening server for accepting incoming gnutella
	connections. It is not required to connect out, only to
	accept incoming connections. It does support a connect()
	function in the event you would like a single object to
	handle both incoming/outgoing links.
	
class MonitorRequestHandler(SocketServer.BaseRequestHandler)

	This is the "pure" request handler. It does nothing more than
	read continuously from the link, parse and decode both the
	header and payload, and output a summary to the stdout.
	
	This class has a process() function that should be overridden
	when inherited.
	
	This class does not reply to any messages or run any searches.
	
class GnutellaRequestHandler(MonitorRequestHandler)

	This is the standard gnutella handler. This class will take all
	decoded messages and handle them as best as it can. It will reply
	to pings and queries, track message id's, and verify all messages
	passing through.
	
	It will currently verify:
	
	1. If the message id is valid or has already been handled.
	2. If the ttl value is reasonable/valid
	3. If the hop count is reasonable/valid
	4. If the function id is recognized
	5. If the the IP address is routable to the rest of the world.
	6. If a PUSH command is routed correctly
	
	Only validated messages are printed to the stdout.
	
class FileIndex
	
	This is the index cache for all local files. If you want to add a
	directory to the cache, use the index(path) function. If you want
	to add the directory and subdirs, use index(path, recurse = 1).
	
	Successive directories can be added, and will be stored along with
	the recurse option. This allows you to call reload() to rebuild the
	file cache without reentering the directories.
	
class FileSearch

	This is a search object that supports many types of searches, even
	though the gnutella protocol is limited (right now) to doing glob
	searches.
	
	When creating a new search object, you MUST supply a FileIndex class
	for the __init__ function. The file cache will be copied and tested.
	
	You can run successive searches on the search object.
	
	Sample globbing usage for a "metallica ride lightening mp3" search:
	
		search	= FileSearch(my_file_index)
		search.glob("*metallica*")
		search.glob("*ride*")
		search.glob("*lightening*")
		search.glob("*mp3*")
		return search.matches()
	
	As each glob runs, the list of matches is reduced. The matches()
	function returns a list of (index, name, size) tuples.
	
	Search functions supported:
	
		search.glob(wildcard)
		search.regex(regular expression)
		search.smaller(value)
		search.larger(value)
		search.before(value)
		search.since(value)
		
class Stdin

	Creates a sys.stdin readline object for accepting command input. See
	the monitor usage section below.
	
## Supporting classes

class GnutellaHeader
class GnutellaPayloadBase
class GnutellaPing(GnutellaPayloadBase)
class GnutellaPingRpl(GnutellaPayloadBase)
class GnutellaPush(GnutellaPayloadBase)
class GnutellaQuery(GnutellaPayloadBase)
class GnutellaQueryRpl(GnutellaPayloadBase)
class GnutellaQueryRec(GnutellaPayloadBase)
		
## Monitor Usage

When run from the commandline as the main python file, a Stdin object is
created to take commands. The available commands are as follows:

	listen <port>		: opens a listening servent
	open [addr] [port]	: connects, default port of 6346. If no
				  address is given, a random address from
				  the servent cache is picked.
	ping			: ping all connected links
	query <search text>	: query links for the file (**)
	quiet			: silences/restores all output
	save [filename]		: saves addr:port to the filename, with
				  the default gnutella.net (*)
	load [filename]		: loads addr:port from the filename, with
				  the default gnutella.net (*)
	dump			: dumps all addresses to the stdout
	stat			: prints stat stuff to the stdout (*)
	quit			: leaves the program, closes all links.
	
				
	(*) these commands are still problematic
	(**) useless, since there is no way yet to get the files

## Sample output from monitor usage:

rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=0 hops=7 speed=0 search='paul weller'
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=0 hops=1 addr=<ip> port=6346 count=110L bytes=503302L
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=1 hops=6
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=0 hops=5 speed=0 search='mpeg'
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=1 hops=4 speed=0 search='anime'
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=1 hops=6
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=1 hops=6 speed=0 search='jedy'
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=2 hops=5 speed=0 search='Exchange'
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=0 hops=7
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=0 hops=5 speed=0 search='les mpeg'
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=3 hops=4 speed=0 search='metallica'
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=3 hops=4 speed=0 search='young'
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=3 hops=4
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=0 hops=5
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=1 hops=6
rhost=<ip:port> lhost=<ip:port> id=0x80 ttl=0 hops=7 speed=0 search='Thorn birds'
rhost=<ip:port> lhost=<ip:port> id=0x0 ttl=2 hops=5
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=2 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L
rhost=<ip:port> lhost=<ip:port> id=0x1 ttl=1 hops=1 addr=<ip> port=6346 count=0L bytes=0L

## Issues:

1. Only internet IP's addresses are recognized as valid.
2. The load/save commands have issues.
3. Dropped packets are not counted
4. No http server implemented for file retrieval
6. The --listen ip is the one used for ping and query replies.
		

## Protocol fixes:
##
## These are just ideas for protocol fixes. These are NOT the current
## protocol structures.

gnutella_hdr:		all function id's

	header.ver	= 0x00		# unsigned version
	header.fid	= 0x00		# unsigned, low bit on is a reply
	header.ttl	= 0x00		# unsigned
	header.opts	= 0x00		# unused message options
	header.mid	= 0x00 * 16	# string GUID or md5	
	header.dlen	= 0x0000	# unsigned, length of data
	header.null	= 0x0000	# empty, unused
	
	Total len: 24 bytes, aligned on boundry

	Notes:

	1. Hops are not needed. The ttl value is sufficient for tracking
	message life. Since replies are routed, the ttl and hop values are
	both meaningless on replies. Pushes are also routed, so hops are
	meaningless here as well.

	Pretty much, it boils down to: if the message gets there the first
	time, it should be guaranteed to get routed back and forth again.

	2. Version field is needed in the header so that future changes can
	be made. Right now the only version check is at connect time, but
	that implies that all messages are fully parsed by each servent, when
	in fact most messages are forwarded and forgotten. Translating each
	message per connection is a very unneeded overhead, which is why a
	version field is needed.

	3. The max message length is 65536 bytes. This is also the max MTU
	allowed by current rfc's, which happens to be a hyperchannel link,
	whatever that is.

	The options can be extended in the future (?)

	1. Add a DO_NOT_REPLY option. This would allow "breeding servents"
	whose job would be to emit pings with ip/ports randomly chosen from
	it's host cache. When other servents receive the ping, they cache
	the ip/port, but would not reply with if option was enabled.


gnutella_link_hdr:	function id 0x00, 0x01, 0x40, 0x81

	header.ver	= 0x00		# unsigned, record version
	header.speed	= 0x00		# unsigned
	header.port	= 0x0000	# unsigned
	header.addr	= 0x00000000	# signed (?)
	header.count	= 0x00000000	# unsigned
	header.size	= 0x00000000	# unsigned

	Total len:	16 bytes.

	Note:

	For 0x00 and 0x01 messages, the header.count is the total number
	of files available for searching, and the header.size is the total
	size of the files in kbytes.
	
	For 0x40 and 0x81 messages, the header.count is the index of the
	file in question. For 0x40 messages, the header.size is the file
	offset to start the PUSH at. For 0x81 messages the header.size is
	the size of the file in bytes.
	
gnutella_query_hdr:	function 0x80, 0x81

	header.ver	= 0x00
	header.num	= 0x00		# unsigned
	header.recs	= ..		# series of gnutella_query_rec

	Total size:	2 + (total record size)
	Max size:	65536 (from the gnutella_hdr.dlen field)

	For 0x80 messages, the header.recs is a series of search keyword
	records to test for. For 0x81 message, the header.recs is a series
	of matching files found.

gnutella_query_rec:	function 0x80, 0x81

	header.type	= 0x00		# unsigned, type of record
	header.len	= 0x00		# length of record
	header.data	= ..		# some string data

	Total size:	2 + string len
	Max size:	2 + 256 = 258

	For 0x80 messages, the header.type should be the type of search to
	perform. Right now of file glob style searches are available, but
	others could be added:

		0x00		wildcard glob
		0x01		regular expression
		0x02		file size smaller than
		0x03		file size larger than
		0x04		file creation before
		0x05		file creation after
		0x06		file modified before
		0x07		file modified after
		0x0a		file contains string
		0x0b		file does not contain string

## Function format

type 0x00	: gnutella_hdr + gnutella_link_hdr
type 0x01	: gnutella_hdr + gnutella_link_hdr
type 0x40	: gnutella_hdr + gnutella_link_hdr
type 0x80	: gnutella_hdr + gnutella_link_hdr + gnutella_query_hdr + \
		  (n searches items * gnutella_query_rec)
type 0x81	: gnutella_hdr + gnutella_link_hdr + gnutella_query_hdr + \
		  (n reply items * gnutella_query_rec)

"""

__author__		= "Ian Zepp"
__email__		= "devel@edotorg.org"
__version__		= "0.3.0"
__date__		= "May 07 2000"

import os, sys
import md5, time
import struct
import string, re
import thread
import marshal
import whrandom
import traceback
import array
import fnmatch
import stat
import socket
import mutex		# requires python 1.5.2

## Instance types
from types import *

## Socket server stuff
from SocketServer import TCPServer
from SocketServer import ThreadingMixIn
from SocketServer import ForkingMixIn
from SocketServer import ThreadingTCPServer
from SocketServer import StreamRequestHandler

## HTTP serving stuff
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler

##
## Try this:
##
## remotemsg_cache	= {
##	"<message_id>"	: "<source link_id>"
##	"<pushid>"	: "<bounce link_id>"
## }
##

gnutella_hdr		= "_hdr_"
gnutella_ping		= 0x00
gnutella_ping_rpl	= 0x01
gnutella_push		= 0x40
gnutella_query		= 0x80
gnutella_query_rpl	= 0x81
gnutella_query_rec	= 0x82

## Protocol formatting
GnutellaOriginal	= {
	## Main header
	gnutella_hdr		: "<16sbbbI",
	
	## Subsections
	gnutella_ping		: "<",	
	gnutella_ping_rpl	: "<hiII",
	gnutella_push		: "<16sIih",
	gnutella_query		: "<H%ss",
	gnutella_query_rpl	: "<BhiI%ss16s",
	gnutella_query_rec	: "<II%ss",
	
}

GnutellaReprOutput	= {
	## Main header
	gnutella_hdr		: "fid=%(fid)d ttl=%(ttl)d " + \
				  "hops=%(hops)d len=%(len)d",
	
	## Subsections
	gnutella_ping		: "",	
	gnutella_ping_rpl	: "addr=%(addr)s:%(port)d " + \
				  "count=%(count)d bytes=%(bytes)d",
	gnutella_push		: "addr=%(addr)s:%(port)d " + \
				  "index=%(index)d",
	gnutella_query		: "speed=%(speed)d search=%(search)s",
	gnutella_query_rpl	: "addr=%(addr)s:%(port)d " + \
				  "num=%(num)d speed=%(speed)d",
	gnutella_query_rec	: "index=%(index)d size=%(size)d " +\
				  "name=%(name)s",
	
}

## Hack to quiet output from an interactive python session
quiet			= 0

##
## Convert a dotted ip to network byte order and back
##

def inet_aton(x):
	host	= socket.gethostbyname(x)
	a, b, c, d = map(int, string.split(host, '.'))
	host	= (a << 24) + (b << 16) + (c << 8) + (d << 0)
	host	= socket.htonl(host)
	return host

def inet_ntoa(x):
	x = socket.htonl(x)

	return "%s.%s.%s.%s" % (
		(x >> 24) & 0xff,
		(x >> 16) & 0xff,
		(x >> 8) & 0xff,
		(x >> 0) & 0xff,
	)
	
def inet_isroutable(x):
	a, b, c, d = map(int, string.split(x, '.'))
	
	if a == 0:
		return 0			# rumored unroutable
	if a == 10:
		return 0			# rfc 1918
	if a >= 65 and a <= 95:
		return 0			# reserved block 7
	if a >= 96 and a <= 126:
		return 0			# reserved block 8
	if a == 127:
		return 0			# loopback (should be valid?)
	if a == 172 and b >= 16 and b <= 31:
		return 0			# rfc 1918
	if a == 192 and b == 168:
		return 0			# rfc 1918
	if a >= 224:
		return 0			# reserved for multicast
	return 1

##
## Generate a unique id
##	

def unique(prefix = "" ):
	seed	= repr(prefix) + \
		  repr(whrandom.random()) + \
		  repr(time.time()) + \
		  repr(os.getpid())
	return md5.new(seed).digest()

##
## Output mutual exclusion: needed when threaded
##

stdout_lock	= mutex.mutex()
stderr_lock	= mutex.mutex()

def log_stdout(text):
	if not quiet:
		stdout_lock.lock(sys.stdout.write, text)
	stdout_lock.unlock()

def log_stderr(text):
	if not quiet:
		stderr_lock.lock(sys.stderr.write, text)
	stderr_lock.unlock()

def log_info(text):
	log_stdout("INFO " + text)
	
def log_stat(text):
	log_stdout("STAT " + text)
	
def log_error(text):
	log_stderr("ERROR " + text)
	
def log_debug(text):
	log_stderr("DEBUG " + text)

#####################################################################
##
## Global commands
##
#####################################################################

def open_servent(address):
	request	= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	request.connect(address)

	rfile	= request.makefile("rb", 0)
	wfile	= request.makefile("wb", 0)

	## Send a login
	wfile.write("GNUTELLA CONNECT/0.4\n\n")

	## Try to read a reply
	text	= rfile.readline()

	if text == "GNUTELLA OK\n":
		rfile.readline()	# gets the second trailing newline

		## Send a login ping
		payload		= GnutellaPing()
		payload		= payload.encode()

		header		= GnutellaHeader()
		header.mid	= unique()
		header.fid	= gnutella_ping
		header		= header.encode()

		wfile.write(header + payload)

		handler	= GnutellaConnectVersion4(request, address)
		thread.start_new_thread(handler.message_loop, ())
	else:
		raise IOError, "unable to login"

#####################################################################
##
## Indexing and searching the local files
##
#####################################################################

class FileIndex:
	def __init__(self):
		self.files	= {}		# index : (path, stat)
		self.dirs	= {}		# path : (glob, recurse)

		self.size	= 0		# total size of files
				
	def __len__(self):
		return len(self.files)

	def recurse(self, path, glob = "*"):
		self.index(path, glob, recurse = 1)

	def index(self, path, glob = "*", recurse = 0):
		path		= os.path.normpath(path)
		path		= os.path.normcase(path)

		self.dirs[path]	= (glob, recurse)

		if not recurse:
			self.__index(glob, path, os.listdir(path))
		else:
			os.path.walk(path, self.__index, glob)

	def __index(self, glob, dirname, names):
		count	= len(self.files)

		log_stdout("index=%s glob=%s num=%s total=%s\n" %
			(dirname, glob, len(names), count))

		for item in names:
			path	= os.path.join(dirname, item)
			path	= os.path.normpath(path)

			if os.path.islink(path):
				continue
			if os.path.isdir(path):
				continue

			if not fnmatch.fnmatch(item, glob):
				continue

			fstat		= os.stat(path)
			count		= count + 1
			self.size	= self.size + fstat[stat.ST_SIZE]
			
			self.files[count] = (dirname, item, fstat)

	def reload(self):
		tmp	= self.dirs.copy()

		self.files.clear()
		self.dirs.clear()

		for path, data in tmp.items():
			self.index(path, data[0], data[1],)

class FileSearch:
	def __init__(self, findex):
		if not isinstance(findex, FileIndex):
			raise TypeError, "not a FileIndex class"
		
		self.files	= findex.files.copy()
		self.cache	= {}
	def __len__(self):
		return len(self.files)

	def glob(self, glob = "*"):
		return self.regex(fnmatch.translate(glob))
	def regex(self, regex = ".*"):
		regex	= re.compile(regex, re.I)

		for index, fdata in self.files.items():
			## Split into dirname, basename, and stat
			fd, fb, fst	= fdata

			if not regex.match(fb):
				del self.files[index]

	def smaller(self, value):
		self.__compare(stat.ST_SIZE, value, above = 0)
	def larger(self, value):
		self.__compare(stat.ST_SIZE, value, above = 1)
	def before(self, value):
		self.__compare(stat.ST_MTIME, value, above = 0)
	def since(self, value):
		self.__compare(stat.ST_MTIME, value, above = 1)
	def __compare(self, attr, value, above):
		value	= int(value)

		for index, fdata in self.files.items():
			fd, fb, fst	= fdata

			if above and (fst[attr] < value):
				del self.files[index]
			elif not above and (fst[attr] > value):
				del self.files[index]

	##
	## Get the matches, up to a maximum value
	##

	def matches(self, max = 32):
		data	= []
		count	= 0

		for index, fdata in self.files.items():
			if count >= max:
				break
				
			count		= count + 1
			fd, fb, fst	= fdata

			data.append((index, fb, fst[stat.ST_SIZE]))
		return data

######################################################################
##
## Class items
##
######################################################################

class GnutellaHTTPServer(ThreadingMixIn, HTTPServer):
	pass
	

class GnutellaHTTPRequestHandler(SimpleHTTPRequestHandler):
	## Filesystem used for caching files
	file_system	= FileIndex()

	##
	## handling routines
	##
	
	def handle(self):
		""" This function overrides the default

		This is needed to allow a single port to act as a receiver
		for a variety of different protocols.

		Most of this code was taken from the BaseHTTPServer module.

		I changed some ordering though.
		"""
		self.command	= self.rfile.readline()
		self.headers	= rfc822.Message(self.rfile, 0)
		
		## reorder gnutella requests
		if self.command == "GNUTELLA CONNECT/0.4\n":
			self.command = "CONNECT public GNUTELLA/0.4\n"
			
		items		= re.split(" ", self.command, 2)
		
		## Split items
		if len(items) == 2:	# should only exist for http 0.9 gets
			self.method	= items[0]
			self.path	= items[1]
			self.version	= "HTTP/0.9"
		elif len(items) == 3:
			self.method	= items[0]
			self.path	= items[1]
			self.version	= items[2]
		else:
			self.send_error(501)
			return
			
		## Compat with base class
		self.request_version	= self.version
		
		## Method name
		mname	= "do_" + self.command
		
		if not hasattr(self, mname):
			self.send_error(501, "Unsupported method (%s)" %
				self.command)
			return

		try:
			apply(getattr(self, mname), ())
		except:
			print "--- Internal apply error in request handler"
			traceback.print_exc()
			print "--- EOT"
	
	def log_message(self, format, *args):
		"""
		Discard all log messages
		"""
		pass
		
	def do_CONNECT(self):
		"""
		Handler for both the original gnutella version, and
		subsequent protocols. The original protocol login
		is rewritten in the handle() method, before being
		parsed for command and version.
		
		After the protocol handler is registered, it will be
		picked up in the main loop automatically
		"""

		if self.version == "GNUTELLA/0.4":
			## Okay, accept connection
			self.wfile.write("GNUTELLA OK\n")
			self.wfile.write("\n")
		
			## Send a login ping
			payload		= GnutellaPing()
			payload		= payload.encode()

			header		= GnutellaHeader()
			header.mid	= unique()
			header.fid	= gnutella_ping
			header		= header.encode()

			self.wfile.write(header + payload)

			## Start new request handler
			handler	= GnutellaConnectVersion4(
				self.request,
				self.client_address,
			)
	
			## Run the loop.
			handler.message_loop()
			return
			
	def translate_path(self, path):
		"""
		Translate a given index to an actual path
		
		the do_GET() and do_HEAD() methods from the SimpleHTTPServer
		module use this method to find where the requested file
		really lives.
		
		This method takes an index number and returns an actual
		file path. In the event the file doesn't exist, it returns
		an empty string. At that point the get will fail, and a 404
		error will be returned.
		"""
		
		files	= self.file_system.files

		if not len(files):
			return ""
		
		if path[:1] == "/":
			path	= path[1:]
		
		try:
			if self.path[:1] == "/":
				path	= int(self.path[1:])
			else:
				path	= int(self.path)
		except:
			return ""
			
			
		## Does that index exist?
		if not files.has_key(path):
			return ""
			

		try:
			fd, fb, fst	= files[path]
			path		= os.path.join(fd, fb)
		except:
			return ""
		else:
			return path

class GnutellaConnectBase:
	"""
	Servents are cached on an (addr, port) basis, but each time we see a
	ping_rpl for a servent, the older entry is removed from the ordering
	list, and pushed back to the end. This lets old entries that we
	haven't received any ping replies from in a while to get expired.

	"""
	## Near global values
	msg_cache	= {}
	msg_order	= []
	msg_max		= 50000
	msg_slice	= 1000

	servent_cache	= {}
	servent_order	= []
	servent_max	= 2000
	servent_slice	= 500

	ttl_max		= 10
	hops_max	= 10
	drop_max	= 1000

	open_links	= {}

	## host and port to use for query/ping replies to use
	reply_host	= "0.0.0.0"
	reply_port	= 0
	reply_speed	= 0
	
	## Function id counts
	stat_data	= {}

	def __init__(self, request, client_address):
		self.request	= request
		#self.request.setblocking(1)

		self.wfile	= self.request.makefile("wb", 0)
		self.rfile	= self.request.makefile("rb", 0)
		self.address	= client_address

		self.header	= GnutellaHeader()
		self.payload	= GnutellaPayloadBase()
		
		## Number of dropped messages
		self.drop	= 0

		## remember link
		self.open_links[self.address]	= self.wfile

	def __del__(self):
		if not hasattr(self, "address"):
			return
		if not self.open_links.has_key(self.address):
			return
		del self.open_links[self.address]

	def __repr__(self):
		return "rhost=%s drop=%s %s %s" % (
			"%s:%s" % self.address,
			repr(self.drop),
			repr(self.header),
			repr(self.payload),
		)
	def __str__(self):
		return self.__repr__()

	def message_loop(self):
		"""
		Run the read message loop, must be subclassed
		"""

		return

	##
	## Remember/familiar/slice messages
	##

	def remember_message(self, msg_id = None, data = None):
		if not msg_id:
			msg_id	= self.header.mid
		if not data:
			data	= (self.header.fid, self.address)

		self.msg_cache[msg_id]	= data
		self.msg_order.append(msg_id)

		## Over slice limit?
		if len(self.msg_order) < self.msg_max:
			return

		## Cut out old entries
		for item in self.msg_order[:self.msg_slice]:
			if self.msg_cache.has_key(item):
				del self.msg_cache[item]
		self.msg_order	= self.msg_order[self.msg_slice:]
			
	def get_message(self, msg_id = None):
		if not msg_id:
			msg_id	= self.header.mid
		return self.msg_cache.get(msg_id, (None, None))

	##
	## Remember/get/slice servents
	##

	def remember_servent(self, address, data):
		self.servent_cache[address]	= data
		self.servent_order.append(address)

		## Over slice limit?
		if len(self.servent_order) < self.servent_max:
			return

		## Cut out old entries
		for item in self.servent_order[:self.servent_slice]:
			if self.servent_cache.has_key(item):
				del self.servent_cache[item]
		self.servent_order	= self.servent_order[self.servent_slice:]
			
	##
	## Write back to the network
	##

	def broadcast(self, header, payload, exclude = None):
		## Is the payload already encoded?
		if isinstance(payload, GnutellaPayloadBase):
			payload		= payload.encode()

		## how about the header?
		if isinstance(header, GnutellaHeader):
			if header.ttl <= 0:
				return
			if header.hops >= self.hops_max:
				return

			header.dlen	= len(payload)
			header		= header.encode()

		for address, wfile in self.open_links.items():
			if address == exclude:
				continue

			self.write_direct(address, header, payload)

	def write_direct(self, address, header, payload):
		## Is the payload already encoded?
		if isinstance(payload, GnutellaPayloadBase):
			payload		= payload.encode()

		## how about the header?
		if isinstance(header, GnutellaHeader):
			header.dlen	= len(payload)
			header		= header.encode()

		## Full text to send
		text	= header + payload

		## Write object
		wfile	= self.open_links.get(address)

		if not wfile:
			return

		try:
			wfile.write(text)
		except (socket.error, IOError), why:
			log_error("Error writing link: %s\n" % why)
			
			## remove link
			del self.open_links[address]

class GnutellaConnectVersion4(GnutellaConnectBase):
	def message_loop(self):
		try:
			while (1):
				## Excessive drops?
				if self.drop >= self.drop_max:
					raise EOFError, "excessive drops"
				
				self.read_message()
				
				## Add stat data
				self.save_stat()
			
				if not self.verify():
					continue

				## Decrement the drop value
				if self.drop > 0:
					self.drop	= self.drop - 1
				
				self.handle()
				self.output()

		except EOFError, why:
			log_error("EOFError: %s\n" % why)

	def break_push(self):
		self.header.mid		= unique()
		self.header.ttl		= self.ttl_max
		self.header.hops	= 0
		
                self.broadcast(self.header, self.raw_data)
                log_stdout("Breaking push: %s\n" % repr(self.header.mid))
			
	def save_stat(self):
		fid	= self.header.fid
		count	= self.stat_data.get(fid, 0) + 1
		self.stat_data[fid]	= count
	
	def read_message(self):
		self.header	= GnutellaHeader()
		self.payload	= GnutellaPayloadBase()

		header_read	= self.rfile.read(23)

		## If no read, then the connection closed.
		if not header_read:
			raise EOFError, "closed %s:%s" % self.address

		self.header	= GnutellaHeader(header_read)
		self.raw_data	= self.rfile.read(self.header.dlen)

	def output(self):
		print "%s" % repr(self)

	def handle(self):
		"""
		We are trying to avoid decoding the payload here as best as
		possible, in order to improve throughput.

		Unfortunately, it seems to be that every payload has to be decoded.

		0x00	no payload anyways
		0x01	decoded to catch the ip:port pair
		0x40	decoded to check the pushid value
		0x80	decoded to run a search
		0x81	decoded to cache the pushid value

		Best we can do is delay decoding as long as possible
		"""
		if self.header.fid == gnutella_ping:
			self.handle_PING()
			return
			
		if self.header.fid == gnutella_ping_rpl:
			self.handle_PING_RPL()
			return
			
		if self.header.fid == gnutella_push:
			self.handle_PUSH()
			return
			
		if self.header.fid == gnutella_query:
			self.handle_QUERY()
			return
			
		if self.header.fid == gnutella_query_rpl:
			self.handle_QUERY_RPL()
			return
		
	##
	## Verify routines
	##

	def verify(self):
		"""
		Verify a selection of header items.

		"""
		return self.verify_fid() \
		and self.verify_mid() \
		and self.verify_ttl() \
		and self.verify_hops() \

	def verify_fid(self):
		""" Verify the function ID
		
		Valid IDs are:
		
			0x00	gnutella_ping
			0x01	gnutella_ping_rpl
			0x40	gnutella_push
			0x80	gnutella_query
			0x81	gnutella_query_rpl
			
		"""
		
		if self.header.fid == gnutella_ping \
                or self.header.fid == gnutella_ping_rpl \
                or self.header.fid == gnutella_push \
                or self.header.fid == gnutella_query \
                or self.header.fid == gnutella_query_rpl:
                	return 1
                	
                ## Whoops! Bump the drop count
                self.drop	= self.drop + 1
			
	def verify_mid(self):
		"""
		
		Adds the message to the caches in a few different ways,
		and returns whether it existed previously
		
		If this message is a PUSH type, then we have to decode the
		payload, and look for a pushid match.
		
		Replies should always be handled. Anything else that has
		already been seen is a network loop.
		
		"""

		if self.header.fid == gnutella_ping_rpl \
		or self.header.fid == gnutella_query_rpl:
			return 1

		## This returns a function id/write object if we have seen
		## this message id already.
		fid, wfile	= self.get_message()

		## PUSH logic. If we never saw the original message,
		## regardless of possible pushid, it is a misroute.
		if self.header.fid == gnutella_push and not fid:
	                ## Whoops! Bump the drop count, bad pushes hurt
        	        self.drop	= self.drop + 1
			return 0
				
		## If it's not a PUSH and we have lready seen it, then it's
		## a network loop or a misroute. Drop it.
		if fid and wfile:
			return 0

		self.remember_message()
		return 1

	def verify_ttl(self):
		"""
		Verify the time to live
		
		This function enforces an absolute ttl value. If the ttl as
		received is over the maximum ttl allowed, then the ttl is
		first reduced to the maximum, and then the current hop count
		is subtracted from that.

		After this step, the ttl is reduced once more for all
		messages. However, the ttl is not enforced for the message
		at this point if it is a reply-type message. It will be
		rechecked before being forwarded though.

		Note that this can (possibly) allow replies to run into a
		negative ttl value. As long as they are routed correctly,
		this should not be a concern.		

		"""
		
		if self.header.ttl > self.ttl_max:
			self.header.ttl	= self.ttl_max - self.header.hops

		self.header.ttl = self.header.ttl - 1
		
		if self.header.fid == gnutella_ping_rpl \
		or self.header.fid == gnutella_query_rpl:
			return 1
	
		return (self.header.ttl >= 0)
		
	def verify_hops(self):
		"""
                Make sure the hop count is sane

		"""
		self.header.hops = self.header.hops + 1
		return (self.header.hops <= self.hops_max)

        ##
	## Handle version 4 messages
	##
	
	def handle_PING(self):
		## Broadcast pure ping
		self.broadcast(self.header, self.raw_data,
			exclude = self.address)

		## Build a ping reply
		header		= GnutellaHeader()
		header.mid	= self.header.mid
		header.fid	= gnutella_ping_rpl
		header.ttl	= self.header.hops

		payload		= GnutellaPingRpl()
		payload.addr	= inet_aton(self.reply_host)
		payload.port	= self.reply_port
		payload.count	= len(file_system)
		payload.bytes	= len(file_system)

		## Retrieve message id address
		fid, address	= self.get_message()
		self.write_direct(self.address, header, payload)
			
	def handle_PING_RPL(self):
		"""
		PING replies

		"""
		
		## Decode payload
		self.payload	= GnutellaPingRpl(self.raw_data)

		## Cache address and port
		address		= (self.payload.addr, self.payload.port)
		data		= (self.payload.count, self.payload.bytes)

		self.remember_servent(address, data)

		## Try to forward? Local origin messages are tagged with
		## a "localhost" in the msg_cache address field
		fid, address	= self.get_message()

		## Do nothing for local targeted messages
		if address == "localhost":
			return

		if not address:
			return	# misroute

		## Write reply path
		self.write_direct(address, self.header, self.raw_data)
			
	def handle_PUSH(self):
		""" PUSH requests

		The msg_id has to be cached to pass verify_mid()
		The pushid has to be cached to pass this method.

		"""
		
		## Decode payload
		self.payload	= GnutellaPush(self.raw_data)

		fid, address	= self.get_message(self.payload.pushid)

		## Do nothing for local targeted messages (?? for PUSHES?)
		if address == "localhost":
			return

		if not address:
			return	# misroute

		## Write reply path
		self.write_direct(address, self.header, self.raw_data)

	def handle_QUERY(self):
		""" QUERY requests
		
		Search the cached file system for matching files, and
		reply accordingly. Rebroadcast the message.
		
		"""
		
		## Decode payload
		self.payload	= GnutellaQuery(self.raw_data)

		## Rebroadcast
		self.broadcast(self.header, self.raw_data,
			exclude = self.address)

		## Seach the files
		search	= FileSearch(file_system)
		
		for item in string.split(self.payload.search, " "):
			if not item:
				continue

			search.glob("*" + item + "*")

		## No matches?
		if not len(search.files):
			return

		## Build payload
		payload		= GnutellaQueryRpl()
		payload.addr	= inet_aton(self.reply_host)
		payload.port	= self.reply_port
		payload.speed	= self.reply_speed
		payload.pushid	= unique()

		## Create record list
		for index, name, size in search.matches():
			item		= GnutellaQueryRec()
			item.index	= index
			item.size	= size
			item.name	= name

			payload.records.append(item)

		## Build reply header
		header		= GnutellaHeader()
		header.mid	= self.header.mid
		header.fid	= gnutella_query_rpl
		header.ttl	= self.header.hops

		## Reply down the pipe
		self.write_direct(self.address, header, payload)

	def handle_QUERY_RPL(self):
		"""
		PING replies

		"""
		
		## Decode payload
		self.payload	= GnutellaQueryRpl(self.raw_data)

		## Try to forward? Local origin messages are tagged with
		## a "localhost" in the msg_cache address field
		fid, address	= self.get_message()

		## Do nothing for local targeted messages
		if address == "localhost":
			return

		if not address:
			return	# misroute

		## Save push id
		self.remember_message(self.payload.pushid,
			(gnutella_query_rpl, self.address))

		## Write reply path
		self.write_direct(address, self.header, self.raw_data)
			
class GnutellaHeader:
	encode_format	= "<16sBBBi"
	decode_format	= "<16sBBBi"

	def __init__(self, data = None):
		self.reset()
		
		if data:
			self.decode(data)
			
	def __repr__(self):
		return "id=%s ttl=%s hops=%s" % (
			hex(self.fid),
			self.ttl,
			self.hops,
		)
		
	def __str__(self):
		return self.__repr__()
	
	def reset(self):
		global ttl_default
	
		self.mid	= "\0" * 16
		self.fid	= 0x00		
		self.ttl	= 0x00
		self.hops	= 0x00		
		self.dlen	= 0x00000000

		## Evil packets
		self.evil	= 0
		
	def encode(self):
		data	= struct.pack(
			self.encode_format,
			self.mid,
			self.fid,
			self.ttl,
			self.hops,
			self.dlen,
		)

		return data
		
	def decode(self, data):
		data	= struct.unpack(self.decode_format, data)
		
		self.mid	= data[0]
		self.fid	= data[1]
		self.ttl	= data[2]
		self.hops	= data[3]
		self.dlen	= data[4]

		return self			

class GnutellaPayloadBase:
	def __init__(self, data = None):
		self.reset()
		self.decode(data)
	def __repr__(self):
		return ""
	def __str__(self):
		return self.__repr__()
	def reset(self):
		return
	def encode(self):
		return ""
	def decode(self, data):
		return
	def checksize(self, format, data):
		""" Check formatting size
		
		Decoding data is done based on a format string, but if the
		length of the payload is not the same as the length of
		the decoded format string, then unpacking will fail.
		
		This should NEVER happen, and means that the sent data is
		invalid, and the packet should be dropped.
		"""
		
		return (struct.calcsize(format) == len(data))

class GnutellaPing(GnutellaPayloadBase):
	""" Ping messages should NEVER contain data in the payload
	
	FunctionID:	0x00

	Payload:	None
	
	Replies:	0x01
	
	"""
	pass
		
class GnutellaPingRpl(GnutellaPayloadBase):
	""" Ping replies
	
	FunctionID:	0x01

	Payload:	0x0000 		port
			0x00000000	host
			0x00000000	number of files
			0x00000000	total file size
			
	Replies:	None
	"""
	
	encode_format		= "<hiII"
	decode_format		= "<hiII"

	def __init__(self, data = None):
		self.reset()
		self.decode(data)
	
	def __repr__(self):
		return "addr=%s:%d count=%d bytes=%d" % (
			inet_ntoa(self.addr),
			self.port,
			self.count,
			self.bytes,
		)
		
	def reset(self):
		self.port	= 0x0000
		self.addr	= 0x00000000
		self.count	= 0x00000000
		self.bytes	= 0x00000000
		
		## Is this an evil packet?
		self.evil	= 0

	def encode(self):
		return struct.pack(
			self.encode_format,
			self.port,
			self.addr,
			self.count,
			self.bytes,
		)
		
	def decode(self, data = None):
		if not data:
			return self
		if not self.checksize(self.decode_format, data):
			self.evil	= 1
			return self
			
		data	= struct.unpack(self.decode_format, data)
		
		self.port	= data[0]
		self.addr	= data[1]
		self.count	= data[2]
		self.bytes	= data[3]
		
		return self			

class GnutellaPush(GnutellaPayloadBase):
	""" Push requests
	
	FunctionID:	0x40

	Payload:	\000 * 16	unique id
			0x00000000	index
			0x00000000	address
			0x0000		port
			
	Replies:	None
	"""
	
	encode_format	= "<16sIih"
	decode_format	= "<16sIih"

	def __repr__(self):
		return "index=%d addr=%s:%d" % (
			self.index,
			inet_ntoa(self.addr),
			self.port,
		)
	
	def reset(self):
		self.pushid	= "\0" * 16
		self.index	= 0x00000000
		self.addr	= 0x00000000
		self.port	= 0x0000
		
		## Is this an evil packet?
		self.evil	= 0
		
	def encode(self):
		return struct.pack(
			self.encode_format,
			self.pushid,
			self.index,
			self.addr,
			self.port,
		)
		
	def decode(self, data = None):
		if not data:
			return self
		if not self.checksize(self.decode_format, data):
			self.evil	= 1
			return self
			
		data	= struct.unpack(self.decode_format, data)
		
		self.pushid	= data[0]
		self.index	= data[1]
		self.addr	= data[2]
		self.port	= data[3]

		return self			

class GnutellaQuery(GnutellaPayloadBase):
	""" Query request
	
	FunctionID:	0x80
	
	Payload:	
			0x0000		minimum speed
			0x00+		search criteria, \0 terminated
			
		Currently, a very basic search syntax is supported. This
		should be expanded as soon as possible.
		
		Possibly the IMAPv4 search syntax would be used, as it is
		concise, powerful, and well established. See rfc2060.
		
		More possibly, the protocol should be overhauled and version
		tracking implemented per message.
	
	Replies:	0x81
	
	"""

	encode_format		= "<H%ss"
	decode_format		= "<H%ss"
	
	## see non-standard decode() !!!

	def __repr__(self):
		return "speed=%d search=%s" % (
			self.speed,
			repr(self.search),
		)
	
	def reset(self):
		self.speed	= 0x0000
		self.search	= ""
		
		## Is this an evil packet?
		self.evil	= 0

	def encode(self):
		null_pos	= string.find(self.search, "\0")

		if null_pos != -1:
			tmp_data = self.search[:null_pos] + "\0"
		else:
			tmp_data = self.search + "\0"
	
		return struct.pack(
			self.encode_format % len(tmp_data),
			self.speed,
			tmp_data,
		)
		
	def decode(self, data = None):
		if not data:
			return self
			
		## Strip ending \0
		nlen	= len(data) - struct.calcsize("<H")

		if not self.checksize(self.decode_format % nlen, data):
			self.evil	= 1
			return self

		data	= struct.unpack(self.decode_format % nlen, data)
		
		self.speed	= data[0]
		self.search	= data[1]

		null_pos	= string.find(self.search, "\0")

		if null_pos != -1:
			self.search	= self.search[:null_pos]

		return self			

class GnutellaQueryRec(GnutellaPayloadBase):
	""" Query reply
	
	FunctionID:	0x81
	
	Payload:	
	
		Contains at least 1 hit set and 1+ hit entries
	
	One hit:
			0x00000000	index number
			0x00000000	file size
			0x00+		file name, double \0 terminated

	"""

	encode_format		= "<II%ss"
	decode_format		= "<II%ss"

	def __repr__(self):
		return "index=%d size=%d name=%s" % (
			self.index,
			self.size,
			repr(self.name),
		)
	
	def reset(self):
		self.index	= 0x00000000
		self.size	= 0x00000000
		self.name	= ""
		
		## Is this an evil packet?
		self.evil	= 0

	def encode(self):
		null_pos	= string.find(self.name, "\0")

		if null_pos != -1:
			tmp_data = self.name[:null_pos] + "\0\0"
		else:
			tmp_data = self.name + "\0\0"
	
		return struct.pack(
			self.encode_format % len(tmp_data),
			self.index,
			self.size,
			tmp_data,
		)
		
	def decode(self, data = None):
		if not data:
			return self
			
		## Find the \0\0 starting at 8
		npos	= len(data) - 8
		
		if npos < 0:
			self.evil	= 1
			return self

		if not self.checksize(self.decode_format % npos, data):
			self.evil	= 1
			return self

		data	= struct.unpack(self.decode_format % npos, data)
		
		self.index	= data[0]
		self.size	= data[1]
		self.name	= data[2]

		null_pos	= string.find(self.name, "\0")

		if null_pos != -1:
			self.name = self.name[:null_pos]

		return self			

class GnutellaQueryRpl(GnutellaPayloadBase):
	""" Push requests
	
	FunctionID:	0x81

	Payload:	0x00		number of records
			0x0000		port of sender
			0x00000000	address of sender
			0x00000000	speed of sender
			0x00 +		series of records
			\000 * 16	senders unique id
			
	Replies:	None
	"""
	
	encode_format		= "<BhiI%ss16s"
	decode_format		= "<BhiI%ss16s"
	
	## see non-standard decode below!

	def __repr__(self):
		return "total=%d addr=%s:%d speed=%d" % (
			self.num,
			inet_ntoa(self.addr),
			self.port,
			self.speed,
		)
	
	def reset(self):
		self.num	= 0x00
		self.port	= 0x0000
		self.addr	= 0x00000000
		self.speed	= 0x00000000
		self.results	= ""
		self.pushid	= "\0" * 16

		## Parsed records
		self.records	= []
		
	def encode(self):
		self.results	= ""
		self.num	= len(self.records)

		for item in self.records:
			self.results	 = self.results + item.encode()

		return struct.pack(
			self.encode_format % len(self.results),
			self.num,
			self.port,
			self.addr,
			self.speed,
			self.results,
			self.pushid,
		)
		
	def decode(self, data = None):
		if not data:
			return self
			
		## Find the ranges
		npos	= len(data) - struct.calcsize("<BhiI16s")

		if not self.checksize(self.decode_format % npos, data):
			self.evil	= 1
			return self

		data	= struct.unpack(self.decode_format % npos, data)
		
		self.num	= data[0]
		self.port	= data[1]
		self.addr	= data[2]
		self.speed	= data[3]
		self.results	= ""
		self.pushid	= data[5]

		## Decode the records
		tmp		= data[4]
		self.records	= []

		while len(tmp):
	 		pos	= string.find(tmp[8:], "\0\0") + 8 + 2

			self.records.append(GnutellaQueryRec(tmp[:pos]))
			tmp	= tmp[pos:]

		return self			

	
##
## Get correct syntax for commands
##	

def format_ping():
	## Send a login ping
	payload		= GnutellaPing()

	header		= GnutellaHeader()
	header.mid	= unique()
	header.fid	= gnutella_ping
	header.ttl	= GnutellaConnectBase.ttl_max
	header		= header.encode()
	
	return (header, payload)

def format_query(speed, search):
	## Send a login ping
	payload		= GnutellaQuery()
	payload.speed	= int(speed)
	payload.search	= search

	header		= GnutellaHeader()
	header.mid	= unique()
	header.fid	= gnutella_ping
	header.ttl	= GnutellaConnectBase.ttl_max
	header		= header.encode()
	
	return (header, payload)


class GnutellaStdin:
	def __init__(self):
		self.servent	= None
		
	def handle(self):
		try:
			while (1):
				self.handle_read()
		except SystemExit:
			pass
		except KeyboardInterrupt:
			pass
			
	def handle_read(self):
		data	= sys.stdin.readline()
		data	= string.strip(string.lower(data))
		data	= string.split(data, " ")

		if data[0] == "query":
			self.handle_query(data)
			return
			
		if data[0] == "listen":
			self.handle_listen(data)
			return
			
		if data[0] == "open":
			thread.start_new_thread(self.handle_open, (data,))
			return
			
		if data[0] == "close":
			thread.start_new_thread(self.handle_close, (data,))
			return
			
		if data[0] == "quit" or data[0] == "exit":
			self.handle_quit()
			return
			
		if data[0] == "save":
			self.handle_save(data)
			return
			
		if data[0] == "load":
			self.handle_load(data)
			return
			
		if data[0] == "stat":
			self.handle_stat()
			return
			
		if data[0] == "quiet":
			global quiet
			quiet	= (not quiet)
			return
			
		if data[0] == "ping":
			ping_network()
			return
			
		if data[0] == "dump":
			print "-" * 80
			print "Servent Cache"
			print ""
			
			for ip, port in servent_cache.keys():
				print inet_ntoa(ip), repr(ip), port
			
			print ""
			return
			
		## Invalid
		log_error("Unknown command: %s\n" % data[0])
		
	def handle_query(self, data):
		if not data[1:]:
			log_error("Not enough arguments\n")
			return
			
		search		= string.join(data[1:])
		header, payload	= format_query(0, search)
		
		payload		= payload.encode()
		header.dlen	= len(payload)
		message		= header.encode() + payload
		
		
		for item, wfile in GnutellaHTTPRequestHandler.open_links.items():
			try:
				wfile.write(message)
			except:
				log_error("Unable to write: %s\n" % item)
		
	def handle_save(self, data):
		if not data[1:]:
			path	= "gnutella.net"
		else:
			path	= string.join(data[1:])
			
		try:
			file	= open(path, "w")
		except IOError, why:
			log_error("%s\n" % why)
			return
			
		for addr, port in servent_cache.keys():
			file.write("%s:%s\n" % (inet_ntoa(addr), port))
				
		log_info("Saved net file to %s\n" % path)

	def handle_load(self, data):
		if not data[1:]:
			path	= "gnutella.net"
		else:
			path	= string.join(data[1:])
			
		try:
			file	= open(path, "r")
		except IOError, why:
			log_error("%s\n" % why)
			return
			
		servent_cache.clear()
		
		for item in file.readlines():
			if not item:
				continue
				
			addr, port	= string.split(item, ":")
			addr		= inet_aton(addr)
			port		= int(port)
			
			remember_servent((addr, port, 0, 0))

		log_info("Loaded net file from %s\n" % path)

	def handle_listen(self, data):
		""" Listen for connections
		
		Usage: listen (port)
		
		"""
		
		if not data[1:]:
			log_error("No port given\n" )
			return
			
		## Try of listen
		addr	= socket.gethostbyname(socket.gethostname())
		port	= int(data[1])
		
		try:
			servent	= GnutellaHTTPServer(
				(addr, port),
				GnutellaRequestHandler,
			)
		except:
			log_error("Unable to listen\n")
			traceback.print_exc()
		else:
			log_info("Listening: %s:%s\n" % (addr, port))
			
			thread.start_new_thread(servent.serve_forever, ())
			
	def handle_open(self, data):
		""" Open a connection to another servent
		
		Syntax: open (host|ip) (port)
		
		Note that the "listen" command must be called before this,
		since the system server handles both incoming and outgoing
		connections.
		
		"""

		if not data[1:] and not len(servent_cache):
			log_error("No host given, nothing in cache\n")
			return

		if not data[1:]:
			item	= whrandom.choice(servent_cache.keys())
			addr, port	= item
			addr	= inet_ntoa(addr)
		elif not data[2:]:
			addr	= data[1]
			port	= 6346
		else:
			addr	= data[1]
			port	= int(data[2])

		open_servent((addr, port), GnutellaRequestHandler)

	def handle_close(self, data):
		pass
		
	def handle_quit(self):
		raise SystemExit
		
	def handle_stat(self):

		return
		global message_count
		global stat_data
	
		total	= len(stat_data)
	
		## Print stats
		for item, value in stat_data.items():
			sys.stdout.write("STAT %s %s %s %s\n" %
				(total, hex(item), value, message_count))
		
class GnutellaMaintain:
	## Default number of links to keep open
	maintain_open	= 5

	def __init__(self):
		while (1):
			num	= len(GnutellaConnectBase.open_links)
			min	= self.maintain_open

			if num < min:
				try:
					self.open_new()
				except (SystemExit, KeyboardInterrupt):
					break
				except:
					continue

			time.sleep(10)

	def open_new(self):
		order	= GnutellaConnectBase.servent_order

		if not len(order):
			return

		address, port	= whrandom.choice(order)
		address		= inet_ntoa(address)
		
		thread.start_new_thread(open_servent, ((address, port),))
		# Done.
		

	def exists(self, addr):
		clients	= GnutellaConnectBase.open_links

		for item in clients.keys():
			if item[0] == addr:
				return 1

		return 0

##
## Final things to do when importing
##

file_system		= FileIndex()

##
##
##

##
## Running __main__ ?
##

command_help = \
"""Usage: %s -o ip[:port] [args ...]

Command-line arguments:
	-h, --help		this help page
	-s, --stdin		accept input from the stdin
	-t, --terminal		start a full terminal emulation session
	-l, --listen PORT	start a gnutella/http server [default=6346]
	-o, --open IP:PORT	open a full gnutellanet connection
	-m, --monitor IP:PORT	open a monitoring only connection
	-n, --maintain NUM	number of connection to keep open

File system options:
	-i, --index PATH	index directory
	-r, --recurse PATH	index directory, recursive

More controlling options are:
	--set-localip IP:PORT	local ip and port to use in replies
	--set-speed NUM		local speed to use in query replies
"""

if __name__ == "__main__":
	## Program name
	name	= os.path.basename(sys.argv[0])
	
	if not sys.argv[1:]:
		sys.exit(command_help % name)
		
	## Short/long version
	short	= "hstl:o:m:n:i:r:"
	long	= [
		"help",
		"console",
		"listen=",
		"open=",
		"monitor=",
		"maintain=",
		"index=",
		"recurse=",
		"set-localip=",
		"set-speed=",
	]
		
	import getopt
	
	try:
		options, parms	= getopt.getopt(sys.argv[1:], short, long)
	except getopt.error, why:
		sys.exit("%s: %s" % (name, why))
		
	
	USE_TERMINAL	= 0
	USE_STDIN	= 0
	
	
	for flag, data in options:
		global USE_TERMINAL, USE_STDIN
		
		if flag == "-s" or flag == "--sdtin":
			if USE_TERMINAL:
				sys.exit("%s: unable to start both a " + \
					 "stdin and terminal session" % name)
			else:
				USE_STDIN	= 1
			
	
		if flag == "-t" or flag == "--terminal":
			if USE_STDIN:
				sys.exit("%s: unable to start both a " + \
					 "stdin and terminal session" % name)
			else:
				USE_TERMINAL	= 1
			
	
		## help
		if flag == "-h" or flag == "--help":
			sys.stdout.write(command_help % name)
			sys.exit()
	
		## -l, --listen [port]
		if flag == "-l" or flag == "--listen":
			if not data:
				data	= 6346	# default port
			
			try:
				data	= int(data)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			try:
				server	= GnutellaHTTPServer(
					("", data),
					GnutellaHTTPRequestHandler,
				)
			except socket.error, (error, why):
				sys.exit("%s: listen: %s" % (name, why))
			else:
				sys.stdout.write("%s: listening on %s\n" %
					(name, data))
			thread.start_new_thread(server.serve_forever, ())
			continue
			
		## Maintain flag
		if flag == "-n" or flag == "--maintain":
			try:
				data	= int(data)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			GnutellaMaintain.maintain_open	= data
			continue
			
		## Local ip flag
		if flag == "--set-localip":
			try:
				ip, port	= re.split(":", data, 1)
			except ValueError, why:
				sys.exit("%s: %s" % (name, port))
			
			try:
				port	= int(port)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			GnutellaConnectBase.reply_host	= ip
			GnutellaConnectBase.reply_port	= port
			continue
				
		## Maintain flag
		if flag == "--set-speed":
			try:
				data	= int(data)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			GnutellaConnectBase.reply_speed	= data
			continue
			
		## Index
		if flag == "-i" or flag == "--index":
			data	= string.strip(data)
			handler	= GnutellaHTTPRequestHandler
			
			try:
				handle.file_system.index(item)
			except (IOError, OSError), (error, why):
				sys.exit("%s: %s" % (name, why))
			continue
			
		## Recurse
		if flag == "-r" or flag == "--recurse":
			data	= string.strip(data)
			handler	= GnutellaHTTPRequestHandler
			
			try:
				handle.file_system.recurse(item)
			except (IOError, OSError), (error, why):
				sys.exit("%s: %s" % (name, why))
			continue
				
		## Open active connection
		if flag == "-o" or flag == "--open":
			try:
				ip, port	= re.split(":", data, 1)
			except ValueError, why:
				ip, port	= data, 6347
			
			try:
				port	= int(port)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			try:
				open_servent((ip, port))
			except socket.error, why:
				sys.exit("%s: open %s:%s: %s" %
					(name, ip, port, why))
			continue
	
		## Open monitor connection
		if flag == "-m" or flag == "--monitor":
			try:
				ip, port	= re.split(":", data, 1)
			except ValueError, why:
				ip, port	= data, 6347
			
			try:
				port	= int(port)
			except ValueError, why:
				sys.exit("%s: %s" % (name, why))
			
			try:
				open_servent((ip, port))
			except socket.error, why:
				sys.exit("%s: monitor %s:%s: %s" %
					(name, ip, port, why))
			continue
	
		## Done arguments
	
	## Begin maintaining connections
	thread.start_new_thread(GnutellaMaintain, ())

	## Start a console?
	if USE_STDIN:
		stdin	= GnutellaStdin()
		stdin.handle()
		sys.exit(1)
	
	## Okay, loop
	try:
		while 1:
			time.sleep(5)
	except:
		data	= GnutellaConnectBase.stat_data
		
		for item, count in data.items():
			print "STAT fid=%s count=%s" % (hex(item), count)
		
		

