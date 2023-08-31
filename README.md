# gnutellalib

Legacy import of a Google Code project

## Description

This is an old Python project, also from the late 1990's, that provides a command line interface to the Gnutella file-sharing protocol.

http://code.google.com/p/ianzepp/source/browse/trunk/gnutellalib SVN Source Tree

## Original Documentation

Gnutalla library and console monitor

Version and contact info is after this docstring.

This file contains a large number of classes designed to make monitoring and
searching the gnutella network easier, as well as a complete gnutella daemon
for running in the background.

## Daemon usage:

This library can be run as a forking background process. Example usage:

```
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
```

Note that if the --console option is NOT given, then the program will simply
connect to the network and try to maintain links.

## Library usage:

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

```
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
```

## Issues:

1. Only internet IP's addresses are recognized as valid.
2. The load/save commands have issues.
3. Dropped packets are not counted
4. No http server implemented for file retrieval
6. The --listen ip is the one used for ping and query replies.
		

## Protocol fixes:

These are just ideas for protocol fixes. These are NOT the current protocol structures.

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

