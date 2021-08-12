/++
	Standalone Mongo driver implementation.

	Copyright: 2020 Symmetry Investments with portion (c) 2012-2016 Nicolas Gurrola
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
+/
module kaleidic.mongo_standalone;

import std.array;
import std.bitmanip;
import std.socket;

static immutable string mongoDriverName = "mongo-standalone";
static immutable string mongoDriverVersion = "0.0.9";

// just a demo of how it can be used
version(Demo)
void main() {

	/+
	string omg;
	foreach(a; 0 .. 8000)
		omg ~= "a";


		document doc1 = document([
			bson_value("foo", 12),
			bson_value("bar", 12.4),
			bson_value("baz", 12L),
			bson_value("faz", omg),
			bson_value("eaz", RegEx("asdasdsa", "i")),
			bson_value("asds", null),
			bson_value("sub", document([
				bson_value("sub1", 12)
			])),
		]);
		+/

	//auto connection = new MongoConnection("mongodb://testuser:testpassword@localhost/test?slaveOk=true");
	auto connection = new MongoConnection("mongodb://localhost/test?slaveOk=true", "testuser", "testpassword");

	connection.update("test.world", true, false, document([bson_value("_id", ObjectId("5ef17aea55c0abb51fbb53bc"))]),
		document([
			//bson_value("_id", ObjectId("5ef17aea55c0abb51fbb53bc")),
			bson_value("replaced","true")
		])
	);

	//connection.insert(false, "test.world", [doc1]);

	import std.stdio;
	//writeln(connection.query(0, "world", 0, 1, document.init));
	auto answer = connection.query("test.world", 35, 1, document.init, document.init, 1);
	writeln(answer);
}

enum QueryFlags {
	TailableCursor = (1 << 1),
	SlaveOk = (1 << 2),
	NoCursorTimeout = (1 << 4),
	AwaitData = (1 << 5),
	Exhaust = (1 << 6),
	Partial = (1 << 7)
}

/// Server Wire version indicating supported features
/// $(LINK https://github.com/mongodb/specifications/blob/master/source/wireversion-featurelist.rst)
enum WireVersion {
	/// Pre 2.6 (-2.4)
	old = 0,
	/// Server version 2.6
	v26 = 1,
	/// Server version 2.6
	v26_2 = 2,
	/// Server version 3.0
	v30 = 3,
	/// Server version 3.2
	v32 = 4,
	/// Server version 3.4
	v34 = 5,
	/// Server version 3.6
	v36 = 6,
	/// Server version 4.0
	v40 = 7,
	/// Server version 4.2
	v42 = 8,
}

class MongoConnection {

	Socket socket;
	IReceiveStream stream;

	uint defaultQueryFlags;

	/// Reported minimum wire version by the server
	WireVersion minWireVersion;
	/// Reported maximum wire version by the server
	WireVersion maxWireVersion;

	private document handshake(string authDatabase, string username,
			document application) {
		import std.compiler : compilerName = name, version_major, version_minor;
		import std.conv : text, to;
		import std.system : os;

		auto dbcmd = authDatabase ~ ".$cmd";

		static immutable osType = os.to!string;

		version (X86_64)
			static immutable osArchitecture = "x86_64";
		else version (X86)
			static immutable osArchitecture = "x86";
		else version (ARM)
			static immutable osArchitecture = "arm";
		else version (PPC64)
			static immutable osArchitecture = "ppc64";
		else version (PPC)
			static immutable osArchitecture = "ppc";
		else
			static assert(false, "no name for this architecture");

		static immutable platform = text(compilerName, " v", version_major, ".", version_minor);

		bson_value[] client;
		if (application.length)
		{
			auto name = application["name"];
			if (name == bson_value.init)
				throw new Exception("Given application without name");
			// https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.rst#limitations
			if (name.toString().length > 128)
				throw new Exception("Application name must not exceed 128 bytes");

			client ~= bson_value("application", application);
		}

		client ~= [
			bson_value("driver", document([
				bson_value("name", mongoDriverName),
				bson_value("version", mongoDriverVersion)
			])),
			bson_value("os", document([
				bson_value("type", osType),
				bson_value("architecture", osArchitecture)
			])),
			bson_value("platform", platform)
		];

		auto cmd = [
			bson_value("isMaster", 1),
			bson_value("client", document(client))
		];
		if (username.length)
			cmd ~= bson_value("saslSupportedMechs", authDatabase ~ "." ~ username);

		auto reply = query(dbcmd, 0, -1, document(cmd));
		if (reply.documents.length != 1 || reply.documents[0]["ok"].get!double != 1)
			throw new Exception("MongoDB Handshake failed");

		return reply.documents[0];
	}

	private void authenticateScramSha1(string authDatabase, string username,
			string password) {
		auto dbcmd = authDatabase ~ ".$cmd";

		bson_value conversationId;

		ScramState state;

		ubyte[] payload = cast(ubyte[]) state.createInitialRequest(username);

		auto cmd = document([
			bson_value("saslStart", 1),
			bson_value("mechanism", "SCRAM-SHA-1"),
			bson_value("payload", payload),
			bson_value("options", document([
				bson_value("skipEmptyExchange", true)
			]))
		]);


		auto firstReply = query(dbcmd, 0, -1, cmd);
		if(firstReply.documents.length != 1 || firstReply.documents[0]["ok"].get!double != 1)
			throw new Exception("Auth failed at first step (username)");

		conversationId = cast(bson_value) firstReply.documents[0]["conversationId"];

		auto response = firstReply.documents[0]["payload"].get!(const(ubyte[]));
		
		const digest = makeDigest(username, password);

		payload = cast(typeof(payload)) state.update(digest, cast(string) response);

		cmd = document([
			bson_value("saslContinue", 1),
			bson_value("conversationId", conversationId),
			bson_value("payload", payload)
		]);

		auto secondReply = query(dbcmd, 0, -1, cmd);
		if(secondReply.documents.length != 1)
			throw new Exception("Auth error at second step");

		if(secondReply.documents[0]["ok"].get!double != 1)
			throw new Exception("Auth failed at second step (password)");

		auto response2 = secondReply.documents[0]["payload"].get!(const(ubyte[]));

		payload = cast(typeof(payload)) state.finalize(cast(string) response2);

		// newer servers can save a roundtrip (they know the password here already)
		if(secondReply.documents[0]["done"].get!bool)
			return;

		cmd = document([
			bson_value("saslContinue", 1),
			bson_value("conversationId", conversationId),
			bson_value("payload", payload)
		]);

		auto finalReply = query(dbcmd, 0, -1, cmd);
		if(finalReply.documents.length != 1)
			throw new Exception("Auth error at final step");

		if(finalReply.documents[0]["ok"].get!double != 1)
			throw new Exception("Auth failed at final step");

		if(!finalReply.documents[0]["done"].get!bool)
			throw new Exception("Authentication didn't respond 'done'");
	}

	/++
		Connects to a Mongo database. You can give a username and password in the
		connection string if URL encoded, OR you can pass it as arguments to this
		constructor.

		Please note that username/password in the connectionString will OVERRIDE
		ones given as separate arguments.
	+/
	this(string connectionString, string defaultUsername = null, string defaultPassword = null) {
		import std.uri : decodeComponent;
		import std.string;

		auto uri = Uri(connectionString);

		if(uri.hosts.length == 0)
			throw new Exception("no host given in connection string");

		foreach(ref p; uri.hosts) {
			if(p.port == 0)
				p.port = 27017;
		}

		string host = decodeComponent(uri.hosts[0].host);
		if(host.length == 0)
			host = "localhost";

		// FIXME: break up the host into the list and at least
		// pretend to care about replication sets

		string authDb = "admin";
		string appName;

		string username = defaultUsername;
		string password = defaultPassword;

		auto split = uri.userinfo.indexOf(":");
		if(split != -1) {
			username = decodeComponent(uri.userinfo[0 .. split]);
			password = decodeComponent(uri.userinfo[split + 1 .. $]);
		}
		if(uri.path.length > 1)
			authDb = uri.path[1 .. $];

		bool ssl;

		foreach(part; uri.query.splitter("&")) {
			split = part.indexOf("=");
			auto name = decodeComponent(part[0 .. split]);
			auto value = decodeComponent(part[split + 1 .. $]);

			// https://docs.mongodb.com/manual/reference/connection-string/#connections-connection-options
			switch(name) {
				case "slaveOk": defaultQueryFlags |= QueryFlags.SlaveOk; break;
				case "appName": appName = value; break;
				case "authSource": authDb = value; break;
				case "tls", "ssl": ssl = value == "true"; break;
				default: throw new Exception("Unsupported mongo db connect option: " ~ name);
			}
		}

		if(host[0] == '/') {
			version(Posix) {
				socket = new Socket(AddressFamily.UNIX, SocketType.STREAM);
				socket.connect(new UnixAddress(host));
			} else throw new Exception("Cannot use unix socket on Windows at this time");
		} else {
			if(ssl)
				throw new Exception("ssl/tls connections not supported by this driver");
			socket = new TcpSocket(new InternetAddress(host, cast(ushort) uri.hosts[0].port));
		}

		stream = new SocketReceiveStream(socket);

		document appArgs;
		if (appName.length)
			appArgs = document([bson_value("name", appName)]);
		auto handshakeResponse = handshake(authDb, username, appArgs);

		minWireVersion = cast(WireVersion)handshakeResponse["minWireVersion"].get!int;
		maxWireVersion = cast(WireVersion)handshakeResponse["maxWireVersion"].get!int;

		bool supportsScramSha1 = maxWireVersion >= WireVersion.v30;
		bool supportsScramSha256 = maxWireVersion >= WireVersion.v40;

		auto saslSupportedMechs = handshakeResponse["saslSupportedMechs"];
		if (saslSupportedMechs != bson_value.init) {
			auto arr = saslSupportedMechs.get!(const(bson_value)[]);
			supportsScramSha1 = false;
			supportsScramSha256 = false;
			foreach (v; arr) {
				switch (v.toString) {
				case "SCRAM-SHA-1":
					supportsScramSha1 = true;
					break;
				case "SCRAM-SHA-256":
					supportsScramSha256 = true;
					break;
				default:
					// unsupported mechanism
					break;
				}
			}
		}

		// https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst#supported-authentication-methods
		if (username.length) {
			// TODO: support other (certificate based) authentication mechanisms

			// TODO: SCRAM-SHA-256 support
			// if (supportsScramSha256) {
			// } else
			if (supportsScramSha1) {
				authenticateScramSha1(authDb, username, password);
			} else {
				if (maxWireVersion < WireVersion.v30)
					throw new Exception("legacy MONGODB-CR authentication not implemented");
				else
					throw new Exception(
						"Cannot authenticate because no common authentication mechanism could be found.");
			}
		}
	}

	void update(const(char)[] fullCollectionName, bool upsert, bool multiupdate, document selector, document update) {
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.UPDATE;

		SendBuffer sb;

		sb.add(header);

		int zero;
		sb.add(zero);

		sb.add(fullCollectionName);
		int flags;
		if(upsert) flags |= 1;
		if(multiupdate) flags |= 2;
		sb.add(flags);
		sb.add(selector);
		sb.add(update);

		send(sb.data);
	}

	void insert(bool continueOnError, const(char)[] fullCollectionName, document[] documents) {
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.INSERT;

		SendBuffer sb;

		sb.add(header);

		int flags = continueOnError ? 1 : 0;
		sb.add(flags);
		sb.add(fullCollectionName);
		foreach(doc; documents)
			sb.add(doc);

		send(sb.data);
	}

	OP_REPLY getMore(const(char)[] fullCollectionName, int numberToReturn, long cursorId, int limitTotalEntries = int.max) {
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.GET_MORE;

		SendBuffer sb;

		sb.add(header);

		int zero;
		sb.add(zero);
		sb.add(fullCollectionName);
		sb.add(numberToReturn);
		sb.add(cursorId);

		send(sb.data);
		
		auto reply = stream.readReply();

		reply.numberToReturn = numberToReturn;
		reply.fullCollectionName = fullCollectionName;
		reply.current = 0;
		reply.connection = this;

		return reply;
	}

	void delete_(const(char)[] fullCollectionName, bool singleRemove, document selector) {
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.DELETE;

		SendBuffer sb;

		sb.add(header);

		int zero;
		sb.add(0);
		sb.add(fullCollectionName);
		int flags = singleRemove ? 1 : 0;
		sb.add(flags);
		sb.add(selector);

		send(sb.data);
	}

	void killCursors(const(long)[] cursorIds) {
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.KILL_CURSORS;

		SendBuffer sb;

		sb.add(header);
		int zero = 0;
		sb.add(zero);

		sb.add(cast(int) cursorIds.length);
		foreach(id; cursorIds)
			sb.add(id);

		send(sb.data);
	}

	OP_REPLY query(const(char)[] fullCollectionName, int numberToSkip, int numberToReturn, document query, document returnFieldsSelector = document.init, int flags = 1, int limitTotalEntries = int.max) {
		if(flags == 1)
			flags = defaultQueryFlags;
		MsgHeader header;

		header.requestID = ++nextRequestId;
		header.opCode = OP.QUERY;

		SendBuffer sb;

		sb.add(header);

		sb.add(flags);
		sb.add(fullCollectionName);
		sb.add(numberToSkip);
		sb.add(numberToReturn);
		sb.add(query);

		if(returnFieldsSelector != document.init)
			sb.add(returnFieldsSelector);

		send(sb.data);
		
		auto reply = stream.readReply();

		reply.numberToReturn = numberToReturn;
		reply.limitRemaining = limitTotalEntries;
		reply.fullCollectionName = fullCollectionName;
		reply.current = 0;
		reply.connection = this;

		return reply;
	}

	private int nextRequestId;

	private void send(const(ubyte)[] data) {
		while(data.length) {
			auto ret = socket.send(data);
			if(ret <= 0)
				throw new Exception("wtf");
			data = data[ret .. $];
		}
	}
}

unittest {
	auto uri = Uri("mongo://test:12,foo:14/");
	assert(uri.hosts.length == 2);
	assert(uri.hosts[0] == UriHost("test", 12));
	assert(uri.hosts[1] == UriHost("foo", 14));
}

interface IReceiveStream {
	final OP_REPLY readReply() {
		OP_REPLY reply;


		reply.header.messageLength = readInt();
		reply.header.requestID = readInt();
		reply.header.responseTo = readInt();
		reply.header.opCode = readInt();

		// flag 0: cursor not found. 1: query failure. $err set in a thing.
		reply.responseFlags = readInt();
		reply.cursorID = readLong();
		reply.startingFrom = readInt();
		reply.numberReturned = readInt();

		reply.documents.length = reply.numberReturned;

		foreach(ref doc; reply.documents) {
			doc = readBson();
		}

		return reply;
	}

	final document readBson() {
		document d;
		d.bytesCount = readInt();

		int remaining = d.bytesCount;
		remaining -= 4; // length
		remaining -= 1; // terminating zero

		while(remaining > 0) {
			d.values_ ~= readBsonValue(remaining);
		}

		d.terminatingZero = readByte();
		if(d.terminatingZero != 0)
			throw new Exception("something wrong reading bson");

		return d;
	}

	final bson_value readBsonValue(ref int remaining) {
		bson_value v;

		v.tag = readByte();
		remaining--;

		v.e_name = readZeroTerminatedChars();
		remaining -= v.e_name.length + 1; // include the zero term

		switch(v.tag) {
			case 0x00: // not supposed to exist!
				throw new Exception("invalid bson");
			case 0x01:
				auto d = readDouble();
				remaining -= 8;
				v.x01 = d;
			break;
			case 0x02:
				v.x02 = readCharsWithLengthPrefix();
				remaining -= 5 + v.x02.length; // length and zero
			break;
			case 0x03:
				v.x03 = readBson();
				remaining -= v.x03.bytesCount;
			break;
			case 0x04:
				v.x04 = readBson();
				remaining -= v.x04.bytesCount;
			break;
			case 0x05:
				auto length = readInt();
				v.x05_tag = readByte();
				v.x05_data = readBytes(length);
				remaining -= v.x05_data.length + 5;
			break;
			case 0x06: // undefined
				// intentionally blank, no additional data
			break;
			case 0x07:
				foreach(ref b; v.x07) {
					b = readByte();
					remaining--;
				}
			break;
			case 0x08:
				v.x08 = readByte() ? true : false;
				remaining--;
			break;
			case 0x09:
				v.x09 = readLong();
				remaining -= 8;
			break;
			case 0x0a: // null
				// intentionally blank, no additional data
			break;
			case 0x0b:
				v.x0b_regex = readZeroTerminatedChars();
				remaining -= v.x0b_regex.length + 1;
				v.x0b_flags = readZeroTerminatedChars();
				remaining -= v.x0b_flags.length + 1;
			break;
			case 0x0d:
				v.x0d = readCharsWithLengthPrefix();
				remaining -= 5 + v.x0d.length; // length and zero
			break;
			case 0x10:
				v.x10 = readInt();
				remaining -= 4;
			break;
			case 0x11:
				v.x11 = readLong();
				remaining -= 8;
			break;
			case 0x12:
				v.x12 = readLong();
				remaining -= 8;
			break;
			case 0x13:
				foreach(ref b; v.x13) {
					b = readByte();
					remaining--;
				}
			break;
			default:
				import std.conv;
				assert(0, "unsupported tag in bson: " ~ to!string(v.tag));
		}

		return v;
	}

	final ubyte readByte() {
		return readSmall!1[0];
	}

	final int readInt() {
		return readSmall!4.littleEndianToNative!int;
	}

	final long readLong() {
		return readSmall!8.littleEndianToNative!long;
	}

	final double readDouble() {
		return readSmall!8.littleEndianToNative!double;
	}
	
	final string readZeroTerminatedChars() {
		return cast(string) readUntilNull();
	}

	final string readCharsWithLengthPrefix() {
		auto length = readInt();
		// length prefixed string allows 0 characters
		auto bytes = readBytes(length);
		if (bytes[$ - 1] != 0)
			throw new Exception("Malformed length prefixed string");
		return cast(string)bytes[0 .. $ - 1];
	}

	/// Reads exactly the amount of bytes specified and returns a newly
	/// allocated buffer containing the data.
	final immutable(ubyte)[] readBytes(size_t length) {
		ubyte[] ret = new ubyte[length];
		readExact(ret);
		return (() @trusted => cast(immutable)ret)();
	}

	/// Reads a small number of bytes into a stack allocated array. Convenience
	/// function calling $(LREF readExact).
	ubyte[n] readSmall(size_t n)() {
		ubyte[n] buf;
		readExact(buf[]);
		return buf;
	}

	/// Reads exactly the expected length into the given buffer argument.
	void readExact(scope ubyte[] buffer);

	/// Reads until a 0 byte and returns all data before it as newly allocated
	/// buffer containing the data.
	immutable(ubyte)[] readUntilNull();
}

class SocketReceiveStream : IReceiveStream {
	this(Socket socket) {
		this.socket = socket;
	}

	Socket socket;
	ubyte[4096] buffer;
	// if bufferLength > bufferPos then following data is linear after bufferPos
	// if bufferLength < bufferPos then data is following bufferPos and also from 0..bufferLength
	// if bufferLength == bufferPos then all data is read
	int bufferLength;
	// may only increment until at the end of buffer.length, where it wraps back to 0
	int bufferPos;

	protected ptrdiff_t receiveSocket(ubyte[] buffer) {
		const length = socket.receive(buffer);

		if (length == 0)
			throw new Exception("Remote side has closed the connection");
		else if (length == Socket.ERROR)
			throw new Exception(lastSocketError());
		else
			return length;
	}

	/// Loads more data after bufferPos if there is space, otherwise load before
	/// bufferPos, indicating data is wrapping around.
	void loadMore() {
		if (bufferPos == bufferLength) {
			// we read up all the bytes, start back from 0 for bigger recv buffer
			bufferPos = 0;
			bufferLength = 0;
		}

		ptrdiff_t length;
		if (bufferLength < bufferPos) {
			// length wrapped around before pos
			// try to read up to the byte before bufferPos to not trigger the
			// bufferPos == bufferLength case
			length = receiveSocket(buffer[bufferLength .. bufferPos - 1]);
		} else {
			length = receiveSocket(buffer[bufferLength .. $ - 1]);
		}

		bufferLength += length;
		if (bufferLength == buffer.length)
			bufferLength = 0;
	}

	void readExact(scope ubyte[] dst) {
		if (!dst.length)
			return;

		if (bufferPos == bufferLength)
			loadMore();

		auto end = bufferPos + dst.length;
		if (end < buffer.length) {
			// easy linear copy
			// receive until bufferLength wrapped around or we have enough bytes
			while (bufferLength >= bufferPos && end > bufferLength)
				loadMore();
			dst[] = buffer[bufferPos .. bufferPos = cast(typeof(bufferPos))end];
		} else {
			// copy from wrapping buffer
			size_t i;
			while (i < dst.length) {
				auto remaining = dst.length - i;
				if (bufferPos < bufferLength) {
					auto d = min(remaining, bufferLength - bufferPos);
					dst[i .. i += d] = buffer[bufferPos .. bufferPos += d];
				} else if (bufferPos > bufferLength) {
					auto d = buffer.length - bufferPos;
					if (remaining >= d) {
						dst[i .. i += d] = buffer[bufferPos .. $];
						dst[i .. i += bufferLength] = buffer[0 .. bufferPos = bufferLength];
					} else {
						dst[i .. i += remaining] = buffer[bufferPos .. bufferPos += remaining];
					}
				} else {
					loadMore();
				}
			}
		}
	}

	immutable(ubyte)[] readUntilNull() {
		auto ret = appender!(immutable(ubyte)[]);
		while (true) {
			ubyte[] chunk;
			if (bufferPos < bufferLength) {
				chunk = buffer[bufferPos .. bufferLength];
			} else if (bufferPos > bufferLength) {
				chunk = buffer[bufferPos .. $];
			} else {
				loadMore();
				continue;
			}

			auto zero = chunk.countUntil(0);
			if (zero == -1) {
				ret ~= chunk;
				bufferPos += chunk.length;
				if (bufferPos == buffer.length)
					bufferPos = 0;
			} else {
				ret ~= chunk[0 .. zero];
				bufferPos += zero + 1;
				return ret.data;
			}
		}
	}
}

unittest {
	class MockedSocketReceiveStream : SocketReceiveStream {
		int maxChunk = 64;
		ubyte generator = 0;

		this() {
			super(null);
		}

		protected override ptrdiff_t receiveSocket(ubyte[] buffer) {
			if (buffer.length >= maxChunk) {
				buffer[0 .. maxChunk] = ++generator;
				return maxChunk;
			} else {
				buffer[] = ++generator;
				return buffer.length;
			}
		}
	}

	auto stream = new MockedSocketReceiveStream();
	stream.buffer[] = 0;
	auto b = stream.readBytes(3);
	assert(b == [1, 1, 1]);
	assert(stream.buffer[0 .. 64].all!(a => a == 1));
	assert(stream.buffer[64 .. $].all!(a => a == 0));
	b = stream.readBytes(3);
	assert(b == [1, 1, 1]);
	assert(stream.buffer[64 .. $].all!(a => a == 0));
	assert(stream.bufferPos == 6);
	assert(stream.bufferLength == 64);
	b = stream.readBytes(64);
	assert(b[0 .. $ - 6].all!(a => a == 1));
	assert(b[$ - 6 .. $].all!(a => a == 2));
	assert(stream.bufferPos == 70);
	assert(stream.bufferLength == 128);
	b = stream.readBytes(57);
	assert(b.all!(a => a == 2));
	assert(stream.bufferPos == 127);
	assert(stream.bufferLength == 128);
	b = stream.readBytes(8000);
	assert(b[0] == 2);
	assert(b[1 .. 65].all!(a => a == 3));
	assert(b[65 .. 129].all!(a => a == 4));

	stream.buffer[] = 0;
	stream.bufferPos = stream.bufferLength = 0;
	stream.generator = 0;
	assert(stream.readUntilNull().length == 64 * 255);
}

struct SendBuffer {
	private ubyte[4096] backing;

	private ubyte[] buffer;
	private size_t position;

	ubyte[] data() {
		assert(position > 4);

		resetSize();
		return buffer[0 .. position];
	}

	private void size(size_t addition) {
		if(buffer is null)
			buffer = backing[];
		if(position + addition > buffer.length) {
                        buffer.length = buffer.length * 2;
                        size(addition);
                }
	}

	void add(const document d) {
		SendBuffer sb;

		sb.add(d.bytesCount);
		foreach(v; d.values)
			sb.add(v);
		sb.addByte(0);

		auto data = sb.data;
		//import std.stdio; writefln("%(%x %)",data);

		this.add(data);
	}

	void add(const MsgHeader header) {
		add(header.messageLength);
		add(header.requestID);
		add(header.responseTo);
		add(header.opCode);
	}

	void add(const bson_value v) {
		addByte(v.tag);
		add(v.name);

		static struct visitor {
			this(SendBuffer* buf) { this.buf = buf; }
			SendBuffer* buf;
			void visit(long v) { buf.add(v); }
			void visit(int v) { buf.add(v); }
			void visit(bool v) { buf.addByte(v ? 1 : 0); }
			void visit(double v) { buf.add(v); }
			void visit(const document v) { buf.add(v); }
			void visit(const(char)[] v) { buf.add(cast(int) v.length + 1); buf.add(v); }
			void visit(const typeof(null)) {  }
			void visit(ubyte tag, const(ubyte)[] v) { buf.add(cast(int) v.length); buf.addByte(tag); buf.add(v); }
			void visit(const Undefined v) {  }
			void visit(const ObjectId v) { buf.add(v.v[]); }
			void visit(const Javascript v) { buf.add(cast(int) v.v.length + 1); buf.add(v.v); }
			void visit(const Timestamp v) { buf.add(v.v); }
			void visit(const UtcTimestamp v) { buf.add(v.v); }
			void visit(const Decimal128 v) { buf.add(v.v[]); }
			void visit(const RegEx v) { buf.add(v.regex); buf.add(v.flags); }

			void visit(const(bson_value)[] v) { buf.add(document(v));  }
		}

		visitor mv = visitor(&this);
		v.visit(mv);
	}


	void addByte(ubyte a) {
		size(1);
		buffer[position++] = (a >> 0) & 0xff;
	}

	void add(double i) {
		long a = *(cast(long*) &i);
		add(a);
	}

	void add(int a) {
		size(4);
		buffer[position++] = (a >> 0) & 0xff;
		buffer[position++] = (a >> 8) & 0xff;
		buffer[position++] = (a >> 16) & 0xff;
		buffer[position++] = (a >> 24) & 0xff;
	}

	void add(long a) {
		size(8);
		buffer[position++] = (a >> 0) & 0xff;
		buffer[position++] = (a >> 8) & 0xff;
		buffer[position++] = (a >> 16) & 0xff;
		buffer[position++] = (a >> 24) & 0xff;
		buffer[position++] = (a >> 32) & 0xff;
		buffer[position++] = (a >> 40) & 0xff;
		buffer[position++] = (a >> 48) & 0xff;
		buffer[position++] = (a >> 56) & 0xff;
	}

	// does NOT write the length out first!
	void add(const(char)[] a) {
		size(a.length + 1);
		buffer[position .. position + a.length] = cast(ubyte[]) a[];
		position += a.length;
		buffer[position++] = 0;
	}

	// does NOT write the length out first!
	void add(const(ubyte)[] a) {
		size(a.length);
		buffer[position .. position + a.length] = cast(ubyte[]) a[];
		position += a.length;
	}

	private void resetSize() {
		auto sz = cast(int) position;
		buffer[0] = (sz >> 0) & 0xff;
		buffer[1] = (sz >> 8) & 0xff;
		buffer[2] = (sz >> 16) & 0xff;
		buffer[3] = (sz >> 24) & 0xff;
	}
}

unittest {
        // A test for correct buffer allocation
        import std.algorithm;
        import std.range;
        import std.conv;

        // a large BSON array
        auto anArray = iota(100000)
                .enumerate()
                .map!(tup => bson_value(tup.index.to!string, tup.value))
                .array();

        auto doc = document([bson_value("array", anArray)]);
        SendBuffer buf;
        buf.add(doc);
}

struct MsgHeader {
	int messageLength;
	int requestID;
	int responseTo;
	int opCode;
}

enum OP {
	REPLY = 1,
	UPDATE = 2001,
	INSERT = 2002,
	QUERY = 2004, // sends a reply
	GET_MORE = 2005, // sends a reply
	DELETE = 2006,
	KILL_CURSORS = 2007,
	MSG = 2013
}

struct OP_UPDATE {
	MsgHeader header;
	int zero;
	const(char)[] fullCollectionName;
	int flags; // bit 0 == upsert, bit 1 == multiupdate if
	document selector;
	document update;
}

struct OP_INSERT {
	MsgHeader header;
	int flags; // bit 0 == ContinueOnError
	const(char)[] fullCollectionName;
	document[] documents;
}

struct OP_QUERY {
	MsgHeader header;
	int flags; // SEE: https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#op-query
	const(char)[] fullCollectionName;
	int numberToSkip;
	int numberToReturn;
	document query;
	document returnFieldsSelector; // optional.....
}

struct OP_GET_MORE {
	MsgHeader header;
	int zero;
	const(char)[] fullCollectionName;
	int numberToReturn;
	long cursorID;
}

struct OP_DELETE {
	MsgHeader header;
	int zero;
	const(char)[] fullCollectionName;
	int flags; // bit 0 is single remove
	document selector;
}

// If a cursor is read until exhausted (read until OP_QUERY or OP_GET_MORE returns zero for the cursor id), there is no need to kill the cursor.
struct OP_KILL_CURSORS {
	MsgHeader header;
	int zero;
	int numberOfCursorIds;
	const(long)[] cursorIDs;
}

/+
// in mongo 3.6
struct OP_MSG {
	MsgHeader header,
	uint flagBits;
	Section[]
}
+/

struct OP_REPLY {
	MsgHeader header;
	int responseFlags; // flag 0: cursor not found. 1: query failure. $err set in a thing.
	long cursorID;
	int startingFrom;
	int numberReturned;
	document[] documents;

	/* range elements */
	int numberToReturn;
	const(char)[] fullCollectionName;
	size_t current;
	MongoConnection connection;
	int limitRemaining = int.max;

	string errorMessage;
	int errorCode;

	@property bool empty() {
		return errorCode != 0 || numberReturned == 0 || limitRemaining <= 0;
	}

	void popFront() {
		limitRemaining--;
		current++;
		if(current == numberReturned) {
			this = connection.getMore(fullCollectionName, numberToReturn, cursorID, limitRemaining);
			if(numberReturned == 1) {
				auto err = documents[0]["$err"];
				auto ecode = documents[0]["code"];
				if(err !is bson_value.init) {
					errorMessage = err.get!string;
					errorCode = ecode.get!int;
				}
			}
		}
	}

	@property document front() {
		return documents[current];
	}
}

/* bson */

struct document {
	private int bytesCount;
	private const(bson_value)[] values_;
	private ubyte terminatingZero;

	const(bson_value) opIndex(string name) {
		foreach(value; values)
			if(value.name == name)
				return value;
		return bson_value.init;
	}

	this(const(bson_value)[] values) {
		values_ = values;
		terminatingZero = 0;
		foreach(v; values)
			bytesCount += v.size;
	}

	size_t length() const {
		return values_.length;
	}

	const(bson_value)[] values() const {
		return values_;
	}

	string toString(int indent = 0) const {
		string s;

		s ~= "{\n";

		foreach(value; values) {
			foreach(i; 0 .. indent + 1) s ~= "\t";
			s ~= value.name;
			s ~= ": ";
			s ~= value.toString();
			s ~= "\n";
		}

		foreach(i; 0 .. indent) s ~= "\t";
		s ~= "}\n";

		return s;
	}
}

struct ObjectId {
	ubyte[12] v;
	string toString() const {
		import std.format;
		return format("ObjectId(%(%02x%))", v[]);
	}

	this(const ubyte[12] v) {
		this.v = v;
	}

	this(string s) {
		import std.algorithm;
		if(s.startsWith("ObjectId("))
			s = s["ObjectId(".length .. $-1];
		if(s.length != 24)
			throw new Exception("invalid object id: " ~ s);
		static int hexToDec(char c) {
			if(c >= '0' && c <= '9')
				return c - '0';
			if(c >= 'A' && c <= 'F')
				return c - 'A' + 10;
			if(c >= 'a' && c <= 'f')
				return c - 'a' + 10;
			throw new Exception("Invalid hex char " ~ c);
		}
		foreach(ref b; v) {
			b = cast(ubyte) ((hexToDec(s[0]) << 4) | hexToDec(s[1]));
			s = s[2 .. $];
		}
	}
}
struct UtcTimestamp {
	long v;
}
struct RegEx {
	const(char)[] regex;
	const(char)[] flags;
}
struct Javascript {
	string v;
}
struct Timestamp {
	ulong v;
}
struct Decimal128 {
	ubyte[16] v;
}
struct Undefined {}


struct ToStringVisitor(T) if (isSomeString!T) {
	import std.conv;

	// of course this could have been a template but I wrote it out long-form for copy/paste purposes
	T visit(const double v) { return to!T(v); }
	T visit(const string v) { return to!T(v); }
	T visit(const document v) { return to!T(v); }
	T visit(const const(bson_value)[] v) { return to!T(v); }
	T visit(const ubyte tag, const ubyte[] v) { return to!T(v); }
	T visit(const ObjectId v) { return to!T(v); }
	T visit(const bool v) { return to!T(v); }
	T visit(const UtcTimestamp v) { return to!T(v); }
	T visit(const typeof(null)) { return to!T(null); }
	T visit(const RegEx v) { return to!T(v); }
	T visit(const Javascript v) { return to!T(v); }
	T visit(const int v) { return to!T(v); }
	T visit(const Undefined) { return "undefined".to!T; }
	T visit(const Timestamp v) { return to!T(v); }
	T visit(const long v) { return to!T(v); }
	T visit(const Decimal128 v) { return to!T(v); }
}

struct GetVisitor(T) {
	T visit(V)(const V t) {
		static if (isIntegral!V) {
			static if(isIntegral!T || isFloatingPoint!T)
				return cast(T)t;
			else throw new Exception("incompatible type");
		} else static if (isFloatingPoint!V) {
			static if(isFloatingPoint!T)
				return cast(T)t;
			else throw new Exception("incompatible type");
		} else {
			static if(is(V : T))
				return t;
			else throw new Exception("incompatible type");
		}
	}

	T visit(ubyte tag, const(ubyte)[] v) {
		static if(is(typeof(v) : T))
			return v;
		else throw new Exception("incompatible type " ~ T.stringof);
	}
}

struct bson_value {
	private ubyte tag;
	private const(char)[] e_name;

	// It only allows integer types or const getting in order to work right in the visitor...
	/// Tries to get the value matching exactly this type. The type will convert
	/// between different floating point types and integral types as well as
	/// perform a conversion from integral types to floating point types.
	T get(T)() const if (__traits(compiles, GetVisitor!T)) {
		GetVisitor!T v;
		return visit(v);
	}

	const(char)[] name() const {
		return e_name;
	}

	this(const(char)[] name, bson_value v) {
		this = v;
		e_name = name;
	}

	this(const(char)[] name, double v) {
		e_name = name;
		tag = 0x01;
		x01 = v;
	}
	this(const(char)[] name, string v) {
		e_name = name;
		tag = 0x02;
		x02 = v;
	}
	this(const(char)[] name, document v) {
		e_name = name;
		tag = 0x03;
		x03 = v;
	}
	this(const(char)[] name, bson_value[] v) {
		e_name = name;
		tag = 0x04;
		const(bson_value)[] n;
		n.reserve(v.length);
		import std.conv;
		foreach(idx, i; v)
			n ~= bson_value(to!string(idx), i);
		x04 = document(n);
	}
	this(const(char)[] name, const(ubyte)[] v, ubyte tag = 0x00) {
		e_name = name;
		this.tag = 0x05;
		x05_tag = tag;
		x05_data = v;
	}
	this(const(char)[] name, ObjectId v) {
		e_name = name;
		tag = 0x07;
		x07 = v.v;
	}
	this(const(char)[] name, bool v) {
		e_name = name;
		tag = 0x08;
		x08 = v;
	}
	this(const(char)[] name, UtcTimestamp v) {
		e_name = name;
		tag = 0x09;
		x09 = v.v;
	}
	this(const(char)[] name, typeof(null)) {
		e_name = name;
		tag = 0x0a;
	}
	this(const(char)[] name, RegEx v) {
		e_name = name;
		tag = 0x0b;
		x0b_regex = v.regex;
		x0b_flags = v.flags;
	}
	this(const(char)[] name, Javascript v) {
		e_name = name;
		tag = 0x0d;
		x0d = v.v;
	}
	this(const(char)[] name, int v) {
		e_name = name;
		tag = 0x10;
		x10 = v;
	}
	this(const(char)[] name, Timestamp v) {
		e_name = name;
		tag = 0x11;
		x11 = v.v;
	}
	this(const(char)[] name, long v) {
		e_name = name;
		tag = 0x12;
		x12 = v;
	}
	this(const(char)[] name, Decimal128 v) {
		e_name = name;
		tag = 0x13;
		x13 = v.v;
	}

	auto visit(T)(T t) const {
		switch(tag) {
			case 0x00: throw new Exception("invalid bson");
			case 0x01: return t.visit(x01);
			case 0x02: return t.visit(x02);
			case 0x03: return t.visit(x03);
			case 0x04: return t.visit(x04.values);
			case 0x05: return t.visit(x05_tag, x05_data);
			case 0x06: return t.visit(Undefined());
			case 0x07: return t.visit(ObjectId(x07));
			case 0x08: return t.visit(x08);
			case 0x09: return t.visit(UtcTimestamp(x09));
			case 0x0a: return t.visit(null);
			case 0x0b: return t.visit(RegEx(x0b_regex, x0b_flags));
			case 0x0d: return t.visit(Javascript(x0d));
			case 0x10: return t.visit(x10);
			case 0x11: return t.visit(Timestamp(x11));
			case 0x12: return t.visit(x12);
			case 0x13: return t.visit(Decimal128(x13));
			default:
				import std.conv;
				assert(0, "unsupported tag in bson: " ~ to!string(tag));

		}
	}

	string toString() const {
		ToStringVisitor!string v;
		return visit(v);
	}

	private union {
		void* zero;
		double x01;
		string x02; // given with an int length preceding and 0 terminator
		document x03; // child object
		document x04; // array with indexes as key values
		struct {
			ubyte x05_tag;
			const(ubyte)[] x05_data; // binary data
		}
		void* undefined;
		ubyte[12] x07; // a guid/ ObjectId
		bool x08;
		long x09; // utc datetime stamp
		void* x0a; // null
		struct {
			const(char)[] x0b_regex;
			const(char)[] x0b_flags; // alphabetized
		}
		string x0d; // javascript
		int x10; // integer!!! omg
		ulong x11; // timestamp
		long x12; // integer!!!
		ubyte[16] x13; // decimal 128
	}

	size_t size() const {
		auto count = 2 + e_name.length;

		switch(this.tag) {
			case 0x00: // not supposed to exist!
				throw new Exception("invalid bson");
			case 0x01:
				count += 8;
			break;
			case 0x02:
				count += 5 + x02.length; // length and zero
			break;
			case 0x03:
				count += x03.bytesCount;
			break;
			case 0x04:
				count += x04.bytesCount;
			break;
			case 0x05:
				count += x05_data.length;
				count += 5; // length and tag
			break;
			case 0x06: // undefined
				// intentionally blank, no additional data
			break;
			case 0x07:
				count += x07.length;
			break;
			case 0x08:
				count++;
			break;
			case 0x09:
				count += 8;
			break;
			case 0x0a: // null
				// intentionally blank, no additional data
			break;
			case 0x0b:
				count += x0b_regex.length + 1;
				count += x0b_flags.length + 1;
			break;
			case 0x0d:
				count += 5 + x0d.length; // length and zero
			break;
			case 0x10:
				count += 4;
			break;
			case 0x11:
				count += 8;
			break;
			case 0x12:
				count += 8;
			break;
			case 0x13:
				count += x13.length;
			break;
			default:
				import std.conv;
				assert(0, "unsupported tag in bson: " ~ to!string(tag));
		}

		return count;
	}
}

struct UriHost {
	string host;
	int port;
}

/* copy/pasted from arsd.cgi, modified for mongo-specific comma behavior. used with permission */
struct Uri {
	// scheme//userinfo@host:port/path?query#fragment

	string scheme; /// e.g. "http" in "http://example.com/"
	string userinfo; /// the username (and possibly a password) in the uri
	UriHost[] hosts;
	string path; /// e.g. "/folder/file.html" in "http://example.com/folder/file.html"
	string query; /// the stuff after the ? in a uri
	string fragment; /// the stuff after the # in a uri.

	/// Breaks down a uri string to its components
	this(string uri) {
		reparse(uri);
	}

	private void reparse(string uri) {
		// from RFC 3986
		// the ctRegex triples the compile time and makes ugly errors for no real benefit
		// it was a nice experiment but just not worth it.
		// enum ctr = ctRegex!r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?";
		/*
			Captures:
				0 = whole url
				1 = scheme, with :
				2 = scheme, no :
				3 = authority, with //
				4 = authority, no //
				5 = path
				6 = query string, with ?
				7 = query string, no ?
				8 = anchor, with #
				9 = anchor, no #
		*/
		// Yikes, even regular, non-CT regex is also unacceptably slow to compile. 1.9s on my computer!
		// instead, I will DIY and cut that down to 0.6s on the same computer.
		/*

				Note that authority is
					user:password@domain:port
				where the user:password@ part is optional, and the :port is optional.

				Regex translation:

				Scheme cannot have :, /, ?, or # in it, and must have one or more chars and end in a :. It is optional, but must be first.
				Authority must start with //, but cannot have any other /, ?, or # in it. It is optional.
				Path cannot have any ? or # in it. It is optional.
				Query must start with ? and must not have # in it. It is optional.
				Anchor must start with # and can have anything else in it to end of string. It is optional.
		*/

		this = Uri.init; // reset all state

		// empty uri = nothing special
		if(uri.length == 0) {
			return;
		}

		size_t idx;

		scheme_loop: foreach(char c; uri[idx .. $]) {
			switch(c) {
				case ':':
				case '/':
				case '?':
				case '#':
					break scheme_loop;
				default:
			}
			idx++;
		}

		if(idx == 0 && uri[idx] == ':') {
			// this is actually a path! we skip way ahead
			goto path_loop;
		}

		if(idx == uri.length) {
			// the whole thing is a path, apparently
			path = uri;
			return;
		}

		if(idx > 0 && uri[idx] == ':') {
			scheme = uri[0 .. idx];
			idx++;
		} else {
			// we need to rewind; it found a / but no :, so the whole thing is prolly a path...
			idx = 0;
		}

		if(idx + 2 < uri.length && uri[idx .. idx + 2] == "//") {
			// we have an authority....
			idx += 2;

			auto authority_start = idx;
			authority_loop: foreach(char c; uri[idx .. $]) {
				switch(c) {
					case '/':
					case '?':
					case '#':
						break authority_loop;
					default:
				}
				idx++;
			}

			auto authority = uri[authority_start .. idx];

			auto idx2 = authority.indexOf("@");
			if(idx2 != -1) {
				userinfo = authority[0 .. idx2];
				authority = authority[idx2 + 1 .. $];
			}

			auto remaining = authority;

			while(remaining.length) {
				auto idx3 = remaining.indexOf(",");
				if(idx3 != -1) {
					authority = remaining[0 .. idx3];
					remaining = remaining[idx3 + 1 .. $];
				} else {
					authority = remaining;
					remaining = null;
				}

				string host;
				int port;

				idx2 = authority.indexOf(":");
				if(idx2 == -1) {
					port = 0; // 0 means not specified; we should use the default for the scheme
					host = authority;
				} else {
					host = authority[0 .. idx2];
					port = to!int(authority[idx2 + 1 .. $]);
				}

				hosts ~= UriHost(host, port);
			}
		}

		path_loop:
		auto path_start = idx;
		
		foreach(char c; uri[idx .. $]) {
			if(c == '?' || c == '#')
				break;
			idx++;
		}

		path = uri[path_start .. idx];

		if(idx == uri.length)
			return; // nothing more to examine...

		if(uri[idx] == '?') {
			idx++;
			auto query_start = idx;
			foreach(char c; uri[idx .. $]) {
				if(c == '#')
					break;
				idx++;
			}
			query = uri[query_start .. idx];
		}

		if(idx < uri.length && uri[idx] == '#') {
			idx++;
			fragment = uri[idx .. $];
		}

		// uriInvalidated = false;
	}
}
/* end */


version(linux)
	@trusted
	extern(C)
	int getentropy(scope void*, size_t);
else version(Windows) {
	import core.sys.windows.windows;
	import core.sys.windows.ntdef;
	enum STATUS_SUCCESS = 0;
	pragma(lib, "bcrypt");
	@trusted
	extern(Windows)
	NTSTATUS BCryptGenRandom(scope void*, PUCHAR, ULONG, ULONG);
} else static assert(0);




// copy pasted from vibe.d; https://raw.githubusercontent.com/vibe-d/vibe.d/master/mongodb/vibe/db/mongo/sasl.d

/*
	SASL authentication functions

	Copyright: © 2012-2016 Nicolas Gurrola
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Nicolas Gurrola
*/

import std.algorithm;
import std.base64;
import std.conv;
import std.digest.hmac;
import std.digest.sha;
import std.exception;
import std.format;
import std.string;
import std.traits;
import std.utf;

@safe:

package struct ScramState
{
	@safe:

	private string m_firstMessageBare;
	private string m_nonce;
	private DigestType!SHA1 m_saltedPassword;
	private string m_authMessage;

	string createInitialRequest(string user)
	{
		ubyte[18] randomBytes;
		version(linux) {
			if(getentropy(&(randomBytes[0]), randomBytes.length) != 0)
				throw new Exception("get random failure");
		} else version(Windows) {
			if(BCryptGenRandom(null, &(randomBytes[0]), randomBytes.length, 2 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG */) != STATUS_SUCCESS)
				throw new Exception("get random failure");
		} else static assert(0);

		m_nonce = Base64.encode(randomBytes);

		m_firstMessageBare = format("n=%s,r=%s", escapeUsername(user), m_nonce);
		return format("n,,%s", m_firstMessageBare);
	}

	version (unittest) private string createInitialRequestWithFixedNonce(string user, string nonce)
	{
		m_nonce = nonce;

		m_firstMessageBare = format("n=%s,r=%s", escapeUsername(user), m_nonce);
		return format("n,,%s", m_firstMessageBare);
	}

	// MongoDB drivers require 4096 min iterations https://github.com/mongodb/specifications/blob/59390a7ab2d5c8f9c29b8af1775ff25915c44036/source/auth/auth.rst#scram-sha-1
	string update(string password, string challenge, int minIterations = 4096)
	{
		string serverFirstMessage = challenge;

		string next = challenge.find(',');
		if (challenge.length < 2 || challenge[0 .. 2] != "r=" || next.length < 3 || next[1 .. 3] != "s=")
			throw new Exception("Invalid server challenge format: " ~ challenge);
		string serverNonce = challenge[2 .. $ - next.length];
		challenge = next[3 .. $];
		next = challenge.find(',');
		ubyte[] salt = Base64.decode(challenge[0 .. $ - next.length]);

		if (next.length < 3 || next[1 .. 3] != "i=")
			throw new Exception("Invalid server challenge format");
		int iterations = next[3 .. $].to!int();

		if (iterations < minIterations)
			throw new Exception("Server must request at least " ~ minIterations.to!string ~ " iterations");

		if (serverNonce[0 .. m_nonce.length] != m_nonce)
			throw new Exception("Invalid server nonce received");
		string finalMessage = format("c=biws,r=%s", serverNonce);

		m_saltedPassword = pbkdf2(password.representation, salt, iterations);
		m_authMessage = format("%s,%s,%s", m_firstMessageBare, serverFirstMessage, finalMessage);

		auto proof = getClientProof(m_saltedPassword, m_authMessage);
		return format("%s,p=%s", finalMessage, Base64.encode(proof));
	}

	string finalize(string challenge)
	{
		if (challenge.length < 2 || challenge[0 .. 2] != "v=")
		{
			throw new Exception("Invalid server signature format");
		}
		if (!verifyServerSignature(Base64.decode(challenge[2 .. $]), m_saltedPassword, m_authMessage))
		{
			throw new Exception("Invalid server signature");
		}
		return null;
	}

	private static string escapeUsername(string user)
	{
		char[] buffer;
		foreach (i, dchar ch; user)
		{
			if (ch == ',' || ch == '=') {
				if (!buffer) {
					buffer.reserve(user.length + 2);
					buffer ~= user[0 .. i];
				}
				if (ch == ',')
					buffer ~= "=2C";
				else
					buffer ~= "=3D";
			} else if (buffer)
				encode(buffer, ch);
		}
		return buffer ? () @trusted { return assumeUnique(buffer); } () : user;
	}

	unittest
	{
		string user = "user";
		assert(escapeUsername(user) == user);
		assert(escapeUsername(user) is user);
		assert(escapeUsername("user,1") == "user=2C1");
		assert(escapeUsername("user=1") == "user=3D1");
		assert(escapeUsername("u,=ser1") == "u=2C=3Dser1");
		assert(escapeUsername("u=se=r1") == "u=3Dse=3Dr1");
	}

	private static auto getClientProof(DigestType!SHA1 saltedPassword, string authMessage)
	{
		auto clientKey = () @trusted { return hmac!SHA1("Client Key".representation, saltedPassword); } ();
		auto storedKey = sha1Of(clientKey);
		auto clientSignature = () @trusted { return hmac!SHA1(authMessage.representation, storedKey); } ();

		foreach (i; 0 .. clientKey.length)
		{
			clientKey[i] = clientKey[i] ^ clientSignature[i];
		}
		return clientKey;
	}

	private static bool verifyServerSignature(ubyte[] signature, DigestType!SHA1 saltedPassword, string authMessage)
	@trusted {
		auto serverKey = hmac!SHA1("Server Key".representation, saltedPassword);
		auto serverSignature = hmac!SHA1(authMessage.representation, serverKey);
		return serverSignature == signature;
	}
}

private DigestType!SHA1 pbkdf2(const ubyte[] password, const ubyte[] salt, int iterations)
{
	import std.bitmanip;

	ubyte[4] intBytes = [0, 0, 0, 1];
	auto last = () @trusted { return hmac!SHA1(salt, intBytes[], password); } ();
	static assert(isStaticArray!(typeof(last)),
		"Code is written so that the hash array is expected to be placed on the stack");
	auto current = last;
	foreach (i; 1 .. iterations)
	{
		last = () @trusted { return hmac!SHA1(last[], password); } ();
		foreach (j; 0 .. current.length)
		{
			current[j] = current[j] ^ last[j];
		}
	}
	return current;
}

unittest {
	ScramState state;
	assert(state.createInitialRequestWithFixedNonce("user", "fyko+d2lbbFgONRv9qkxdawL")
		== "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
	auto last = state.update(makeDigest("user", "pencil"),
		"r=fyko+d2lbbFgONRv9qkxdawLHo+Vgk7qvUOKUwuWLIWg4l/9SraGMHEE,s=rQ9ZY3MntBeuP3E1TDVC4w==,i=10000");
	assert(last == "c=biws,r=fyko+d2lbbFgONRv9qkxdawLHo+Vgk7qvUOKUwuWLIWg4l/9SraGMHEE,p=MC2T8BvbmWRckDw8oWl5IVghwCY=",
		last);
	last = state.finalize("v=UMWeI25JD1yNYZRMpZ4VHvhZ9e0=");
	assert(last == "", last);
}

string makeDigest(string username, string password) {
	import std.digest.md;
	return md5Of(username ~ ":mongo:" ~ password).toHexString().idup.toLower();
}
