/++
	BSON data format implementation for MongoDB.

	Copyright: 2020-2022 Symmetry Investments
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
+/
module kaleidic.mongo_standalone.bson;

import std.traits;

struct document {
	package int bytesCount_;
	package const(bson_value)[] values_;
	package ubyte terminatingZero;

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
			bytesCount_ += v.size;
	}

	int bytesCount() const {
		return bytesCount_;
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

	int opCmp(ObjectId id) {
		import std.algorithm;
		return cmp(cast(ubyte[])this.v, cast(ubyte[])id.v);
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
	package ubyte tag;
	package const(char)[] e_name;

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
	this(const(char)[] name, document[] v) {
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

	package union {
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

	bool opEquals(const bson_value other) const
	{
		if (tag != other.tag)
			return false;
		if (e_name != other.e_name)
			return false;

		switch(tag) {
			case 0x01: return x01 == other.x01;
			case 0x02: return x02 == other.x02;
			case 0x03: return x03 == other.x03;
			case 0x04: return x04 == other.x04;
			case 0x05: return x05_tag == other.x05_tag && x05_data == other.x05_data;
			case 0x06: return true;
			case 0x07: return x07 == other.x07;
			case 0x08: return x08 == other.x08;
			case 0x09: return x09 == other.x09;
			case 0x0a: return true;
			case 0x0b: return x0b_regex == other.x0b_regex && x0b_flags == other.x0b_flags;
			case 0x0d: return x0d == other.x0d;
			case 0x10: return x10 == other.x10;
			case 0x11: return x11 == other.x11;
			case 0x12: return x12 == other.x12;
			case 0x13: return x13 == other.x13;
			default: return true;
		}
	}
}
