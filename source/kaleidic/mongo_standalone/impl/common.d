module kaleidic.mongo_standalone.impl.common;

import std.typecons;
import std.sumtype;

import kaleidic.mongo_standalone.bson;

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
	/// Server version 4.4
	v44 = 9,
	/// Server version 4.9
	v49 = 12,
	/// Server version 5.0
	v50 = 13,
	/// Server version 5.1
	v51 = 14,
	/// Server version 5.2
	v52 = 15,
	/// Server version 5.3
	v53 = 16
}

/// Ignores this field in auto-serialization of command args.
package enum ignore;
/// Ignores the field if we are before this WireVersion
package struct since { WireVersion ver; }
/// Throws an error if this Nullable field is set before the given WireVersion
package struct errorBefore { WireVersion ver; }
/// Prints a deprecation warning if this Nullable field is set on or after the given WireVersion
package struct deprecatedSince { WireVersion ver; }
/// Sets the serialized field name to this given name.
package struct name { string name; }

/// Serializes the given struct to a BSON document. Omits null Nullable and
/// SumType!(typeof(null)) values.
///
/// Throws an exception if attributes are used that are not supported with the
/// given wire version. Logs messages to stderr if attributes are used that are
/// deprecated with the given wire version. Ignores attributes that are defined
/// to be ignored if not matching at least a certain wire version.
package static document serializeCommandArgs(T)(T value, WireVersion wireVersion)
{
	import std.traits;
	import std.meta : staticIndexOf;
	import std.conv;

	bson_value[] values;
	foreach (i, v; value.tupleof)
	{
		alias member = __traits(getMember, value, __traits(identifier, T.tupleof[i]));

		static if (!hasUDA!(member, ignore))
		{
			alias nameUDA = getUDAs!(member, name);
			alias sinceUDA = getUDAs!(member, since);
			alias errorBeforeUDA = getUDAs!(member, errorBefore);
			alias deprecatedSinceUDA = getUDAs!(member, deprecatedSince);

			static if (nameUDA.length == 0)
				string n = __traits(identifier, T.tupleof[i]);
			else static if (nameUDA.length == 1)
				string n = nameUDA[0].name;
			else
				static assert(false, "multiple @name UDAs on field " ~ T.tupleof[i].stringof);

			static if (is(typeof(v) : Nullable!U, U))
				if (v.isNull)
					continue;

			static if (isSumType!(typeof(v)) && __traits(compiles, v.match!((typeof(null)) => true, _ => false)))
				if (v.match!((typeof(null)) => true, _ => false))
					continue;

			static foreach (sinceV; sinceUDA)
				if (wireVersion < sinceV.ver)
					v = typeof(v).init;

			static foreach (errorBeforeV; errorBeforeUDA)
				if (wireVersion < errorBeforeV.ver)
					throw new Exception("Cannot set field " ~ T.stirngof ~ "." ~ n
						~ " when not connected to a server that at least supports WireVersion "
						~ errorBeforeV.ver.to!string);

			static foreach (deprecatedSinceV; deprecatedSinceUDA)
				if (wireVersion >= deprecatedSinceV.ver)
					stderr.writeln("MongoDB deprecation: Field " ~ T.stirngof ~ "." ~ n
						~ " is not supported anymore since WireVersion "
						~ deprecatedSinceV.ver.to!string);

			values ~= serializeKeyImpl(n, v);
		}
	}

	return document(values);
}

private bson_value serializeKeyImpl(T)(string name, T v)
{
	import std.meta : staticIndexOf;

	static if (is(typeof(v) : Nullable!U, U))
		return serializeKeyImpl(name, v.get);
	else static if (is(T : SumType!Args, Args...))
	{
		static foreach (Arg; Args)
			static if (!__traits(compiles, serializeKeyImpl(name, Arg.init)))
				pragma(msg, "Error: " ~ Arg.stringof ~ " is not implemented in serializeKeyImpl");
		return v.match!((d) => serializeKeyImpl(name, d));
	}
	else
		return bson_value(name, v);
}

/**
  Specifies a level of isolation for read operations. For example, you can use read concern to only read data that has propagated to a majority of nodes in a replica set.

  See_Also: $(LINK https://docs.mongodb.com/manual/reference/read-concern/)
 */
struct ReadConcern {
	///
	enum Level : string {
		/// This is the default read concern level.
		local = "local",
		/// This is the default for reads against secondaries when afterClusterTime and "level" are unspecified. The query returns the the instance’s most recent data.
		available = "available",
		/// Available for replica sets that use WiredTiger storage engine.
		majority = "majority",
		/// Available for read operations on the primary only.
		linearizable = "linearizable"
	}

	/// The level of the read concern.
	string level;
}

/**
  See_Also: $(LINK https://docs.mongodb.com/manual/reference/write-concern/)
 */
struct WriteConcern {
	/**
		If true, wait for the the write operation to get committed to the

		See_Also: $(LINK http://docs.mongodb.org/manual/core/write-concern/#journaled)
	*/
	@name("j")
	Nullable!bool journal;

	/**
		When an integer, specifies the number of nodes that should acknowledge
		the write and MUST be greater than or equal to 0.

		When a string, indicates tags. "majority" is defined, but users could
		specify other custom error modes.
	*/
	SumType!(typeof(null), int, string) w;

	/**
		If provided, and the write concern is not satisfied within the specified
		timeout (in milliseconds), the server will return an error for the
		operation.

		See_Also: $(LINK http://docs.mongodb.org/manual/core/write-concern/#timeouts)
	*/
	@name("wtimeout")
	Nullable!long wtimeoutMS;
}

unittest
{
	WriteConcern w;
	w.journal = true;
	w.w = "foo";
	w.wtimeoutMS = 100;
	auto doc = serializeCommandArgs(w, WireVersion.v44);
	assert(doc.values.length == 3);
	assert(doc.values[0] == bson_value("j", true));
	assert(doc.values[1] == bson_value("w", "foo"));
	assert(doc.values[2] == bson_value("wtimeout", 100L));

	w.w = typeof(w.w).init;
	doc = serializeCommandArgs(w, WireVersion.v44);
	assert(doc.values.length == 2);
	assert(doc.values[0] == bson_value("j", true));
	assert(doc.values[1] == bson_value("wtimeout", 100L));
}

/**
  Collation allows users to specify language-specific rules for string comparison, such as rules for letter-case and accent marks.

  See_Also: $(LINK https://docs.mongodb.com/manual/reference/collation/)
 */
struct Collation {
	///
	enum Alternate : string {
		/// Whitespace and punctuation are considered base characters
		nonIgnorable = "non-ignorable",
		/// Whitespace and punctuation are not considered base characters and are only distinguished at strength levels greater than 3
		shifted = "shifted",
	}

	///
	enum MaxVariable : string {
		/// Both whitespaces and punctuation are “ignorable”, i.e. not considered base characters.
		punct = "punct",
		/// Whitespace are “ignorable”, i.e. not considered base characters.
		space = "space"
	}

	/**
	  The ICU locale

	  See_Also: See_Also: $(LINK https://docs.mongodb.com/manual/reference/collation-locales-defaults/#collation-languages-locales) for a list of supported locales.

	  To specify simple binary comparison, specify locale value of "simple".
	 */
	string locale;
	/// The level of comparison to perform. Corresponds to ICU Comparison Levels.
	Nullable!int strength;
	/// Flag that determines whether to include case comparison at strength level 1 or 2.
	Nullable!bool caseLevel;
	/// A flag that determines sort order of case differences during tertiary level comparisons.
	Nullable!string caseFirst;
	/// Flag that determines whether to compare numeric strings as numbers or as strings.
	Nullable!bool numericOrdering;
	/// Field that determines whether collation should consider whitespace and punctuation as base characters for purposes of comparison.
	Nullable!Alternate alternate;
	/// Field that determines up to which characters are considered ignorable when `alternate: "shifted"`. Has no effect if `alternate: "non-ignorable"`
	Nullable!MaxVariable maxVariable;
	/**
	  Flag that determines whether strings with diacritics sort from back of the string, such as with some French dictionary ordering.

	  If `true` compare from back to front, otherwise front to back.
	 */
	Nullable!bool backwards;
	/// Flag that determines whether to check if text require normalization and to perform normalization. Generally, majority of text does not require this normalization processing.
	Nullable!bool normalization;
}

///
struct CursorInitArguments {
	/// Specifies the initial batch size for the cursor. Or null for server
	/// default value.
	Nullable!int batchSize;
}

unittest
{
	Collation c;
	c.locale = "en";
	c.strength = 5;
	c.alternate = Collation.Alternate.shifted;
	auto doc = serializeCommandArgs(c, WireVersion.v44);
	assert(doc.values.length == 3);
	assert(doc.values[0] == bson_value("locale", "en"));
	assert(doc.values[1] == bson_value("strength", 5));
	assert(doc.values[2] == bson_value("alternate", "shifted"));
}
