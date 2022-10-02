import kaleidic.mongo_standalone;
import std.format;
import std.stdio;
import std.uri;

int main(string[] args) {
	if (args.length < 3) {
		writeln("usage: ", args[0],
			" [expected auth] [encoded username] [encoded password]");
		writeln("  if [expected auth] is 'FAIL', the script errors if the user");
		writeln("    managed to authenticate using the given credentials.");
		writeln("  Otherwise it checks that the given auth mechanism name like");
		writeln("    SCRAM-SHA-1 has been used for the connection.");
		return 1;
	}

	const expectedAuth = args[1];
	const username = args[2];
	const password = args[3];

	// don't encode, test script should be able to pass anything
	const dbUri = format!"mongodb://%s:%s@localhost/test?slaveOk=true"(
		username,
		password
	);

	TestingMongoConnection connection;
	try {
		connection = new TestingMongoConnection(dbUri);
	} catch (Exception e) {
		if (expectedAuth == "FAIL") {
			writeln("expectedly failed");
			return 0;
		} else {
			throw e;
		}
	}

	assert(connection.didAuthenticate == expectedAuth,
		"Expected " ~ expectedAuth ~ " but driver connected with "
		~ connection.didAuthenticate);

	auto reply = connection.runCommand("test", document([
		bson_value("dbStats", 1)
	]));

	writeln("reply: ", reply);

	writeln("auth succeeded");
	return 0;
}

class TestingMongoConnection : MongoConnection
{
	/// Filled with the authentication mechanism when authentication has been done
	string didAuthenticate;
	
	this(string connectionString)
	{
		super(connectionString);
	}

	override OP_REPLY query(const(char)[] fullCollectionName, int numberToSkip,
		int numberToReturn, document query,
		document returnFieldsSelector = document.init, int flags = 1, int limit = int.max)
	{
		test_doc(query);
		return super.query(__traits(parameters));
	}

	override OP_MSG msg(int responseTo, uint flagBits, const document doc)
	{
		test_doc(doc);
		return super.msg(__traits(parameters));
	}

	private void test_doc(document query)
	{
		auto saslStart = query["saslStart"];
		if (saslStart != bson_value.init)
			didAuthenticate = query["mechanism"].toString();
	}
}
