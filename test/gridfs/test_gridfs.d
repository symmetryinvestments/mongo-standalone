import kaleidic.mongo_standalone;
import kaleidic.mongo_gridfs;

import std.stdio;
import std.digest.sha;

int main(string[] args) {
    if (args.length != 3) {
        writeln("use: test_gridfs <FILE> <SHA1>\n");
        return 1;
    }
    string fileName = args[1];
    string sha1Sum = args[2];

    MongoConnection mongo = new MongoConnection("mongodb://localhost/?slaveOk=true");
    ubyte[] contents = gridfsReadFile(mongo, "test_files.fs", fileName);

    ubyte[20] hashBytes = sha1Of(contents);
    auto hashStr = toHexString!(LetterCase.lower)(hashBytes);
    if (hashStr != sha1Sum) {
        writeln("FAILURE:");
        writeln("  NAME: ", fileName);
        writeln("  SIZE: ", contents.length);
        writeln("  SHA1: ", hashStr);
        writeln("  EXPECTED SHA1: ", sha1Sum);
        writeln("");
        return 1;
    }

    writeln("SUCCESS:");
    writeln("  NAME: ", fileName);
    writeln("  SIZE: ", contents.length);
    writeln("  SHA1: ", hashStr);
    writeln("");

    return 0;
}
