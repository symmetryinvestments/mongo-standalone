import kaleidic.mongo_standalone;
import kaleidic.mongo_gridfs;

import std.stdio;
import std.file;
import std.digest.sha;

int main(string[] args) {
    char[40][string] files;
    MongoConnection mongo = new MongoConnection("mongodb://localhost/?slaveOk=true");

    foreach(fileName; args[1..$]) {
        auto hashBytes = sha1Of(read(fileName));
        auto hashStr = toHexString!(LetterCase.lower)(hashBytes);
        files[fileName] = hashStr;
    }

    auto fetchedFiles = gridfsReadManyFiles(mongo, "test_files.fs", files.keys);
    foreach(fileName, contents; fetchedFiles) {
        auto hashBytes = sha1Of(contents);
        auto hashStr = toHexString!(LetterCase.lower)(hashBytes);
        if (hashStr != files[fileName]) {
            writeln("FAILURE:");
            writeln("  NAME: ", fileName);
            writeln("  SIZE: ", contents.length);
            writeln("  SHA1: ", hashStr);
            writeln("  EXPECTED SHA1: ", files[fileName]);
            writeln("");
            return 1;
        }
    }

    writeln("SUCCESS: ", fetchedFiles.length, " files were read correctly");

    return 0;
}
