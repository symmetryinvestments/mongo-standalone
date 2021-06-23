module kaleidic.mongo_gridfs;

import kaleidic.mongo_standalone;

// IN:     mongo            - active connection to the MongoDB instance.
//         gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
//         id               - the file object ID, i.e., it's "_id" value.
// RETURN: The entire file contents in an array.
// THROWS: File not found, or on corrupt properties.

ubyte[] gridfsReadFile(MongoConnection mongo, const string gridfsBucketName, const ObjectId id) {
    import std.outbuffer;

    // Get the file size.
    OP_REPLY reply =
        mongo.query(gridfsBucketName ~ ".files", 0, 1, document([bson_value("_id", id)]));
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }
    if (reply.documents.length != 1) {
        throw new Exception("Requested file not found.");
    }
    long fileSize = reply.documents[0]["length"].get!long;
    long chunkSize = reply.documents[0]["chunkSize"].get!long;

    OutBuffer contents = new OutBuffer();
    contents.reserve(fileSize);

    // Loop for each chunk and append to our buffer.
    int numChunks = cast(int)(fileSize / chunkSize + 1);
    for (int chunkIdx = 0; chunkIdx < numChunks; chunkIdx++) {
        reply = mongo.query(gridfsBucketName ~ ".chunks", 0, 1,
                            document([bson_value("files_id", id), bson_value("n", chunkIdx)]));
        if (reply.errorCode != 0) {
            throw new Exception(reply.errorMessage);
        }
        if (reply.documents.length != 1) {
            throw new Exception("Requested file content not found.");
        }
        contents.write(reply.documents[0]["data"].get!(const(ubyte[])));
    }

    return contents.toBytes;
}

// IN:     mongo            - active connection to the MongoDB instance.
//         gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
//         name             - file name
// RETURN: The entire file contents in an array.
// THROWS: File not found, or if more than 1 file match name, or on corrupt properties.

ubyte[] gridfsReadFile(MongoConnection mongo, const string gridfsBucketName, const string name) {
    OP_REPLY reply =
        mongo.query(gridfsBucketName ~ ".files", 0, 2, document([bson_value("filename", name)]));
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }
    if (reply.documents.length != 1) {
        throw new Exception("error: failed to match single file: '" ~ name ~ "'");
    }
    return gridfsReadFile(mongo, gridfsBucketName, reply.documents[0]["_id"].get!ObjectId);
}
