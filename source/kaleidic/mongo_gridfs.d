module kaleidic.mongo_gridfs;

import kaleidic.mongo_standalone;

/++
   IN:     mongo            - active connection to the MongoDB instance.
           gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
           id               - the file object ID, i.e., it's "_id" value.
   RETURN: The entire file contents in an array.
   THROWS: File not found, or on corrupt properties.
+/

ubyte[] gridfsReadFile(MongoConnection mongo, const string gridfsBucketName, const ObjectId id) {
    OP_REPLY reply =
        mongo.query(gridfsBucketName ~ ".files", 0, 1, document([bson_value("_id", id)]));
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }
    if (reply.documents.length != 1) {
        throw new Exception("Requested file not found.");
    }

    return gridfsReadFileById(mongo, gridfsBucketName, id);
}

/++
   IN:     mongo            - active connection to the MongoDB instance.
           gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
           name             - file name
   RETURN: The entire file contents in an array.
   THROWS: File not found, or if more than 1 file match name, or on corrupt properties.
+/

ubyte[] gridfsReadFile(MongoConnection mongo, const string gridfsBucketName, const string name) {
    OP_REPLY reply =
        mongo.query(gridfsBucketName ~ ".files", 0, 2, document([bson_value("filename", name)]));
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }
    if (reply.documents.length != 1) {
        throw new Exception("error: failed to match single file: '" ~ name ~ "'");
    }
    ObjectId id = reply.documents[0]["_id"].get!ObjectId;

    return gridfsReadFileById(mongo, gridfsBucketName, id);
}

private ubyte[] gridfsReadFileById(MongoConnection mongo, const string gridfsBucketName,
                                   const ObjectId id) {
    import std.outbuffer;

    OutBuffer contents = new OutBuffer();
    string collectionName = gridfsBucketName ~ ".chunks";

    OP_REPLY reply = mongo.query(collectionName, 0, int.max,
                                 document([bson_value("files_id", id)]));
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }

    foreach (doc; reply.documents) {
        contents.write(doc["data"].get!(const(ubyte[])));
    }

    // fetch remaining documents if any
    while (reply.cursorID != 0) {
        reply = mongo.getMore(collectionName, int.max, reply.cursorID);
        if (reply.errorCode != 0) {
            throw new Exception(reply.errorMessage);
        }
        foreach (doc; reply.documents) {
            contents.write(doc["data"].get!(const(ubyte[])));
        }
    }

    return contents.toBytes;
}
