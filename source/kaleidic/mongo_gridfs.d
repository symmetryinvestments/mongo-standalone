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
    return gridfsReadManyFiles(mongo, gridfsBucketName, [id])[id];
}

/++
   IN:     mongo            - active connection to the MongoDB instance.
           gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
           name             - file name
   RETURN: The entire file contents in an array.
   THROWS: File not found, or if more than 1 file match name, or on corrupt properties.
+/

ubyte[] gridfsReadFile(MongoConnection mongo, const string gridfsBucketName, const string name) {
    return gridfsReadManyFiles(mongo, gridfsBucketName, [name])[name];
}

/++
   IN:     mongo            - active connection to the MongoDB instance.
           gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
           ids              - array of file object IDs, i.e., their "_id" values.
   RETURN: An associative array containing id -> entire file content mappings.
   THROWS: File not found, or on corrupt properties.
+/

ubyte[][ObjectId] gridfsReadManyFiles(MongoConnection mongo, const string gridfsBucketName, const ObjectId[] ids) {
    import std.algorithm;
    import std.array;

    if (ids.length > int.max)
        throw new Exception("Number of requested objects exceeds int.max");

    // {"$or": [{"_id": id1}, {"_id": id2}, ... {"_id": idN}]}
    auto query = document([bson_value("$or", makeArray(ids, "_id"))]);

    OP_REPLY reply = mongo.query(gridfsBucketName ~ ".files", 0, cast(int)ids.length, query);
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }

    if (reply.documents.length != ids.length) {
        auto givenIds = ids.dup.sort();
        auto existingIds = reply.documents.map!(doc => doc["_id"].get!ObjectId).array.sort();
        auto missingIds = setDifference(givenIds, existingIds).map!(id => id.toString()).join(", ");
        throw new Exception("Requested file(s) not found. Missing id: " ~ missingIds);
    }

    return gridfsReadFilesById(mongo, gridfsBucketName, ids);
}

/++
   IN:     mongo            - active connection to the MongoDB instance.
           gridfsBucketName - full path to the GridFS parent of collections .files and .chunks.
           names            - array of file names.
   RETURN: An associative array containing file name -> entire file content mappings.
   THROWS: File not found, or if more than 1 file match name, or on corrupt properties.
+/

ubyte[][string] gridfsReadManyFiles(MongoConnection mongo, const string gridfsBucketName, const string[] names) {
    import std.algorithm;
    import std.array;
    import std.typecons;

    // {"$or": [{"filename": name1}, {"filename": name2}, ... {"filename": nameN}]}
    auto query = document([bson_value("$or", makeArray(names, "filename"))]);

    OP_REPLY reply = mongo.query(gridfsBucketName ~ ".files", 0, int.max, query);
    if (reply.errorCode != 0) {
        throw new Exception(reply.errorMessage);
    }

    if (reply.documents.length != names.length) {
        auto givenNames = names.dup().sort();
        auto existingNames = reply.documents.map!(doc => doc["filename"].get!string).array().sort();
        auto missingNames = setDifference(givenNames, existingNames).join(", ");
        throw new Exception("Requested file(s) not found. Missing file(s): " ~ missingNames);
    }

    string[ObjectId] mappings = reply.documents
        .map!(doc => tuple(doc["_id"].get!ObjectId, doc["filename"].get!string))
        .assocArray();

    auto result = gridfsReadFilesById(mongo, gridfsBucketName, mappings.keys)
        .byPair()
        .map!(tup => tuple(mappings[tup[0]], tup[1]))
        .assocArray();

    return result;
}

private ubyte[][ObjectId] gridfsReadFilesById(MongoConnection mongo, const string gridfsBucketName,
                                    const ObjectId[] ids) {
    import std.outbuffer;
    import std.algorithm;
    import std.array;
    import std.typecons;

    // {"$or": [{"files_id": id1}, {"files_id": id2}, ... {"files_id": idN}]}
    auto query = bson_value("$query", document([bson_value("$or", makeArray(ids, "files_id"))]));
    // order results by files_id and chunk number
    auto orderBy = bson_value("$orderby", document([bson_value("files_id", 1), bson_value("n", 1)]));
    auto queryDoc = document([query, orderBy]);

    string collectionName = gridfsBucketName ~ ".chunks";
    OutBuffer[ObjectId] result;

    auto handleReply = (OP_REPLY reply) {
        if (reply.errorCode != 0) {
            throw new Exception(reply.errorMessage);
        }
        foreach (doc; reply.documents) {
            if (doc["$err"] != bson_value.init) {
                throw new Exception(doc["$err"].get!string);
            }
            auto contents = result.require(doc["files_id"].get!ObjectId, new OutBuffer());
            contents.write(doc["data"].get!(const(ubyte[])));
        }
    };

    OP_REPLY reply = mongo.query(collectionName, 0, int.max, queryDoc);
    handleReply(reply);

    // fetch remaining documents if any
    while (reply.cursorID != 0) {
        reply = mongo.getMore(collectionName, int.max, reply.cursorID);
        handleReply(reply);
    }

    return result.byPair().map!(tup => tuple(tup[0], tup[1].toBytes())).assocArray();
}

private bson_value[] makeArray(T)(T[] xs, string key) {
    import std.algorithm;
    import std.range;
    import std.conv;

    return xs
        .enumerate()
        .map!(tup => bson_value(tup.index.to!string, document([bson_value(key, tup.value)])))
        .array();
}
