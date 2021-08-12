all :
	dub build --root ../..
	dmd -I../../source test_gridfs.d ../../libmongo-standalone.a
	dmd -I../../source test_gridfs_many.d ../../libmongo-standalone.a
