#!/bin/bash
set -e -x -o pipefail

SERVER_VERSION=$(echo "db.version()" | mongo --quiet)

if [[ $SERVER_VERSION == 4* ]]; then
	echo "
	db.runCommand({createUser: 'sha1', pwd: 'sha1', roles: ['dbAdmin'], mechanisms: ['SCRAM-SHA-1']});
	db.runCommand({createUser: 'sha256', pwd: 'sha256', roles: ['dbAdmin'], mechanisms: ['SCRAM-SHA-256']});
	db.runCommand({createUser: 'both', pwd: 'both', roles: ['dbAdmin'], mechanisms: ['SCRAM-SHA-1', 'SCRAM-SHA-256']});
	db.runCommand({createUser: 'IX', pwd: 'IX', roles: ['dbAdmin'], mechanisms: ['SCRAM-SHA-1']});
	db.runCommand({createUser: '\u2168', pwd: '\u2163', roles: ['dbAdmin'], mechanisms: ['SCRAM-SHA-256']});
	" | mongo > /dev/null
else
	# MongoDB 3 didn't support SHA-256 yet
	echo "
	db.runCommand({createUser: 'sha1', pwd: 'sha1', roles: ['dbAdmin']});
	" | mongo > /dev/null
fi

function cleanup {
	echo "
	db.dropUser('\u2168');
	db.dropUser('IX');
	db.dropUser('both');
	db.dropUser('sha256');
	db.dropUser('sha1');
	" | mongo > /dev/null
}
trap cleanup EXIT

if [[ $SERVER_VERSION == 4* ]]; then
	rdmd -g -I../../source test_auth.d "" "" ""
	rdmd -g -I../../source test_auth.d SCRAM-SHA-1 sha1 sha1
	rdmd -g -I../../source test_auth.d FAIL sha1 invalidpw
	rdmd -g -I../../source test_auth.d FAIL invaliduser invalidpw
	# TODO: when supporting SHA256 both of the next ones change to SHA256
	rdmd -g -I../../source test_auth.d FAIL sha256 sha256
	rdmd -g -I../../source test_auth.d SCRAM-SHA-1 both both

	# saslprep test (SHA-256 only)
	#rdmd -g -I../../source test_auth.d SCRAM-SHA-256 IX IX
	#rdmd -g -I../../source test_auth.d SCRAM-SHA-256 IX 'I%C2%ADX'
	#rdmd -g -I../../source test_auth.d SCRAM-SHA-256 '%E2%85%A8' 'IV'
	#rdmd -g -I../../source test_auth.d SCRAM-SHA-256 '%E2%85%A8' 'I%C2%ADV'
else
	rdmd -g -I../../source test_auth.d "" "" ""
	rdmd -g -I../../source test_auth.d SCRAM-SHA-1 sha1 sha1
	rdmd -g -I../../source test_auth.d FAIL sha1 invalidpw
	rdmd -g -I../../source test_auth.d FAIL invaliduser invalidpw
fi
