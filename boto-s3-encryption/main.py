import boto
from boto import s3
from boto.s3.key import Key
from boto.s3.connection import Location
import json
import time

if not boto.config.get('s3', 'use-sigv4'):
    boto.config.add_section('s3')
    boto.config.set('s3', 'use-sigv4', 'True')


bucket_name = "encryption-test-%s" % int(time.time())

connection = s3.connect_to_region("eu-west-1")


def create_or_get_bucket(connection, policy):
    bucket = None
    try:
        bucket = connection.get_bucket(bucket_name)
    except:
        bucket = connection.create_bucket(bucket_name, location=Location.EU)

    bucket.set_policy(json.dumps(policy))

    return bucket

policy = {
    "Version":"2012-10-17",
    "Id":"PutObjPolicy",
    "Statement":[{
        "Sid":"DenyUnEncryptedObjectUploads",
        "Effect":"Deny",
        "Principal":"*",
        "Action":"s3:PutObject",
        "Resource":("arn:aws:s3:::%s/*") % bucket_name,
        "Condition": {
            "StringNotEquals": {
                "s3:x-amz-server-side-encryption":"aws:kms"
            }
        }
    }]
}

bucket = create_or_get_bucket(connection, policy)



headers = {
    "x-amz-server-side-encryption": "aws:kms",
    #"x-amz-server-side-encryption-aws-kms-key-id": "zzzzz"
}

key = Key(bucket, "foobar")
key.set_contents_from_string("foobar", headers=headers)
# this line throws because of 
# https://github.com/boto/boto/blob/develop/boto/s3/key.py#L980



bucket.delete()
