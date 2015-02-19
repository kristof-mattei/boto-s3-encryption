from boto.s3.connection import S3Connection
import time

connection = S3Connection("eu-west-1")
bucket_name = "encryption-test-%s" % time.time()

def create_or_get_bucket(connection, policy):
    bucket = None
    try:
        bucket = connection.get_bucket(bucket_name)
    except:
        bucket = connection.create_bucket(bucket_name)

    bucket.set_policy(json.dumps(policy))

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
    "x-amz-server-side-encryption-aws-kms-key-id": "ARN GOES HERE"
}
#
# key = Key(bucket, "foobar")
# key.key = "what?"
# key.set_contents_from_string()
