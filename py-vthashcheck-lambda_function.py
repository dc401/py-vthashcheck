import hashlib, vt , json, magic, requests, boto3
import botocore 
import botocore.session 
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig

# Dennis Chow dchow[AT]xtecsystems.com 03/18/2023
# Find more at https://github.com/dc401 and my blog series at https://dwchow.medium.com
# Partial code inspired from references below

#client constructor outside function to keep warm invoke
s3 = boto3.client('s3')

#use the cache lib to keep the decrypted secret in memory for up to 1 hour
client = botocore.session.get_session().create_client('secretsmanager')
cache_config = SecretCacheConfig()
cache = SecretCache( config = cache_config, client = client)
secret = cache.get_secret_string('virustotal-api-key')

#utilize secret from secrets manager cache
vtclient = vt.Client(secret)
    

def lambda_handler(event, context):
    #obtain s3 object attributes
    bucket = event['Records'][0]["s3"]["bucket"]["name"]
    key = event['Records'][0]["s3"]["object"]["key"]
    
    #cache it to lambda ephemeral storage
    local_file = '/tmp/' + key
    s3.download_file(bucket, key, local_file)
    
    #stream in memory in 4k blocks
    sha256_hash = hashlib.sha256()
    #b notation is read stream in binary
    with open(local_file,"rb") as file:
        for byte_block in iter(lambda: file.read(4096),b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())
    hash_value = str(sha256_hash.hexdigest())
    
    print('object sha256: ' + ' ' +hash_value)
    
    #check for file magic
    file_type = magic.from_file(local_file, mime=True)
    print("object filetype: " + file_type)
    
    #do stuff when you find a particular MIME type
    try:
        #ensure you change mime type in the if statement from text to elf
        if "text" in str(file_type):
            vt_filecheck = vtclient.get_object("/files/" + hash_value)
            print(vt_filecheck.last_analysis_stats)
            result_data = vt_filecheck.last_analysis_stats
            if result_data["malicious"] > 0 or result_data["suspicious"] > 0:
                print('uh oh')
                vtclient.close()
    #client API error raise type: "#vt.error.APIError: ('NotFoundError', 'File "<HASH>" not found')"
    except vt.error.APIError as e:
        if "NotFoundError" in str(e):
            #if not already uploaded perform an upload
            #print('foo')
            with open(local_file, 'rb') as file_upload:
                #analysis = vtclient.scan_file(file_upload, wait_for_completion=True) #careful this could take up to 5 minutes to return
                analysis = vtclient.scan_file(file_upload, wait_for_completion=False)
                print(analysis) #output returned is base64 encoded "md5hash:jobid"
                client.close()
    return "success"