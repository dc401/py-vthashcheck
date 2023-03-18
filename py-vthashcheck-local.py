#!/usr/bin/env python3
#pip3 install vt-py alias to vt
import hashlib, vt , json, magic

# Dennis Chow dchow[AT]xtecsystems.com 03/18/2023
# Find more at https://github.com/dc401 and my blog series at https://dwchow.medium.com
# Partial code inspired from references below

#variables  here
filename_var = str('testfoo.txt')

def get_sha256(filename, buffer_size=2**10*8):
  with open(filename, "rb") as f:
      file_hash = hashlib.sha256()
      while chunk := f.read(buffer_size):
          file_hash.update(chunk)
  return file_hash.hexdigest()

### Main driver ###

hashvalue = get_sha256(filename_var)
hashvalue = str(hashvalue)
print("Bucket object SHA256: " +hashvalue)

#check for file magic
file_type = magic.from_file(filename_var, mime=True)
print("Bucket object filetype is: " + file_type)

client = vt.Client('<USE_YOUR_OWN_API_KEY>')
try: 
    # Change to MIME bin type #
    if "text" in str(file_type):
        vt_filecheck = client.get_object("/files/" + hashvalue)
        print(vt_filecheck.last_analysis_stats)
        result_data = vt_filecheck.last_analysis_stats
        if result_data["malicious"] > 0 or result_data["suspicious"] > 0:
            print('uh oh')
        client.close()
#client API error raise type: "#vt.error.APIError: ('NotFoundError', 'File "<HASH>" not found')"
except vt.error.APIError as e:
    if "NotFoundError" in str(e):
        if "text" in str(file_type):
            #if not already uploaded perform an upload
            #print('foo')
            with open(filename_var, 'rb') as file_upload:
                analysis = client.scan_file(file_upload, wait_for_completion=True) #careful this could take up to 5 minutes to return
            print(analysis) 
            #output returned is base64 encoded "md5hash:jobid"
            client.close()


'''
#Code inspired from the following:
https://stackoverflow.com/questions/1131220/get-the-md5-hash-of-big-files-in-python
https://www.pythonmorsels.com/reading-binary-files-in-python/
https://virustotal.github.io/vt-py/quickstart.html#get-information-about-a-file
https://pypi.org/project/python-magic/
https://www.virustotal.com/gui/file/8f6b4f07705a4fd749864f6e1dc8557959bc6f5acf0f8581452badbf3e1b5055?nocache=1
https://www.virustotal.com/gui/file/71c9179e497dfe59fb16b55d47cd59c563b637503a52f16b4f15c3ace0845048/detection
https://virustotal.github.io/vt-py/quickstart.html#scan-a-file
https://developers.virustotal.com/reference/errors
https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
'''