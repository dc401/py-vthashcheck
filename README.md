# py-vthashcheck
A proof of concept AWS Lambda Python 3.7 runtime that takes Amazon S3 objects, evaluates against file magic MIME types, and will check existing SHA256 hashes or upload the file to VirusTotal using an API key. The API key is retrieved using security best practices with AWS Secrets Manager cached to reduce API overhead.

### Walkthrough
[Threat Informed Defense with AWS Lambda and VirusTotal](https://medium.com/@dwchow/threat-informed-defense-with-aws-lambda-and-virustotal-35512ca32a17)


## Usage

 - Ensure you have the appropriate VirusTotal API key (for commerical or high volume use, you must purchase their licensed premium API key)
 - Create an IAM policy and role for your Lamba to include read permissions for the AWS Secrets Manager ARN, S3 objects, and writing to CloudWatch Logs
 - Create a 'plaintext' secret type in AWS Secrets Manager and optionally specify a KMS-CMK for encryption
 - Download the deployment package zip file, extract the lambda_handler.py and modify to fit your deployment requirements including ARNs, API keys, try/except logic, and MIME file magic evaluation logic
 - Add the revised lambda_handler.py back into the zip (the deployment package already has all the dependencies in its root)
 - Create a AWS Lambda Function with the Python 3.7 runtime
 - Upload from local or another S3 bucket the deployment package zip file that you have revised
 - Set the trigger to be put objects to your root of your S3 bucket
 - Set the appropriate sizing and concurrency limits of your lambda e.g. memory
 - Attach the IAM role to your Lambda function
 - Upload a file to your target S3 bucket
 - Check the output of your Lambda runtime in Cloudwatch logs

### Modifying lambda_function.py

    mkdir py-vthashcheck && cd py-vthashcheck
    unzip py-vthashcheck-deployment-package.zip ./
    vim lambda_function.py #make your edits and wq
    # OPTIONAL: if you have new dependencies run: 
    # pip install --target ./package <packagename>
    # cd package
    # zip -r ../py-vthashcheck-deployment-package.zip .
    # cd ..
    zip py-vthashcheck-deployment-package.zip lambda_function.py
    # OPTIONAL: copy your deployment package to an S3 bucket for faster deployment upload
    # aws s3 cp ./py-vthashcheck-deployment-package.zip s3://<YOURBUCKET>
    

## Diagram
![enter image description here](https://github.com/dc401/py-vthashcheck/blob/main/py-vthashcheck-logical-diagram.png?raw=true)

## Default Output
This is the default output into CloudWatch logs when a 'malicious' payload is discovered by VirusTotal in the hash check known to the community. In this case it was an EICAR payload in the text file. If you want different actions and results you will need to modify the code.
![enter image description here](https://github.com/dc401/py-vthashcheck/blob/main/py-vthashcheck-sample-cwoutput-EICAR-txtfile.png?raw=true)

## Author

    Dennis Chow dchow[AT]xtecsystems.com
    March 18, 2023
    This is considered free and open to the public. No expressed liability or warranty.
