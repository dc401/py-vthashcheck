# py-vthashcheck
A proof of concept AWS Lambda Python 3.7 runtime that takes Amazon S3 objects, evaluates against file magic MIME types, and will check existing SHA256 hashes or upload the file to VirusTotal using an API key. The API key is retrieved using security best practices with AWS Secrets Manager cached to reduce API overhead.
