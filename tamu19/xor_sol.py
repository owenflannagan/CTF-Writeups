import base64

ctxt = base64.b64decode("XUBdTFdScw5XCVRGTglJXEpMSFpOQE5AVVxJBRpLT10aYBpIVwlbCVZATl1WTBpaTkBOQFVcSQdH")

key = ":)"

flag = ""
for i in range(len(ctxt)):
    flag += chr(ord(ctxt[i]) ^ ord(key[i % 2]))

print flag
