# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

class DataCatalogObjectFlags(object):
    # objects generated by a job
    Generated = 1
    # Object contents are encrypted. When this is set the `obj` field is an
    # EncryptedObject instance.
    Encrypted = 2
    # Object has a cryptographic signature
    Signed = 4