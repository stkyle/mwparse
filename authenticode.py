#

"""
SignedData ::= SEQUENCE {
  version Version,
  digestAlgorithms DigestAlgorithmIdentifiers,
  contentInfo ContentInfo,
  certificates
    	[0] IMPLICIT ExtendedCertificatesAndCertificates
       OPTIONAL,
  Crls
    [1] IMPLICIT CertificateRevocationLists OPTIONAL,
  signerInfos SignerInfos }

DigestAlgorithmIdentifiers ::=
  SET OF DigestAlgorithmIdentifier

ContentInfo ::= SEQUENCE {
  contentType ContentType,
  content
    [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

ContentType ::= OBJECT IDENTIFIER

SignerInfos ::= SET OF SignerInfo
"""
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1_modules import rfc2315
from pyasn1_modules.rfc2315 import *
from pyasn1_modules.rfc2315 import SignedData, Version
from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder
from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))

def decode(signature):
    contentInfo, _ = der_decoder.decode(signature, asn1Spec=rfc2315.ContentInfo())
    contentType = contentInfo.getComponentByName('contentType')
    
    contentInfoMap = {
        (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
        (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
        (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
        (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
        (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
        (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
        }
    
    content, _ = der_decoder.decode(
        contentInfo.getComponentByName('content'),
        asn1Spec=contentInfoMap[contentType]
        )
    
    return content

print content.getComponentByName('version')
print content.getComponentByName('certificates')
print content.getComponentByName('digestAlgorithms')
print content.getComponentByName('contentInfo')
