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
signeddata = 
from pyasn1.type import univ, namedtype, tag
class SignedData(univ.Sequence):
    Version = namedtype.NamedTypes(namedtype.NamedType('version', univ.Integer())
    digestAlgorithms

