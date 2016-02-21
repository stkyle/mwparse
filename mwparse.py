# map a windows pe file to the cybox data model
#schema: https://cybox.mitre.org/language/version2.1/xsddocs/objects/Win_Executable_File_Object_xsd.html

import hashlib
import stix
import pefile
import cybox
import cybox.objects
import cybox.objects.file_object
import cybox.objects.win_executable_file_object
import cybox.objects.win_file_object
import cybox.core
from cybox.common import HexBinary
from cybox.common import HashList, NonNegativeInteger, Long, String, DateTime, Integer
from cybox.objects.win_file_object import WinFile
from cybox.objects.win_executable_file_object import PEImportedFunction
from cybox.objects.win_executable_file_object import PEImportedFunctions
from cybox.objects.win_executable_file_object import PEImportList
from cybox.objects.win_executable_file_object import PEImport
from cybox.objects.win_executable_file_object import PEBuildInformation
from cybox.objects.win_executable_file_object import DigitalSignature

build_information = PEBuildInformation()
build_information.compiler_name = String('')
build_information.compiler_version = String('')
build_information.linker_name = String('')
build_information.linker_version = String('')

digital_signature = DigitalSignature()
digital_signature.certificate_issuer = String('')
digital_signature.certificate_subject = String('')
digital_signature.signature_description = String('')
digital_signature.signature_exists = None
digital_signature.signature_verified = None

# exports
exports = PEExports()
exports.exported_functions = PEExportedFunctions()
exports.exports_time_stamp = DateTime()
exports.name = String()
exports.number_of_addresses = Long()
exports.number_of_functions = Integer()
exports.number_of_names = Long()

# The Extraneous_Bytes field specifies the number of extraneous bytes contained in the PE binary.
extraneous_bytes = Integer()

headers = PEHeaders()

imports = PEImportList()

pe_checksum = PEChecksum()

resources = PEResourceList()

sections = PESectionList()

type_ = String()


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
# IMAGE_NT_OPTIONAL_HDR_MAGIC
# The file is an executable image. This value is defined as IMAGE_NT_OPTIONAL_HDR32_MAGIC
# in a 32-bit application and as IMAGE_NT_OPTIONAL_HDR64_MAGIC in a 64-bit application.
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
# The file is an executable image.
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
# The file is an executable image.
IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
# The file is a ROM image.

target =r'C:\Program Files\Internet Explorer\iexplore.exe'
def get_md5(filepath):
    _data = None
    with open(filepath, 'rb') as f:
        _data = f.read()
    return hashlib.md5(_data).hexdigest()

def get_sha1(filepath):
    _data = None
    with open(filepath, 'rb') as f:
        _data = f.read()
    return hashlib.sha1(_data).hexdigest()

def get_sha256(filepath):
    _data = None
    with open(filepath, 'rb') as f:
        _data = f.read()
    return hashlib.sha256(_data).hexdigest()

h = HashList.from_list([{'type' : 'MD5', 'simple_hash_value' : get_md5(target)},
                        {'type' : 'SHA1', 'simple_hash_value' : get_sha1(target)},
                        {'type' : 'SHA256', 'simple_hash_value' :get_sha256(target)}])



pe = pefile.PE(target)

dos_header = cybox.objects.win_executable_file_object.DOSHeader()
file_header = cybox.objects.win_executable_file_object.PEFileHeader()
winfile = cybox.objects.win_executable_file_object.WinExecutableFile()
pe_headers = cybox.objects.win_executable_file_object.PEHeaders()

# e_magic   : Word;                   // Magic number ("MZ")
dos_header.e_magic = HexBinary(hex(pe.DOS_HEADER.e_magic)) # HexBinary(hex(pe.DOS_HEADER.e_magic)[2:])
# e_cblp    : Word;                   // Bytes on last page of file
dos_header.e_cblp = hex(pe.DOS_HEADER.e_cblp)
# e_cp      : Word;                   // Pages in file
dos_header.e_cp = hex(pe.DOS_HEADER.e_cp)
# e_crlc    : Word;                   // Relocations
dos_header.e_crlc = hex(pe.DOS_HEADER.e_crlc)
# e_cparhdr : Word;                   // Size of header in paragraphs
dos_header.e_cparhdr = hex(pe.DOS_HEADER.e_cparhdr)
# e_minalloc: Word;                   // Minimum extra paragraphs needed
dos_header.e_minalloc = hex(pe.DOS_HEADER.e_minalloc)
# e_maxalloc: Word;                   // Maximum extra paragraphs needed
dos_header.e_maxalloc = hex(pe.DOS_HEADER.e_maxalloc)
# e_ss      : Word;                   // Initial (relative) SS value
dos_header.e_ss = hex(pe.DOS_HEADER.e_ss)
# e_sp      : Word;                   // Initial SP value
dos_header.e_sp = hex(pe.DOS_HEADER.e_sp)
# e_csum    : Word;                   // Checksum
dos_header.e_csum = hex(pe.DOS_HEADER.e_csum)
# e_ip      : Word;                   // Initial IP value
dos_header.e_ip = hex(pe.DOS_HEADER.e_ip)
# e_cs      : Word;                   // Initial (relative) CS value
dos_header.e_cs = hex(pe.DOS_HEADER.e_cs)
# e_lfarlc  : Word;                   // Address of relocation table
dos_header.e_lfarlc = hex(pe.DOS_HEADER.e_lfarlc)
# e_ovno    : Word;                   // Overlay number
# see http://www.tavi.co.uk/phobos/exeformat.html#overlaynote for more information about overlays
dos_header.e_ovno = hex(pe.DOS_HEADER.e_ovno)
dos_header.e_ovro = hex(pe.DOS_HEADER.e_ovno) # there is a typo in cybox e_ovro -> e_ovno
# e_res     : packed array [0..3] of Word;  // Reserved words
#dos_header.e_res = hex(pe.DOS_HEADER.e_res)[2:]
# e_oemid   : Word;                   // OEM identifier (for e_oeminfo)
dos_header.e_oemid = hex(pe.DOS_HEADER.e_oemid)
# e_oeminfo : Word;                   // OEM info; e_oemid specific
dos_header.e_oeminfo = hex(pe.DOS_HEADER.e_oeminfo)
# e_res2    : packed array [0..9] of Word;  // Reserved words
#dos_header.e_res2 = hex(pe.DOS_HEADER.e_res2)[2:]
# e_lfanew  : Longint;                // File address of new exe header
dos_header.e_lfanew = hex(pe.DOS_HEADER.e_lfanew)

import sys
import os

file_header.machine = HexBinary(hex(pe.FILE_HEADER.Machine))
file_header.number_of_sections = NonNegativeInteger(pe.FILE_HEADER.NumberOfSections)
file_header.time_date_stamp = hex(pe.FILE_HEADER.TimeDateStamp)
file_header.pointer_to_symbol_table = hex(pe.FILE_HEADER.PointerToSymbolTable)
file_header.number_of_symbols = NonNegativeInteger(pe.FILE_HEADER.NumberOfSymbols)
file_header.size_of_optional_header = hex(pe.FILE_HEADER.SizeOfOptionalHeader)
file_header.characteristics = hex(pe.FILE_HEADER.Characteristics)



pe_headers.file_header = file_header
pe_headers.dos_header = dos_header
winfile.headers = pe_headers
winfile.hashes = h

winfile.file_name = os.path.split(target)[1]
winfile.file_extension = os.path.split(target)[1].split('.')[-1]
winfile.size_in_bytes = os.path.getsize(target)




for s in pe.sections:
    print s
    print 'Entropy: %s' % s.get_entropy()

print pe.OPTIONAL_HEADER

import_list = PEImportList()

for d in pe.DIRECTORY_ENTRY_IMPORT:
    ped = PEImport()
    ped.imported_functions = PEImportedFunctions()
    ped.file_name = d.dll
    print 'directory.entry: %s' % d.dll
    print d.struct
    print vars(d).keys()
    for imp in d.imports:
        pe_if = PEImportedFunction()
        print 'import.name: %s' % imp.name
        #print vars(imp).keys()
        pe_if.function_name = imp.name
        if pe_if.ordinal:
            pe_if.ordinal = NonNegativeInteger(imp.ordinal)
        imp.struct_iat
        imp.hint_name_table_rva
        if imp.hint:
            pe_if.hint = HexBinary(hex(imp.hint))
        #imp.pe
        if imp.bound:
            pe_if.bound = HexBinary(hex(imp.bound))
        imp.struct_table
        imp.ordinal_offset
        imp.thunk_offset
        imp.import_by_ordinal
        pe_if.virtual_address = HexBinary(hex(imp.address))
        imp.thunk_rva
        imp.name_offset
        ped.imported_functions.append(pe_if)

        #print imp.name
        #print imp.ordinal
        #print imp.struct_table
    #print d.imports
    #print d.struct
    #print d.dll
    import_list.append(ped)

winfile.imports = import_list

if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal

from pprint import pprint
pprint(vars(pe).keys())


print pe.NT_HEADERS
print pe.RICH_HEADER
print vars(pe.DIRECTORY_ENTRY_RESOURCE).keys()
print vars(pe.DIRECTORY_ENTRY_RESOURCE.entries[0])
print vars(pe.DIRECTORY_ENTRY_TLS)
print pe.PE_TYPE
from cybox.objects.win_executable_file_object import PEChecksum
pe_checksum = PEChecksum()

# https://cybox.mitre.org/language/version2.1/xsddocs/objects/Win_Executable_File_Object_xsd.html#PEChecksumType_PE_File_API
pe_checksum.pe_computed_api = Long(pe.generate_checksum())
pe_checksum.pe_file_api = Long(pe.NT_HEADERS.OPTIONAL_HEADER.CheckSum) #None # computed by imagehlp.dll
pe_checksum.pe_file_raw = Long(pe.OPTIONAL_HEADER.CheckSum)
winfile.pe_checksum =pe_checksum
print winfile.to_xml(include_namespaces=False)
print pe.OPTIONAL_HEADER.CheckSum
pprint(vars(pe.NT_HEADERS).keys())
print pe.NT_HEADERS.OPTIONAL_HEADER
pprint(vars(pe.NT_HEADERS.OPTIONAL_HEADER).keys())
pprint(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY)
print vars(pe.NT_HEADERS.OPTIONAL_HEADER)

IMAGE_DIRECTORY_ENTRY_SECURITY = None
for d in pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY:
    if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
        IMAGE_DIRECTORY_ENTRY_SECURITY = d

print vars(IMAGE_DIRECTORY_ENTRY_SECURITY)
print hex(IMAGE_DIRECTORY_ENTRY_SECURITY.VirtualAddress)
print hex(IMAGE_DIRECTORY_ENTRY_SECURITY.Size)
signature_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
signature_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
print signature_size
print hex(signature_size)
signature = pe.write()[signature_address+8:signature_address+8+signature_size]
from OpenSSL import crypto
key = crypto.PKey()
from Crypto.PublicKey import RSA
from Crypto import Signature
from Crypto.Util.asn1 import DerSequence
cert = DerSequence()



pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, signature)
print pkcs7.get_type_name()
print pkcs7.type_is_signed()
print pkcs7.type_is_data()
print pkcs7.type_is_enveloped()

der = ssl.DER_cert_to_PEM_cert(signature)
from cryptography.hazmat.backends.interfaces import X509Backend
be = X509Backend()
c=be.load_der_x509_certificate(signature)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
cert = x509.load_der_x509_certificate(signature, default_backend())
from pyasn1_modules import rfc5208


with open('sig.p7','wb') as f:
    f.write(signature)
