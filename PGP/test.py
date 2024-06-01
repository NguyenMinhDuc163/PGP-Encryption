
import pgpy.constants
import warnings

from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# tạo khóa pgp dùng RSA
key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 4096)

# Tạo User ID (tùy chọn)
uid = pgpy.PGPUID.new('Pham Minh Duc', comment='DuckTheDuck', email='duck@example.com')

# Thêm UserID vào khóa (tùy chọn)
key.add_uid(uid, usage={pgpy.constants.KeyFlags.Sign, pgpy.constants.KeyFlags.EncryptCommunications, pgpy.constants.KeyFlags.EncryptStorage},
            hashes=[pgpy.constants.HashAlgorithm.SHA256, pgpy.constants.HashAlgorithm.SHA384, pgpy.constants.HashAlgorithm.SHA512, pgpy.constants.HashAlgorithm.SHA224],
            ciphers=[pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.SymmetricKeyAlgorithm.AES192, pgpy.constants.SymmetricKeyAlgorithm.AES128],
            compression=[pgpy.constants.CompressionAlgorithm.ZLIB, pgpy.constants.CompressionAlgorithm.BZ2, pgpy.constants.CompressionAlgorithm.ZIP, pgpy.constants.CompressionAlgorithm.Uncompressed])

public=key.pubkey
key.protect("duc19112003", pgpy.constants.SymmetricKeyAlgorithm.AES256,pgpy.constants.HashAlgorithm.SHA256)
# with open("D:\test.txt","r") as f:
#     msg=f.read()
msg="Demo tin nhan PGP"
with open("public.asc","w") as f:
    f.write(str(key))

text=pgpy.PGPMessage.new(msg)

emsg=public.encrypt(text)

print("Key: ",key)
print("Public: ",public)
print("Văn bản gốc: ",msg)
print("Văn bản mã hóa: ",emsg)
with key.unlock("duc19112003"):
    print("Văn bản giải mã: ", key.decrypt(emsg).message)