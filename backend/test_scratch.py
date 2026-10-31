import re

crypto_keywords = [
    "md5(", "MD5(", "MessageDigest.getInstance(\"MD5\")",
    "sha1(", "SHA1(", "MessageDigest.getInstance(\"SHA-1\")",
    "\"DES\"", "'DES'", "\"des\"", "'des'", "DES/", "/DES", "Cipher.DES",
    "\"RC4\"", "'RC4'", "\"rc4\"", "'rc4'", "RC4/", "ARC4",
    "\"ECB\"", "'ECB'", "/ECB",
    "createCipheriv(\"des", "createCipheriv(\"rc4",
    "hashlib.md5(", "hashlib.sha1(", "CryptoJS.MD5(",
]

line = "strcpy(dest, src);"
matches = [kw for kw in crypto_keywords if kw in line or (len(kw) > 3 and kw.lower() in line.lower())]
print("Matches on 'strcpy(dest, src)':", matches)

des_line = 'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");'
matches_des = [kw for kw in crypto_keywords if kw in des_line or (len(kw) > 3 and kw.lower() in des_line.lower())]
print("Matches on Cipher.getInstance DES:", matches_des)
