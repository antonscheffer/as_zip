# as_zip
A PLSQL package to get a file from a zip-file into a blob, and to create a zip-file from file(s) based on a/some blob(s).

* Can read deflate64 format
* Can read zip64 format
* with Winzip and zipcrypto encryption

Any simularities with [APEX_ZIP](https://docs.oracle.com/cd/E59726_01/doc.50/e39149/apex_zip.htm#AEAPI29942) and this [as_zip repository](https://github.com/yallie/as_zip) are no coincidence: both are based on my code, see https://technology.amis.nl/it/parsing-a-microsoft-word-docx-and-unzip-zipfiles-with-plsql/
# Conditional compilation
In the package spec are 3 constants which control the conditional compilation of the package body:
* use_winzip_encryption constant boolean := true;
* use_dbms_crypto       constant boolean := false;
* use_utl_file          constant boolean := true;  

With those constant you can control usage (and required grant) of the Oracle packages dbms_crypto and utl_file.  
dbms_crypto is used for the Winzip AES encrypting, if you disable usage of dbms_crypto a much slower version is used, see [as_crypto](https://github.com/antonscheffer/as_crypto)  
utl_file is only used in as_zip.save_zip, you have to decide for yourself it you need that.
