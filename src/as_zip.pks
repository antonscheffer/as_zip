CREATE OR REPLACE package as_zip
is
/**********************************************
**
** Author: Anton Scheffer
** Date: 25-01-2012
** Website: http://technology.amis.nl/blog
**
** Changelog:
**   Date: 20-09-2021
**     major rewrite
**     more support for deflate64
**     read zip64
**     Winzip AES encryption
**   Date: 04-08-2016
**     fixed endless loop for empty/null zip file
**   Date: 28-07-2016
**     added support for defate64 (this only works for zip-files created with 7Zip)
**   Date: 31-01-2014
**     file limit increased to 4GB
**   Date: 29-04-2012
**    fixed bug for large uncompressed files, thanks Morten Braten
**   Date: 21-03-2012
**     Take CRC32, compressed length and uncompressed length from
**     Central file header instead of Local file header
**   Date: 17-02-2012
**     Added more support for non-ascii filenames
**   Date: 25-01-2012
**     Added MIT-license
**     Some minor improvements
******************************************************************************
******************************************************************************
Copyright (C) 2010,2021 by Anton Scheffer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

******************************************************************************
******************************************** */

  use_winzip_encryption constant boolean := true;
  use_dbms_crypto       constant boolean := true;
  --
  type file_list is table of clob;
  --
  function get_file_list
    ( p_zipped_blob blob
    , p_encoding varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_list;
  --
  function get_file_list
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_encoding varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_list;
  --
  function get_file
    ( p_zipped_blob blob
    , p_file_name varchar2 := null
    , p_encoding varchar2 := null
    , p_nfile_name nvarchar2 := null
    , p_idx number := null
    , p_password varchar2 := null
    )
  return blob;
  --
  function get_file
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_file_name varchar2
    , p_encoding varchar2 := null
    , p_nfile_name nvarchar2 := null
    , p_idx number := null
    , p_password varchar2 := null
    )
  return blob;
  --
  procedure add1file
    ( p_zipped_blob in out blob
    , p_name varchar2
    , p_content blob
    , p_password varchar2 := null
    );
--
  procedure finish_zip( p_zipped_blob in out blob );
--
  procedure save_zip
    ( p_zipped_blob blob
    , p_dir varchar2
    , p_filename varchar2
    );
end;
/
