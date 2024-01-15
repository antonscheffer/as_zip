CREATE OR REPLACE package as_zip
is
/**********************************************
**
** Author: Anton Scheffer
**
** Changelog:
**   Date: 12-11-2023
**     Added p_filter to get_file_names and get_file_list
**     Added p_is_directory to add_file
**     Removed use_winzip_encryption
**     Removed p_nfile_name from get_file
**   Date: 18-03-2023
**     Added get_file_names
**   Date: 29-12-2022
**     fixed decryption of encrypted files
**   Date: 27-09-2022
**     Added set_comment, fixed get_comment
**   Date: 10-09-2022
**     add delete_file, add_file, get_count, get_comment and get_file_info
**     add character set any_cs to parameter p_file_name
**        this makes p_nfile_name obsolete
**   Date: 17-05-2022 shredder2003
**     add p_comment parameter to finish_zip
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
Copyright (C) 2010-2023 by Anton Scheffer

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

  use_dbms_crypto       constant boolean := false;
  use_utl_file          constant boolean := false;
  --
  type file_list is table of clob;
  type file_names is table of varchar2(4000);
  --
  type file_info is record
    ( found        boolean
    , is_directory boolean
    , is_encrypted boolean
    , idx     integer
    , len     integer
    , clen    integer
    , name    clob
    , comment clob
    , nname   nvarchar2(32767)
    );
  --
  function get_file_list
    ( p_zipped_blob      blob
    , p_encoding         varchar2 := null
    , p_start_entry      integer  := null
    , p_max_entries      integer  := null
    , p_filter           varchar2 := null
    , p_case_insensitive boolean  := null
    )
  return file_list;
  --
  function get_file_list
    ( p_dir              varchar2
    , p_zip_file         varchar2
    , p_encoding         varchar2 := null
    , p_start_entry      integer  := null
    , p_max_entries      integer  := null
    , p_filter           varchar2 := null
    , p_case_insensitive boolean  := null
    )
  return file_list;
  --
  function get_file_names
    ( p_zipped_blob      blob
    , p_encoding         varchar2 := null
    , p_start_entry      integer  := null
    , p_max_entries      integer  := null
    , p_filter           varchar2 := null
    , p_case_insensitive boolean  := null
    )
  return file_names;
  --
  function get_file_names
    ( p_dir              varchar2
    , p_zip_file         varchar2
    , p_encoding         varchar2 := null
    , p_start_entry      integer  := null
    , p_max_entries      integer  := null
    , p_filter           varchar2 := null
    , p_case_insensitive boolean  := null
    )
  return file_names;
  --
  function get_file
    ( p_zipped_blob blob
    , p_file_name   varchar2 character set any_cs := null
    , p_encoding    varchar2 := null
    , p_idx         number := null
    , p_password    varchar2 := null
    )
  return blob;
  --
  function get_file
    ( p_dir        varchar2
    , p_zip_file   varchar2
    , p_file_name  varchar2 character set any_cs := null
    , p_encoding   varchar2 := null
    , p_idx        number := null
    , p_password   varchar2 := null
    )
  return blob;
  --
  procedure add1file
    ( p_zipped_blob in out nocopy blob
    , p_name      varchar2 character set any_cs
    , p_content   blob
    , p_password  varchar2 := null
    , p_date      date     := null
    , p_zipcrypto boolean  := null
    );
--
  procedure finish_zip
    ( p_zipped_blob in out nocopy blob
    , p_comment varchar2 default null
    );
--
  procedure save_zip
    ( p_zipped_blob blob
    , p_dir         varchar2
    , p_filename    varchar2
    );
--
  function file2blob
    ( p_dir varchar2
    , p_file_name varchar2
    )
  return blob;
--
  function get_count( p_zipped_blob blob )
  return integer;
--
  function get_comment( p_zipped_blob blob )
  return clob;
--
  function get_file_info
    ( p_zipped_blob blob
    , p_name        varchar2 character set any_cs := null
    , p_idx         number := null
    , p_encoding    varchar2 := null
    )
  return file_info;
--
  function get_file_info
    ( p_zipped_blob blob
    , p_file_info in out file_info
    , p_name        varchar2 character set any_cs := null
    , p_idx         number := null
    , p_encoding    varchar2 := null
    )
  return boolean;
--
  procedure delete_file
    ( p_zipped_blob in out nocopy blob
    , p_name     varchar2 character set any_cs := null
    , p_idx      number := null
    , p_encoding varchar2 := null
    );
--
  procedure add_file
    ( p_zipped_blob in out nocopy blob
    , p_name         varchar2 character set any_cs
    , p_content      blob     := null
    , p_comment      varchar2 character set any_cs := null
    , p_password     varchar2 := null
    , p_date         date     := null
    , p_zipcrypto    boolean  := null
    , p_is_directory boolean  := null
    );
--
  procedure add_csv
    ( p_zipped_blob in out nocopy blob
    , p_cursor      in out sys_refcursor
    , p_name           varchar2 character set any_cs
    , p_comment        varchar2 character set any_cs := null
    , p_password       varchar2 := null
    , p_date           date     := null
    , p_separator      varchar2 := ','
    , p_enclosed_by    varchar2 := '"'
    , p_newline        varchar2 := null
    , p_column_headers boolean  := null
    , p_bulk_size      pls_integer := null
    , p_encoding       varchar2 := null
    , p_zipcrypto      boolean  := null
    );
--
  procedure set_comment
    ( p_zipped_blob in out nocopy blob
    , p_comment varchar2 character set any_cs := null
    );
--
end;
/
