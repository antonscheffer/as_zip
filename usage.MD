# Creating a zip-file
To create a zip-file use either 1 or more times as_zip.add1file and finish with as_zip.finish_zip.

<pre><code>declare
  l_zip blob;
  l_txt clob;
  l_txt_blob blob;
  l_dest_offset integer := 1;
  l_src_offset  integer := 1;
  l_context     integer := dbms_lob.default_lang_ctx;
  l_warning     integer;
  l_csid        integer := nls_charset_id( 'CHAR_CS' );
begin
  dbms_lob.createtemporary( l_txt, true );
  for i in 1 .. 1000
  loop
    l_txt := l_txt || ( 'line ' || i || ': some easy to compress text on this line' || chr(13) || chr(10) );
  end loop;
  dbms_lob.createtemporary( l_txt_blob, true );
  dbms_lob.converttoblob( l_txt_blob, l_txt, dbms_lob.lobmaxsize, l_dest_offset, l_src_offset, l_csid, l_context, l_warning );
  --
  as_zip.add1file( l_zip, 'file1.txt', l_txt_blob );
  as_zip.finish_zip( l_zip, 'Zipfile containing one file with uncompressed size of '
                         || dbms_lob.getlength( l_txt_blob ) || '  bytes' );
  --
  dbms_lob.freetemporary( l_txt );
  dbms_lob.freetemporary( l_txt_blob );
  --
  as_zip.save_zip( l_zip, 'VAGRANT', 'zip2.zip' );
  dbms_lob.freetemporary( l_zip );
end;</code></pre>
<pre><code>declare
  l_zip blob;
  l_txt clob;
  l_txt_blob blob;
  l_dest_offset integer := 1;
  l_src_offset  integer := 1;
  l_context     integer := dbms_lob.default_lang_ctx;
  l_warning     integer;
  l_csid        integer := nls_charset_id( 'CHAR_CS' );
begin
  for f in 1 .. 5
  loop
    dbms_lob.createtemporary( l_txt, true );
    for i in 1 .. 30
    loop
      l_txt := l_txt || ( 'line ' || i || ': some easy to compress text on this line' || chr(13) || chr(10) );
    end loop;  
    l_dest_offset := 1;
    l_src_offset  := 1;
    l_context     := dbms_lob.default_lang_ctx;
    dbms_lob.createtemporary( l_txt_blob, true );
    dbms_lob.converttoblob( l_txt_blob, l_txt, dbms_lob.lobmaxsize, l_dest_offset, l_src_offset, l_csid, l_context, l_warning );
    --
    as_zip.add1file( l_zip, 'file' || f || '.txt', l_txt_blob );
  end loop;
  as_zip.finish_zip( l_zip, 'Zipfile containing 5 files' );
  --
  dbms_lob.freetemporary( l_txt );
  dbms_lob.freetemporary( l_txt_blob );
  --
  as_zip.save_zip( l_zip, 'VAGRANT', 'zip2.zip' );
  dbms_lob.freetemporary( l_zip );
end;</code></pre>
Or use one or more times as_zip.add_file. as_zip.add_file always leaves a valid and complete zip-file and can be used to add a file to anexisting zip-file.

<pre><code>declare
  l_zip blob;
  l_txt clob;
  l_txt_blob blob;
  l_dest_offset integer := 1;
  l_src_offset  integer := 1;
  l_context     integer := dbms_lob.default_lang_ctx;
  l_warning     integer;
  l_csid        integer := nls_charset_id( 'CHAR_CS' );
begin
  for f in 1 .. 5
  loop
    dbms_lob.createtemporary( l_txt, true );
    for i in 1 .. 30
    loop
      l_txt := l_txt || ( 'line ' || i || ': some easy to compress text on this line' || chr(13) || chr(10) );
    end loop;  
    l_dest_offset := 1;
    l_src_offset  := 1;
    l_context     := dbms_lob.default_lang_ctx;
    dbms_lob.createtemporary( l_txt_blob, true );
    dbms_lob.converttoblob( l_txt_blob, l_txt, dbms_lob.lobmaxsize, l_dest_offset, l_src_offset, l_csid, l_context, l_warning );
    --
    as_zip.add_file( l_zip, 'file' || f || '.txt', l_txt_blob, 'This is file ' || f );
  end loop;
  --
  dbms_lob.freetemporary( l_txt );
  dbms_lob.freetemporary( l_txt_blob );
  --
  as_zip.save_zip( l_zip, 'VAGRANT', 'zip3.zip' );
  dbms_lob.freetemporary( l_zip );
end;</code></pre>
