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
Or use one or more times as_zip.add_file. as_zip.add_file always leaves a valid and complete zip-file and can be used to add a file to an existing zip-file.

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
Or use as_zip.add_csv to add a csv-file, based on a sys_refcursor
<pre><code>declare
  l_zip blob;
  l_rc sys_refcursor;
begin
  for f in 1 .. 5
  loop
    open l_rc for
      select level r, 'test "' || level l, sysdate + level n
      from dual connect by level <= f;
    --
    as_zip.add_csv( l_zip, l_rc, 'file' || f || '.csv', 'This is csv-file ' || f );
  end loop;
  --
  as_zip.save_zip( l_zip, 'VAGRANT', 'zip4.zip' );
  dbms_lob.freetemporary( l_zip );
end;</code></pre>

# See what's in a zip-file
To see what's in a zip-file you have several options.  
A file name in a zip-file can be as long as 64k bytes. Use as_zip.get_file_list to get a list of clobs with all the names
<code><pre>declare
  l_zip blob;
  l_files as_zip.file_list;
begin
  l_zip := as_zip.file2blob( 'VAGRANT', 'zip3.zip' );
  l_files := as_zip.get_file_list( l_zip );
  dbms_output.put_line( l_files.count );
  for i in 1 .. l_files.count
  loop
    dbms_output.put_line( l_files( i ) );
  end loop;
  dbms_lob.freetemporary( l_zip );
end;
</code></pre>
As in most cases file names aren't that big, you can use as_zip.get_file_names to get a list of varchar2(4000)'s with all the names. If one of the file names in the zip-file doesn't fit into a varchar2(4000) and exception will be raised
<code><pre>declare
  l_zip blob;
  l_files as_zip.file_names;
begin
  l_zip := as_zip.file2blob( 'VAGRANT', 'zip3.zip' );
  l_files := as_zip.get_file_names( l_zip );
  dbms_output.put_line( l_files.count );
  for i in 1 .. l_files.count
  loop
    dbms_output.put_line( l_files( i ) );
  end loop;
  dbms_lob.freetemporary( l_zip );
end;
</code></pre>
Or use as_zip.get_file_info in a loop to get info, including the name, on the files inside the zip-files
<code><pre>declare
  l_zip blob;
  l_info as_zip.file_info;
begin
  l_zip := as_zip.file2blob( 'VAGRANT', 'zip3.zip' );
  dbms_output.put_line( as_zip.get_count( l_zip ) );
  for i in 1 .. as_zip.get_count( l_zip )
  loop
    l_info := as_zip.get_file_info( l_zip, p_idx => i );
    dbms_output.put_line( l_info.name
      || ' password needed: ' || case when l_info.is_encrypted then 'yes' else 'no' end
      || ' len: ' || l_info.len
      || ' compressed: ' || l_info.clen);
  end loop;
  dbms_lob.freetemporary( l_zip );
end;
</code></pre>
