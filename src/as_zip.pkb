CREATE OR REPLACE package body as_zip
is
--
  c_LOCAL_FILE_HEADER        constant raw(4) := hextoraw( '504B0304' ); -- Local file header signature
  c_END_OF_CENTRAL_DIRECTORY constant raw(4) := hextoraw( '504B0506' ); -- End of central directory signature
--
  type tp_init_tab is table of raw(4) index by varchar2(2);
  crc32_tab tp_init_tab;
--
  t_key1 raw(4);
  t_key2 raw(4);
  t_key3 raw(4);
--
  procedure init_crc32
  is
    c_poly raw(4) := hextoraw( 'EDB88320' );
    t_tmp number(10);
  begin
    if crc32_tab.count() != 256
    then
      for i in 0 .. 255
      loop
        t_tmp := i;
        for j in 1 .. 8
        loop
          if mod( t_tmp, 2 ) = 1
          then
            t_tmp := to_number( rawtohex( utl_raw.bit_xor( hextoraw( to_char( trunc( t_tmp / 2 ), 'fm0xxxxxxx' ) ), c_poly ) ), 'xxxxxxxx' );
          else
            t_tmp := trunc( t_tmp / 2 );
          end if;
        end loop;
        crc32_tab( to_char( i, 'fm0X' ) ) := hextoraw( to_char( t_tmp, 'fm0xxxxxxx' ) );
      end loop;
    end if;
  end;
--
  procedure update_keys( p_char in raw )
  is
    t_crc raw(4);
    t_tmp number;
  begin
    t_key1 := utl_raw.bit_xor( crc32_tab( utl_raw.bit_xor( p_char, utl_raw.substr( t_key1, 4, 1 ) ) )
                             , utl_raw.concat( hextoraw( '00' ), utl_raw.substr( t_key1, 1, 3 ) )
                             );
    t_tmp := mod( ( to_number( rawtohex( t_key2 ), 'xxxxxxxx' )
                  + to_number( rawtohex( utl_raw.substr( t_key1, 4, 1) ), 'xx' )
                  ) * 134775813 + 1
                , 4294967296
                );
    t_key2 := hextoraw( to_char( t_tmp, 'fm0XXXXXXX' ) );
    t_key3 := utl_raw.bit_xor( crc32_tab( utl_raw.bit_xor( utl_raw.substr( t_key2, 1, 1 ), utl_raw.substr( t_key3, 4, 1 ) ) )
                             , utl_raw.concat( hextoraw( '00' ), utl_raw.substr( t_key3, 1, 3 ) )
                             );
  end;
--
  function decryptbyte
  return raw
  is
    t_tmp raw(4);
  begin
    t_tmp := utl_raw.bit_or( t_key3, hextoraw( '00000002' ) );
    t_tmp := to_char( mod( to_number( t_tmp, 'xxxxxxxx' )
                         * to_number( utl_raw.bit_xor( t_tmp, hextoraw( '00000001' ) ), 'xxxxxxxx' )
                         , 4294967296
                         )
                    , 'fm0xxxxxxx'
                    );
    return utl_raw.substr( t_tmp, 3, 1 );
  end;
--
  procedure init_keys( p_password in varchar2 )
  is
  begin
    t_key1 := hextoraw( '12345678' );
    t_key2 := hextoraw( '23456789' );
    t_key3 := hextoraw( '34567890' );
    for i in 1 .. length( p_password )
    loop
      update_keys( utl_raw.cast_to_raw( substr( p_password, i, 1 ) ) );
    end loop;
  end;
--
  function blob2num( p_blob blob, p_len integer, p_pos integer )
  return number
  is
    rv number;
  begin
    rv := utl_raw.cast_to_binary_integer( dbms_lob.substr( p_blob, p_len, p_pos ), utl_raw.little_endian );
    if rv < 0
    then
      rv := rv + 4294967296;
    end if;
    return rv;
  end;
--
  function raw2varchar2( p_raw raw, p_encoding varchar2 )
  return varchar2
  is
  begin
    return coalesce( utl_i18n.raw_to_char( p_raw, p_encoding )
                   , utl_i18n.raw_to_char( p_raw, utl_i18n.map_charset( p_encoding, utl_i18n.GENERIC_CONTEXT, utl_i18n.IANA_TO_ORACLE ) )
                   );
  end;
--
  function little_endian( p_big number, p_bytes pls_integer := 4 )
  return raw
  is
    t_big number := p_big;
  begin
    if t_big > 2147483647
    then
      t_big := t_big - 4294967296;
    end if;
    return utl_raw.substr( utl_raw.cast_from_binary_integer( t_big, utl_raw.little_endian ), 1, p_bytes );
  end;
--
  function file2blob
    ( p_dir varchar2
    , p_file_name varchar2
    )
  return blob
  is
    file_lob bfile;
    file_blob blob;
  begin
    file_lob := bfilename( p_dir, p_file_name );
    dbms_lob.open( file_lob, dbms_lob.file_readonly );
    dbms_lob.createtemporary( file_blob, true );
    dbms_lob.loadfromfile( file_blob, file_lob, dbms_lob.lobmaxsize );
    dbms_lob.close( file_lob );
    return file_blob;
  exception
    when others then
      if dbms_lob.isopen( file_lob ) = 1
      then
        dbms_lob.close( file_lob );
      end if;
      if dbms_lob.istemporary( file_blob ) = 1
      then
        dbms_lob.freetemporary( file_blob );
      end if;
      raise;
  end;
--
  function get_file_list
    ( p_zipped_blob blob
    , p_encoding varchar2 := null
    )
  return file_list
  is
    t_ind integer;
    t_hd_ind integer;
    t_rv file_list;
    t_encoding varchar2(32767);
  begin
    t_ind := dbms_lob.getlength( p_zipped_blob ) - 21;
    loop
      exit when t_ind < 1 or dbms_lob.substr( p_zipped_blob, 4, t_ind ) = c_END_OF_CENTRAL_DIRECTORY;
      t_ind := t_ind - 1;
    end loop;
--
    if t_ind <= 0
    then
      return null;
    end if;
--
    t_hd_ind := blob2num( p_zipped_blob, 4, t_ind + 16 ) + 1;
    t_rv := file_list();
    t_rv.extend( blob2num( p_zipped_blob, 2, t_ind + 10 ) );
    for i in 1 .. blob2num( p_zipped_blob, 2, t_ind + 8 )
    loop
      if p_encoding is null
      then
        if utl_raw.bit_and( dbms_lob.substr( p_zipped_blob, 1, t_hd_ind + 9 ), hextoraw( '08' ) ) = hextoraw( '08' )
        then
          t_encoding := 'AL32UTF8'; -- utf8
        else
          t_encoding := 'US8PC437'; -- IBM codepage 437
        end if;
      else
        t_encoding := p_encoding;
      end if;
      t_rv( i ) := raw2varchar2
                     ( dbms_lob.substr( p_zipped_blob
                                      , blob2num( p_zipped_blob, 2, t_hd_ind + 28 )
                                      , t_hd_ind + 46
                                      )
                     , t_encoding
                     );
      t_hd_ind := t_hd_ind + 46
                + blob2num( p_zipped_blob, 2, t_hd_ind + 28 )  -- File name length
                + blob2num( p_zipped_blob, 2, t_hd_ind + 30 )  -- Extra field length
                + blob2num( p_zipped_blob, 2, t_hd_ind + 32 ); -- File comment length
    end loop;
--
    return t_rv;
  end;
--
  function get_file_list
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_encoding varchar2 := null
    )
  return file_list
  is
  begin
    return get_file_list( file2blob( p_dir, p_zip_file ), p_encoding );
  end;
--
  function get_file
    ( p_zipped_blob blob
    , p_file_name varchar2
    , p_encoding varchar2 := null
    , p_password varchar2 := null
    )
  return blob
  is
    t_tmp blob;
    t_cpr blob;
    t_ind integer;
    t_hd_ind integer;
    t_fl_ind integer;
    t_encoding varchar2(32767);
    t_len integer;
    t_clen number;
    t_idx number;
    t_c raw(1);
    t_encrypt_header raw(12);
  begin
    t_ind := dbms_lob.getlength( p_zipped_blob ) - 21;
    loop
      exit when t_ind < 1 or dbms_lob.substr( p_zipped_blob, 4, t_ind ) = c_END_OF_CENTRAL_DIRECTORY;
      t_ind := t_ind - 1;
    end loop;
--
    if t_ind <= 0
    then
      return null;
    end if;
--
    t_hd_ind := blob2num( p_zipped_blob, 4, t_ind + 16 ) + 1;
    for i in 1 .. blob2num( p_zipped_blob, 2, t_ind + 8 )
    loop
      if p_encoding is null
      then
        if utl_raw.bit_and( dbms_lob.substr( p_zipped_blob, 1, t_hd_ind + 9 ), hextoraw( '08' ) ) = hextoraw( '08' )
        then
          t_encoding := 'AL32UTF8'; -- utf8
        else
          t_encoding := 'US8PC437'; -- IBM codepage 437
        end if;
      else
        t_encoding := p_encoding;
      end if;
      if p_file_name = raw2varchar2
                         ( dbms_lob.substr( p_zipped_blob
                                          , blob2num( p_zipped_blob, 2, t_hd_ind + 28 )
                                          , t_hd_ind + 46
                                          )
                         , t_encoding
                         )
      then
        t_len := blob2num( p_zipped_blob, 4, t_hd_ind + 24 ); -- uncompressed length
        if t_len = 0
        then
          if substr( p_file_name, -1 ) in ( '/', '\' )
          then  -- directory/folder
            return null;
          else -- empty file
            return empty_blob();
          end if;
        end if;
--
        if dbms_lob.substr( p_zipped_blob, 2, t_hd_ind + 10 ) = hextoraw( '0800' ) -- deflate
        then
          t_fl_ind := blob2num( p_zipped_blob, 4, t_hd_ind + 42 );
          dbms_lob.createtemporary( t_cpr, true, dbms_lob.call );
          dbms_lob.writeappend( t_cpr, 10, '1F8B0800000000000003' ); -- gzip header
          if utl_raw.bit_and( dbms_lob.substr( p_zipped_blob, 1, t_hd_ind + 8 ), hextoraw( '01' ) ) = hextoraw( '01' ) -- encrypted
          then
            init_crc32;
            init_keys( p_password );
            t_idx := t_fl_ind + 31
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 27 ) -- File name length
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 29 ); -- Extra field length
            t_encrypt_header := dbms_lob.substr( p_zipped_blob, 12, t_idx );
            for i in 1 .. 12
            loop
              t_c := utl_raw.bit_xor( utl_raw.substr( t_encrypt_header, i, 1 ), decryptbyte );
              update_keys( t_c );
            end loop;
            t_idx := t_idx + 12 - 1;
            t_clen := blob2num( p_zipped_blob, 4, t_hd_ind + 20 );
            for i in 1 .. t_clen - 12  -- compressed length - length encryption header
            loop
              t_c := utl_raw.bit_xor( dbms_lob.substr( p_zipped_blob, 1, t_idx + i ), decryptbyte );
              update_keys( t_c );
              dbms_lob.writeappend( t_cpr, 1, t_c );
            end loop;
          else
            dbms_lob.copy( t_cpr
                         , p_zipped_blob
                         , blob2num( p_zipped_blob, 4, t_hd_ind + 20 )
                         , 11
                         , t_fl_ind + 31
                         + blob2num( p_zipped_blob, 2, t_fl_ind + 27 ) -- File name length
                         + blob2num( p_zipped_blob, 2, t_fl_ind + 29 ) -- Extra field length
                         );
          end if;
          dbms_lob.append( t_cpr, utl_raw.concat( dbms_lob.substr( p_zipped_blob, 4, t_hd_ind + 16 ) -- CRC32
                                                , little_endian( t_len ) -- uncompressed length
                                                )
                         );
          dbms_lob.createtemporary( t_tmp, true, dbms_lob.call );
          utl_compress.lz_uncompress( t_cpr, t_tmp );
          dbms_lob.freetemporary( t_cpr );
          return t_tmp;
        end if;
--
        if dbms_lob.substr( p_zipped_blob, 2, t_hd_ind + 10 ) = hextoraw( '0000' ) -- The file is stored (no compression)
        then
          t_fl_ind := blob2num( p_zipped_blob, 4, t_hd_ind + 42 );
          dbms_lob.createtemporary( t_tmp, true, dbms_lob.call );
          if utl_raw.bit_and( dbms_lob.substr( p_zipped_blob, 1, t_hd_ind + 8 ), hextoraw( '01' ) ) = hextoraw( '01' ) -- encrypted
          then
            init_crc32;
            init_keys( p_password );
            t_idx := t_fl_ind + 31
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 27 ) -- File name length
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 29 ); -- Extra field length
            t_encrypt_header := dbms_lob.substr( p_zipped_blob, 12, t_idx );
            for i in 1 .. 12
            loop
              t_c := utl_raw.bit_xor( utl_raw.substr( t_encrypt_header, i, 1 ), decryptbyte );
              update_keys( t_c );
            end loop;
            t_idx := t_idx + 12 - 1;
            for i in 1 .. t_len
            loop
              t_c := utl_raw.bit_xor( dbms_lob.substr( p_zipped_blob, 1, t_idx + i ), decryptbyte );
              update_keys( t_c );
              dbms_lob.writeappend( t_tmp, 1, t_c );
            end loop;
          else
            dbms_lob.copy( t_tmp
                         , p_zipped_blob
                         , t_len
                         , 1
                         , t_fl_ind + 31
                         + blob2num( p_zipped_blob, 2, t_fl_ind + 27 ) -- File name length
                         + blob2num( p_zipped_blob, 2, t_fl_ind + 29 ) -- Extra field length
                         );
          end if;
          return t_tmp;
        end if;
--
        if (   dbms_lob.substr( p_zipped_blob, 1, t_hd_ind + 8 ) = hextoraw( '01' )
           and dbms_lob.substr( p_zipped_blob, 2, t_hd_ind + 10 ) = hextoraw( '6300' )
           ) -- Winzip AES encrypted
        then
          declare
            t_extra raw(100);
            t_key_bits pls_integer;
            t_key_length pls_integer;
            t_salt raw(16);
            t_pw raw(999) := utl_raw.cast_to_raw( p_password );
            t_key raw(32);
            t_keys raw(80);
            t_mac raw(20);
            t_sum raw(20);
            t_block raw(16);
            t_algo number := dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_CFB + dbms_crypto.PAD_NONE;
            t_hdl binary_integer;
            t_buffer raw(32767);
          begin
            t_fl_ind := blob2num( p_zipped_blob, 4, t_hd_ind + 42 );
            if blob2num( p_zipped_blob, 2, t_fl_ind + 29 ) > 100
            then
              return empty_blob();
            end if;
            t_extra := dbms_lob.substr( p_zipped_blob
                                      , blob2num( p_zipped_blob, 2, t_fl_ind + 29 )
                                      , t_fl_ind + 31
                                      + blob2num( p_zipped_blob, 2, t_fl_ind + 27 )
                                      );
/*
0199 => 9901
0700 => len 7
0200 => AE-2
4145 => vendor AE
03   => 256-bit encryption key
0800 => deflate
*/
            if utl_raw.substr( t_extra, 1, 8 ) not in ( '0199070001004145',  '0199070002004145' )
            then
              return empty_blob();
            end if;
            t_key_bits := case utl_raw.substr( t_extra, 9, 1 )
                            when '01' then 128
                            when '02' then 192
                            when '03' then 256
                          end;
            if t_key_bits is null
            then
              return empty_blob();
            end if;
            t_key_length := t_key_bits / 8 * 2 + 2;
            t_idx := t_fl_ind + 31
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 27 ) -- File name length
                   + blob2num( p_zipped_blob, 2, t_fl_ind + 29 ); -- Extra field length
            t_salt := dbms_lob.substr( p_zipped_blob, t_key_bits / 16, t_idx );
            t_idx := t_idx + t_key_bits / 16;
            for i in 1 .. ceil( t_key_length / 20 )
            loop
              t_mac := dbms_crypto.mac( utl_raw.concat( t_salt, to_char( i, 'fm0xxxxxxx' ) ), dbms_crypto.HMAC_SH1, t_pw );
              t_sum := t_mac;
              for j in 1 .. 999
              loop
                t_mac := dbms_crypto.mac( t_mac, dbms_crypto.HMAC_SH1, t_pw );
                t_sum := utl_raw.bit_xor( t_mac, t_sum );
              end loop;
              t_keys := utl_raw.concat( t_keys, t_sum );
            end loop;
            t_keys := utl_raw.substr( t_keys, 1, t_key_length );
            if dbms_lob.substr( p_zipped_blob, 2, t_idx ) != utl_raw.substr( t_keys, -2, 2 ) -- Password verification value
            then
              return empty_blob();
            end if;
            t_idx := t_idx + 2;
            t_key := utl_raw.substr( t_keys, 1, t_key_bits / 8 );
            t_clen := blob2num( p_zipped_blob, 2, t_fl_ind + 19 );
            t_clen := t_clen - t_key_bits / 16 - 2 - 10;
            dbms_lob.createtemporary( t_tmp, true, dbms_lob.call );
            for i in 0 .. ceil( t_clen / 16 )
            loop
              t_block := dbms_lob.substr( p_zipped_blob, 16, t_idx );
              t_idx := t_idx + 16;
              t_block := dbms_crypto.decrypt( t_block, t_algo, t_key, utl_raw.reverse( to_char( i + 1, 'fm' || lpad( 'X', 32, '0' ) ) ) );
              dbms_lob.writeappend( t_tmp, 16, t_block );
            end loop;
            dbms_lob.trim( t_tmp, t_clen );
            if utl_raw.substr( t_extra, 10 ) = '0000' -- stored
            then
              return t_tmp;
            end if;
            dbms_lob.createtemporary( t_cpr, true, dbms_lob.call );
            dbms_lob.writeappend( t_cpr, 10, '1F8B0800000000000003' ); -- gzip header
            dbms_lob.copy( t_cpr, t_tmp, dbms_lob.lobmaxsize, 11, 1 );
            t_hdl := utl_compress.lz_uncompress_open( t_cpr );
            dbms_lob.freetemporary( t_tmp );
            dbms_lob.createtemporary( t_tmp, true, dbms_lob.call );
            loop
              begin
                utl_compress.lz_uncompress_extract( t_hdl, t_buffer );
                dbms_lob.writeappend( t_tmp, utl_raw.length( t_buffer ), t_buffer );
              exception
                when no_data_found then exit;
              end;
            end loop;
            utl_compress.lz_uncompress_close( t_hdl );
            dbms_lob.freetemporary( t_cpr );
            return t_tmp;
          end;
        end if;
--
      end if;
      t_hd_ind := t_hd_ind + 46
                + blob2num( p_zipped_blob, 2, t_hd_ind + 28 )  -- File name length
                + blob2num( p_zipped_blob, 2, t_hd_ind + 30 )  -- Extra field length
                + blob2num( p_zipped_blob, 2, t_hd_ind + 32 ); -- File comment length
    end loop;
--
    return null;
  end;
--
  function get_file
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_file_name varchar2
    , p_encoding varchar2 := null
    , p_password varchar2 := null
    )
  return blob
  is
  begin
    return get_file( file2blob( p_dir, p_zip_file ), p_file_name, p_encoding, p_password );
  end;
--
  function encrypt( p_pw varchar2, p_src blob )
  return blob
  is
    t_salt raw(16);
    t_key  raw(32);
    t_pw raw(32767) := utl_raw.cast_to_raw( p_pw );
    t_key_bits pls_integer := 256;
    t_key_length pls_integer := t_key_bits / 8 * 2 + 2;
    t_cnt pls_integer := 1000;
    t_keys raw(32767);
    t_sum raw(32767);
    t_mac raw(20);
    t_iv raw(16);
    t_block raw(16);
    t_len pls_integer;
    t_rv blob;
    t_tmp blob;
  begin
    t_salt := dbms_crypto.randombytes( t_key_bits / 16 );
    for i in 1 .. ceil( t_key_length / 20 )
    loop
      t_mac := dbms_crypto.mac( utl_raw.concat( t_salt, to_char( i, 'fm0xxxxxxx' ) ), dbms_crypto.HMAC_SH1, t_pw );
      t_sum := t_mac;
      for j in 1 .. t_cnt - 1
      loop
        t_mac := dbms_crypto.mac( t_mac, dbms_crypto.HMAC_SH1, t_pw );
        t_sum := utl_raw.bit_xor( t_mac, t_sum );
      end loop;
      t_keys := utl_raw.concat( t_keys, t_sum );
    end loop;
    t_keys := utl_raw.substr( t_keys, 1, t_key_length );
    t_key := utl_raw.substr( t_keys, 1, t_key_bits / 8 );
    t_rv := utl_raw.concat( t_salt, utl_raw.substr( t_keys, -2, 2 ) );
--
    for i in 0 .. trunc( ( dbms_lob.getlength( p_src ) - 1 ) / 16 )
    loop
      t_block := dbms_lob.substr( p_src, 16, i * 16 + 1 );
      t_len := utl_raw.length( t_block );
      if t_len < 16
      then
        t_block := utl_raw.concat( t_block, utl_raw.copies( '00', 16 - t_len ) );
      end if;
      t_iv := utl_raw.reverse( to_char( i + 1, 'fm000000000000000000000000000000x' ) );
      dbms_lob.writeappend( t_rv, t_len, dbms_crypto.encrypt( t_block, dbms_crypto.ENCRYPT_AES256 + dbms_crypto.CHAIN_CFB + dbms_crypto.PAD_NONE, t_key, t_iv ) );
    end loop;
--
    dbms_lob.createtemporary( t_tmp, true, dbms_lob.call );
    dbms_lob.copy( t_tmp, t_rv, dbms_lob.getlength( p_src ), 1, t_key_bits / 16 + 2 + 1 );
    t_mac := dbms_crypto.mac( t_tmp, dbms_crypto.HMAC_SH1, utl_raw.substr( t_keys, 1 + t_key_bits / 8, t_key_bits / 8 ) );
    dbms_lob.freetemporary( t_tmp );
    dbms_lob.writeappend( t_rv, 10, t_mac );
    return t_rv;
  end;
--
  procedure add1file
    ( p_zipped_blob in out blob
    , p_name varchar2
    , p_content blob
    , p_password varchar2 := null
    )
  is
    t_now date;
    t_blob blob;
    t_len integer;
    t_clen integer;
    t_crc32 raw(4) := hextoraw( '00000000' );
    t_compressed boolean := false;
    t_encrypted boolean := false;
    t_name raw(32767);
    t_extra raw(11);
  begin
    t_now := sysdate;
    t_len := nvl( dbms_lob.getlength( p_content ), 0 );
    if t_len > 0
    then
      dbms_lob.createtemporary( t_blob, true );
      dbms_lob.copy( t_blob, utl_compress.lz_compress( p_content ), dbms_lob.lobmaxsize , 1, 11 );
      t_clen := dbms_lob.getlength( t_blob ) - 8;
      t_compressed := t_clen < t_len;
      t_crc32 := dbms_lob.substr( t_blob, 4, t_clen + 1 );
      dbms_lob.trim( t_blob, t_clen );
    end if;
    if not t_compressed
    then
      t_clen := t_len;
      t_blob := p_content;
    end if;
--
    if p_zipped_blob is null
    then
      dbms_lob.createtemporary( p_zipped_blob, true );
    end if;
--
    if p_password is not null and t_len > 0
    then
      t_encrypted := true;
      t_crc32 := hextoraw( '00000000' );
      t_extra := hextoraw( '019907000200414503' || case when t_compressed
                                                     then '0800' -- deflate
                                                     else '0000' -- stored
                                                   end
                         );
      t_blob := encrypt( p_password, t_blob );
      t_clen := dbms_lob.getlength( t_blob );
    end if;
    t_name := utl_i18n.string_to_raw( p_name, 'AL32UTF8' );
    dbms_lob.append( p_zipped_blob
                   , utl_raw.concat( utl_raw.concat( c_LOCAL_FILE_HEADER -- Local file header signature
                                                   , hextoraw( '3300' )  -- version 5.1
                                                   )
                                   , case when t_encrypted
                                       then hextoraw( '01' ) -- encrypted
                                       else hextoraw( '00' )
                                     end
                                   , case when t_name = utl_i18n.string_to_raw( p_name, 'US8PC437' )
                                       then hextoraw( '00' )
                                       else hextoraw( '08' ) -- set Language encoding flag (EFS)
                                     end
                                   , case when t_encrypted
                                       then '6300'
                                       else
                                         case when t_compressed
                                           then hextoraw( '0800' ) -- deflate
                                           else hextoraw( '0000' ) -- stored
                                         end
                                     end
                                   , little_endian( to_number( to_char( t_now, 'ss' ) ) / 2
                                                  + to_number( to_char( t_now, 'mi' ) ) * 32
                                                  + to_number( to_char( t_now, 'hh24' ) ) * 2048
                                                  , 2
                                                  ) -- File last modification time
                                   , little_endian( to_number( to_char( t_now, 'dd' ) )
                                                  + to_number( to_char( t_now, 'mm' ) ) * 32
                                                  + ( to_number( to_char( t_now, 'yyyy' ) ) - 1980 ) * 512
                                                  , 2
                                                  ) -- File last modification date
                                   , t_crc32 -- CRC-32
                                   , little_endian( t_clen )                      -- compressed size
                                   , little_endian( t_len )                       -- uncompressed size
                                   , little_endian( utl_raw.length( t_name ), 2 ) -- File name length
                                   , little_endian( nvl( utl_raw.length( t_extra ), 0 ), 2 ) -- Extra field length
                                   , utl_raw.concat( t_name                       -- File name
                                                   , t_extra
                                                   )
                                   )
                   );
    if t_len > 0
    then
      dbms_lob.copy( p_zipped_blob, t_blob, t_clen, dbms_lob.getlength( p_zipped_blob ) + 1, 1 ); -- (compressed) content
    end if;
    if t_blob is not null
    then
      dbms_lob.freetemporary( t_blob );
    end if;
  end;
--
  procedure finish_zip( p_zipped_blob in out blob )
  is
    t_cnt pls_integer := 0;
    t_offs integer;
    t_offs_dir_header integer;
    t_offs_end_header integer;
    t_comment raw(32767) := utl_raw.cast_to_raw( 'Implementation by Anton Scheffer' );
  begin
    t_offs_dir_header := dbms_lob.getlength( p_zipped_blob );
    t_offs := 1;
    while dbms_lob.substr( p_zipped_blob, utl_raw.length( c_LOCAL_FILE_HEADER ), t_offs ) = c_LOCAL_FILE_HEADER
    loop
      t_cnt := t_cnt + 1;
      dbms_lob.append( p_zipped_blob
                     , utl_raw.concat( hextoraw( '504B0102' )      -- Central directory file header signature
                                     , hextoraw( '1400' )          -- version 2.0
                                     , dbms_lob.substr( p_zipped_blob, 26, t_offs + 4 )
                                     , hextoraw( '0000' )          -- File comment length
                                     , hextoraw( '0000' )          -- Disk number where file starts
                                     , hextoraw( '0000' )          -- Internal file attributes =>
                                                                   --     0000 binary file
                                                                   --     0100 (ascii)text file
                                     , case
                                         when dbms_lob.substr( p_zipped_blob
                                                             , 1
                                                             , t_offs + 30 + blob2num( p_zipped_blob, 2, t_offs + 26 ) - 1
                                                             ) in ( hextoraw( '2F' ) -- /
                                                                  , hextoraw( '5C' ) -- \
                                                                  )
                                         then hextoraw( '10000000' ) -- a directory/folder
                                         else hextoraw( '2000B681' ) -- a file
                                       end                         -- External file attributes
                                     , little_endian( t_offs - 1 ) -- Relative offset of local file header
                                     , dbms_lob.substr( p_zipped_blob
                                                      , blob2num( p_zipped_blob, 2, t_offs + 26 )
                                                      , t_offs + 30
                                                      )            -- File name
                                     )
                     );
      t_offs := t_offs + 30 + blob2num( p_zipped_blob, 4, t_offs + 18 )  -- compressed size
                            + blob2num( p_zipped_blob, 2, t_offs + 26 )  -- File name length
                            + blob2num( p_zipped_blob, 2, t_offs + 28 ); -- Extra field length
    end loop;
    t_offs_end_header := dbms_lob.getlength( p_zipped_blob );
    dbms_lob.append( p_zipped_blob
                   , utl_raw.concat( c_END_OF_CENTRAL_DIRECTORY                                -- End of central directory signature
                                   , hextoraw( '0000' )                                        -- Number of this disk
                                   , hextoraw( '0000' )                                        -- Disk where central directory starts
                                   , little_endian( t_cnt, 2 )                                 -- Number of central directory records on this disk
                                   , little_endian( t_cnt, 2 )                                 -- Total number of central directory records
                                   , little_endian( t_offs_end_header - t_offs_dir_header )    -- Size of central directory
                                   , little_endian( t_offs_dir_header )                        -- Offset of start of central directory, relative to start of archive
                                   , little_endian( nvl( utl_raw.length( t_comment ), 0 ), 2 ) -- ZIP file comment length
                                   , t_comment
                                   )
                   );
  end;
--
  procedure save_zip
    ( p_zipped_blob blob
    , p_dir varchar2 := 'MY_DIR'
    , p_filename varchar2 := 'my.zip'
    )
  is
    t_fh utl_file.file_type;
    t_len pls_integer := 32767;
  begin
    t_fh := utl_file.fopen( p_dir, p_filename, 'wb' );
    for i in 0 .. trunc( ( dbms_lob.getlength( p_zipped_blob ) - 1 ) / t_len )
    loop
      utl_file.put_raw( t_fh, dbms_lob.substr( p_zipped_blob, t_len, i * t_len + 1 ) );
    end loop;
    utl_file.fclose( t_fh );
  end;
--
end;
/
