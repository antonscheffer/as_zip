CREATE OR REPLACE package body as_zip
is
  --
  c_version constant raw(1) := hextoraw( '15' ); -- version 2.1
  --
  type tp_zip_info is record
    ( len integer
    , cnt integer
    , len_cd integer
    , idx_cd integer
    , idx_eocd integer
    , idx_zip64_eocd integer
    , zip64 boolean
    , len_comment pls_integer
    , comment1 raw(32767)
    , comment2 raw(32767)
    , comment3 raw(100)
    );
  type tp_cfh is record
    ( offset integer
    , compressed_len integer
    , original_len integer
    , len pls_integer
    , n   pls_integer
    , m   pls_integer
    , k   pls_integer
    , utf8 boolean
    , encrypted boolean
    , crc32 raw(4)
    , external_file_attr raw(4)
    , encoding varchar2(3999)
    , idx   integer
    , name1 raw(32767)
    , name2 raw(32767)
    , name3 raw(100)
    , zip64 boolean
    , zip64_offset pls_integer
    , comment1 raw(32767)
    , comment2 raw(32767)
    , comment3 raw(100)
    );
  --
  c_lob_duration constant pls_integer := dbms_lob.call;
  c_LOCAL_FILE_HEADER        constant raw(4) := hextoraw( '504B0304' ); -- Local file header signature
  c_CENTRAL_FILE_HEADER      constant raw(4) := hextoraw( '504B0102' ); -- Central directory file header signature
  c_END_OF_CENTRAL_DIRECTORY constant raw(4) := hextoraw( '504B0506' ); -- End of central directory signature
  c_ZIP64_END_OF_CD          constant raw(4) := hextoraw( '504B0606' ); -- Zip64 end of central directory
  c_ZIP64_END_OF_CD_LOCATOR  constant raw(4) := hextoraw( '504B0607' ); -- Zip64 end of central directory locator
  c_DATA_DESCRIPTOR          constant raw(4) := hextoraw( '504B0708' ); -- Data Descriptor
  --
  type tp_zipcrypto_tab is table of raw(4) index by varchar2(2);
  l_zipcrypto_tab tp_zipcrypto_tab;
  l_key1 raw(4);
  l_key2 raw(4);
  l_key3 raw(4);
$IF as_zip.use_winzip_encryption
$THEN
$IF as_zip.use_dbms_crypto
$THEN
$ELSE
  type tp_aes_tab is table of number index by pls_integer;
  --
  function bitor( x simple_integer, y simple_integer )
  return simple_integer
  is
  begin
    return x + y - bitand( x, y );
  end;
  --
  function bitxor( x simple_integer, y simple_integer )
  return simple_integer
  is
  begin
    return x + y - 2 * bitand( x, y );
  end;
  --
  function rol32_1( x simple_integer )
  return simple_integer
  is
    t1 simple_integer := x * 2;
    t2 simple_integer := sign( bitand( x, 2147483648 ) );
  begin
    return t1 + t2;
  end;
  --
  function rol32_5( x simple_integer )
  return simple_integer
  is
    t1 simple_integer := x * 32;
    t2 simple_integer := trunc( bitand( x, 4160749568 ) / 134217728 );
  begin
    return t1 + t2;
  end;
  --
  function rol32_30( x simple_integer )
  return simple_integer
  is
  begin
    return trunc( bitand( x, 2147483647 ) / 4 ) + case when x < 0 then 536870912 else 0 end + bitand( x, 3 ) * 1073741824;
  end;
  --
  procedure aes_encrypt_key
    ( key varchar2
    , p_encrypt_key out nocopy tp_aes_tab
    )
  is
    rcon tp_aes_tab;
    SS varchar2(2048);
    s1 varchar2(8);
    s2 varchar2(8);
    s3 varchar2(8);
    s4 varchar2(8);
    Nk pls_integer := length( key ) / 8;
    n pls_integer := 0;
    r pls_integer := 0;
    t simple_integer := 0;
  begin
    SS := '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
       || 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
       || '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
       || 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
       || 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
       || 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
       || 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
       || 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
       || 'C6F8EEF6FFD6DE916002CE56E7B54DEC8F1F89FAEFB28EFB41B35F452353E49B'
       || '75E13D4C6C7EF5836851D1F9E2AB622A0895469D30370A2F0E241BDFCD4E7FEA'
       || '121D583436DCB45BA476B77D52DD5E13A6B900C140E379B6D48D67729498B085'
       || 'BBC54FED869A66118AE904FEA078254BA25D80053F2170F16377AF4220E5FDBF'
       || '811826C3BE35882E9355FC7AC8BA32E6C0199EA344543B0B8CC76B28A7BC16AD'
       || 'DB647414920C48B89FBD43C43931D3F2D58B6EDA01B19C49D8ACF3CFCAF44710'
       || '6FF04A5C38577397CBA1E83E96610D0FE07C71CC9006F71CC26AAE6917993A27'
       || 'D9EB2B22D2A907332D3C15C987AA50A50359091A65D784D082295A1E7BA86D2C'
       || 'A584998D0DBDB1545003A97D1962E69A459D408715EBC90BEC67FDEABFF7965B'
       || 'C21CAE6A5A41024F5CF434089373533F0C52655E28A10FB509369B3D2669CD9F'
       || '1B9E742E2DB2EEFBF64D61CE7B3E7197F568002C601FC8EDBE46D94BDED4E84A'
       || '6B2AE516C5D75594CF100681F044BAE3F3FEC08AADBC4804DFC17563301A0E6D'
       || '4C14352FE1A2CC3957F28247ACE72B95A098D17F667EAB83CA29D33C79E21D76'
       || '3B564E1EDB0A6CE45D6EEFA6A8A4378B324359B78C64D2E0B4FA0725AF8EE918'
       || 'D5886F7224F1C751237C9C21DDDC86859042C4AAD8050112A35FF9D0915827B9'
       || '3813B333BB7089A7B622922049FF787A8FF88017DA31C6B8C3B07711CBFCD63A';
    for i in 0 .. 255
    loop
      s1 := substr( SS, i * 2 + 1, 2 );
      s2 := substr( SS, 512 + i * 2 + 1, 2 );
      s3 := substr( SS, 1024 + i * 2 + 1, 2 );
      p_encrypt_key(i) := to_number( s1, 'XX' );
      p_encrypt_key( 256 + i ) := utl_raw.cast_to_binary_integer( s2 || s1 || s1 || s3 );
      p_encrypt_key( 512 + i ) := utl_raw.cast_to_binary_integer( s3 || s2 || s1 || s1 );
      p_encrypt_key( 768 + i ) := utl_raw.cast_to_binary_integer( s1 || s3 || s2 || s1 );
      p_encrypt_key( 1024 + i ) := utl_raw.cast_to_binary_integer( s1 || s1 || s3 || s2 );
    end loop;
    rcon(0) := 16777216;
    rcon(1) := 33554432;
    rcon(2) := 67108864;
    rcon(3) := 134217728;
    rcon(4) := 268435456;
    rcon(5) := 536870912;
    rcon(6) := 1073741824;
    rcon(7) := -2147483648;
    rcon(8) := 452984832;
    rcon(9) := 905969664;
    for i in 0 .. Nk  - 1
    loop
      p_encrypt_key( 1280 + i ) := utl_raw.cast_to_binary_integer( substr( key, i * 8 + 1, 8 ) );
    end loop;
    for i in Nk .. Nk * 4 + 27
    loop
      t := p_encrypt_key( 1280 + i - 1 );
      if n = 0
      then
        n := Nk;
        SS := utl_raw.cast_from_binary_integer( t );
        s1 := substr( to_char( p_encrypt_key( to_number( substr( SS, 3, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s2 := substr( to_char( p_encrypt_key( to_number( substr( SS, 5, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s3 := substr( to_char( p_encrypt_key( to_number( substr( SS, 7, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s4 := substr( to_char( p_encrypt_key( to_number( substr( SS, 1, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        t := utl_raw.cast_to_binary_integer( s1 || s2 || s3 || s4 );
        t := bitxor( t, rcon( r ) );
        r := r + 1;
      elsif Nk = 8 and n = 4
      then
        SS := utl_raw.cast_from_binary_integer( t );
        s1 := substr( to_char( p_encrypt_key( to_number( substr( SS, 1, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s2 := substr( to_char( p_encrypt_key( to_number( substr( SS, 3, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s3 := substr( to_char( p_encrypt_key( to_number( substr( SS, 5, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        s4 := substr( to_char( p_encrypt_key( to_number( substr( SS, 7, 2 ), '0X' ) ), 'fm0XXXXXXX' ), -2 );
        t := utl_raw.cast_to_binary_integer( s1 || s2 || s3 || s4 );
      end if;
      n := n - 1;
      p_encrypt_key( 1280 + i ) := bitxor( p_encrypt_key( 1280 + i - Nk ), t );
    end loop;
  end;
  --
  function aes_encrypt
    ( src varchar2
    , klen pls_integer
    , p_decrypt_key tp_aes_tab
    )
  return raw
  is
    k pls_integer := 0;
    v0 varchar2(16);
    v1 varchar2(16);
    v2 varchar2(16);
    v3 varchar2(16);
    t0 simple_integer := bitxor( utl_raw.cast_to_binary_integer( substr( src,  1, 8 ) ), p_decrypt_key( 1280 ) );
    t1 simple_integer := bitxor( utl_raw.cast_to_binary_integer( substr( src,  9, 8 ) ), p_decrypt_key( 1281 ) );
    t2 simple_integer := bitxor( utl_raw.cast_to_binary_integer( substr( src, 17, 8 ) ), p_decrypt_key( 1282 ) );
    t3 simple_integer := bitxor( utl_raw.cast_to_binary_integer( substr( src, 25, 8 ) ), p_decrypt_key( 1283 ) );
    function grv( a varchar2, b varchar2, c varchar2, d varchar2, v simple_integer )
    return varchar2
    is
      x0 varchar2(10) := to_char( p_decrypt_key( to_number( a, '0X' ) ), 'fm0X' );
      x1 varchar2(10) := to_char( p_decrypt_key( to_number( b, '0X' ) ), 'fm0X' );
      x2 varchar2(10) := to_char( p_decrypt_key( to_number( c, '0X' ) ), 'fm0X' );
      x3 varchar2(10) := to_char( p_decrypt_key( to_number( d, '0X' ) ), 'fm0X' );
    begin
      return utl_raw.cast_from_binary_integer( bitxor( utl_raw.cast_to_binary_integer( x0 || x1 || x2 || x3 ), v ) );
    end;
  begin
    for i in 1 .. klen / 4 + 5
    loop
      k := k + 4;
      v0 := utl_raw.cast_from_binary_integer( t0 );
      v1 := utl_raw.cast_from_binary_integer( t1 );
      v2 := utl_raw.cast_from_binary_integer( t2 );
      v3 := utl_raw.cast_from_binary_integer( t3 );
      t0 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + to_number( substr( v0, 1, 2 ), '0X' ) )
                                  , p_decrypt_key( 512 + to_number( substr( v1, 3, 2 ), '0X' ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + to_number( substr( v2, 5, 2 ), '0X' ) )
                                  , p_decrypt_key( 1024 + to_number( substr( v3, 7, 2 ), '0X' ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 )
                  );
      t1 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + to_number( substr( v1, 1, 2 ), '0X' ) )
                                  , p_decrypt_key( 512 + to_number( substr( v2, 3, 2 ), '0X' ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + to_number( substr( v3, 5, 2 ), '0X' ) )
                                  , p_decrypt_key( 1024 + to_number( substr( v0, 7, 2 ), '0X' ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 1 )
                  );
      t2 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + to_number( substr( v2, 1, 2 ), '0X' ) )
                                  , p_decrypt_key( 512 + to_number( substr( v3, 3, 2 ), '0X' ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + to_number( substr( v0, 5, 2 ), '0X' ) )
                                  , p_decrypt_key( 1024 + to_number( substr( v1, 7, 2 ), '0X' ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 2 )
                  );
      t3 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + to_number( substr( v3, 1, 2 ), '0X' ) )
                                  , p_decrypt_key( 512 + to_number( substr( v0, 3, 2 ), '0X' ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + to_number( substr( v1, 5, 2 ), '0X' ) )
                                  , p_decrypt_key( 1024 + to_number( substr( v2, 7, 2 ), '0X' ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 3 )
                  );
    end loop;
    k := k + 4;
    v0 := utl_raw.cast_from_binary_integer( t0 );
    v1 := utl_raw.cast_from_binary_integer( t1 );
    v2 := utl_raw.cast_from_binary_integer( t2 );
    v3 := utl_raw.cast_from_binary_integer( t3 );
    return grv( substr( v0, 1, 2 ), substr( v1, 3, 2 ), substr( v2, 5, 2 ), substr( v3, 7, 2 ), p_decrypt_key( 1280 + k ) )
        || grv( substr( v1, 1, 2 ), substr( v2, 3, 2 ), substr( v3, 5, 2 ), substr( v0, 7, 2 ), p_decrypt_key( 1280 + k + 1 ) )
        || grv( substr( v2, 1, 2 ), substr( v3, 3, 2 ), substr( v0, 5, 2 ), substr( v1, 7, 2 ), p_decrypt_key( 1280 + k + 2 ) )
        || grv( substr( v3, 1, 2 ), substr( v0, 3, 2 ), substr( v1, 5, 2 ), substr( v2, 7, 2 ), p_decrypt_key( 1280 + k + 3 ) );
  end;
  --
  function sha1( p_src blob, p_first_block raw := null  )
  return raw
  is
    l_len integer;
    l_mod_len pls_integer;
    l_blocks_2do integer;
    l_first_block_len pls_integer;
    l_padding raw(128);
    l_idx integer;
    l_buf raw(32767);
    type tp_n is table of simple_integer index by pls_integer;
    w tp_n;
    tw tp_n;
    th tp_n;
    c_ffffffff simple_integer := -1;
    c_5A827999 simple_integer := 1518500249;
    c_6ED9EBA1 simple_integer := 1859775393;
    c_8F1BBCDC simple_integer := -1894007588;
    c_CA62C1D6 simple_integer := -899497514;
    mi5 pls_integer;
    mi35 pls_integer;
    procedure sha1_block( p_block varchar2 )
    is
    begin
      for i in 0 .. 15
      loop
        w(i) := utl_raw.cast_to_binary_integer( substr( p_block, i * 8 + 1, 8 ) );
      end loop;
      for i in 16 .. 79
      loop
        w(i) := rol32_1( bitxor( bitxor( w(i-3), w(i-8) ), bitxor( w(i-14), w(i-16) ) ) );
      end loop;
      for i in 0 .. 4
      loop
        tw(i) := th(i);
      end loop;
      for i in 0 .. 19
      loop
        mi5 := mod( i, 5 );
        mi35 := mod( i + 3, 5 );
        tw(4-mi5) := tw(4-mi5) + rol32_5( tw(4-mod(i+4,5)) )
                        + bitor( bitand( tw(4-mi35), tw(4-mod(i+2,5)) )
                               , bitand( c_ffffffff - tw(4-mi35), tw(4-mod(i+1,5)) )
                               )
                        + w(i) + c_5A827999;
        tw( 4 - mi35 ) := rol32_30( tw( 4  -mi35 ) );
      end loop;
      for i in 20 .. 39
      loop
        mi5 := mod( i, 5 );
        mi35 := mod( i + 3, 5 );
        tw(4-mi5) := tw(4-mi5) + rol32_5( tw(4-mod(i+4,5)) )
                        + bitxor( bitxor( tw(4-mi35), tw(4-mod(i+2,5)) )
                                , tw(4-mod(i+1,5))
                                )
                        + w(i) + c_6ED9EBA1;
        tw( 4 - mi35 ) := rol32_30( tw( 4  -mi35 ) );
      end loop;
      for i in 40 .. 59
      loop
        mi5 := mod( i, 5 );
        mi35 := mod( i + 3, 5 );
        tw(4-mi5) := tw(4-mi5) + rol32_5( tw(4-mod(i+4,5)) )
                        + bitor( bitand( tw(4-mi35), tw(4-mod(i+2,5)) )
                               , bitor( bitand( tw(4-mi35), tw(4-mod(i+1,5)) )
                                              , bitand( tw(4-mod(i+2,5)), tw(4-mod(i+1,5)) )
                                              )
                               )
                        + w(i) + c_8F1BBCDC;
        tw( 4 - mi35 ) := rol32_30( tw( 4  -mi35 ) );
      end loop;
      for i in 60 .. 79
      loop
        mi5 := mod( i, 5 );
        mi35 := mod( i + 3, 5 );
        tw(4-mi5) := tw(4-mi5) + rol32_5( tw(4-mod(i+4,5)) )
                        + bitxor( bitxor( tw(4-mi35), tw(4-mod(i+2,5)) )
                                , tw(4-mod(i+1,5))
                                )
                        + w(i) + c_CA62C1D6;
        tw( 4 - mi35 ) := rol32_30( tw( 4  -mi35 ) );
      end loop;
      for i in 0 .. 4
      loop
        th(i) := th(i) + tw(i);
      end loop;
    end;
  begin
    th(0) := 1732584193;  -- '67452301
    th(1) := -271733879;  -- EFCDAB89
    th(2) := -1732584194; -- 98BADCFE
    th(3) := 271733878;   -- 10325476
    th(4) := -1009589776; -- C3D2E1F0
    --
    l_len := nvl( dbms_lob.getlength( p_src ), 0 );
    l_blocks_2do := trunc( l_len / 64 );
    l_mod_len := mod( l_len, 64 );
    l_first_block_len := utl_raw.length( p_first_block );
    if l_first_block_len != 64
    then
      l_first_block_len := 0;
    end if;
    l_padding := utl_raw.concat( hextoraw( '80' )
                               , case when l_mod_len < 55 then utl_raw.copies( hextoraw( '00' ), 55 - l_mod_len ) end
                               , case when l_mod_len > 55 then utl_raw.copies( hextoraw( '00' ), 119 - l_mod_len ) end
                               , to_char( ( l_len + nvl( l_first_block_len, 0 ) ) * 8, 'fm0XXXXXXXXXXXXXXX' )
                               );
    --
    if l_first_block_len = 64
    then
      sha1_block( p_first_block );
    end if;
    --
    l_idx := 1;
    loop
      exit when l_blocks_2do < 1;
      l_buf := dbms_lob.substr( p_src, least( 511, l_blocks_2do ) * 64, l_idx );
      for i in 0 .. least( 511, l_blocks_2do ) - 1
      loop
        sha1_block( utl_raw.substr( l_buf, 1 + i * 64, 64 ) );
      end loop;
      l_idx := l_idx + 32704;
      l_blocks_2do := l_blocks_2do - 511;
    end loop;
    --
    l_buf := utl_raw.concat( dbms_lob.substr( p_src, l_mod_len, l_len - l_mod_len + 1 )
                           , l_padding
                           );
    sha1_block( utl_raw.substr( l_buf, 1, 64 ) );
    if utl_raw.length( l_buf ) > 64
    then
      sha1_block( utl_raw.substr( l_buf, 65 ) );
    end if;
    --
    return utl_raw.concat( utl_raw.cast_from_binary_integer( th(0) )
                         , utl_raw.cast_from_binary_integer( th(1) )
                         , utl_raw.cast_from_binary_integer( th(2) )
                         , utl_raw.cast_from_binary_integer( th(3) )
                         , utl_raw.cast_from_binary_integer( th(4) )
                         );
  end;
  --
  function mac_sha1( src blob, key raw )
  return raw
  is
    l_key raw(128);
    l_len pls_integer;
    l_blocksize pls_integer := 64;
  begin
    l_len := utl_raw.length( key );
    if l_len > l_blocksize
    then
      l_key := sha1( key );
      l_len := utl_raw.length( l_key );
    else
      l_key := key;
    end if;
    if l_len < l_blocksize
    then
      l_key := utl_raw.concat( l_key, utl_raw.copies( hextoraw( '00' ), l_blocksize - l_len ) );
    elsif l_len is null
    then
      l_key := utl_raw.copies( hextoraw( '00' ), l_blocksize );
    end if;
    return sha1( sha1( src
                     , utl_raw.bit_xor( utl_raw.copies( hextoraw( '36' ), l_blocksize ), l_key )
                     )
               , utl_raw.bit_xor( utl_raw.copies( hextoraw( '5c' ), l_blocksize ), l_key )
               );
  end;
$END
$END
  --
  function inflate( p_cmpr blob, p_deflate64 boolean := true )
  return blob
  is
    l_rv blob;
    l_buf varchar2(32767);
    l_idx integer := 1;
    l_buf_idx integer := 32767;
    l_bit_idx number := 256;
    l_current number;
    l_final boolean;
    l_type number;
    l_len number;
    l_len_stored number;
    type tp_huffman_tree is table of pls_integer index by varchar2(16); -- max 16 bit codelength
    l_fixed_literal_tree tp_huffman_tree;
    l_fixed_distance_tree tp_huffman_tree;
    type tp_sliding_window is table of raw(1) index by pls_integer;
    l_sliding_window tp_sliding_window;
    l_slw_idx pls_integer := 0;
    l_slw_sz pls_integer := 65535;  -- actual size minus 1
    --
    function get_1bit
    return number
    is
      t number;
    begin
      if l_bit_idx > 128
      then
        l_bit_idx := 1;
        if l_buf_idx > 32766
        then
          l_buf := dbms_lob.substr( p_cmpr, 16383, l_idx );
          l_idx := l_idx + length( l_buf ) / 2;
          l_buf_idx := 1;
        end if;
        l_current := to_number( substr( l_buf, l_buf_idx, 2 ), 'xx' );
        l_buf_idx := l_buf_idx + 2;
      end if;
      t := sign( bitand( l_current, l_bit_idx ) );
      l_bit_idx := l_bit_idx * 2;
      return t;
    end;
    --
    function bit_string( p_code pls_integer, p_bits pls_integer )
    return varchar2
    is
      l_rv varchar2(16);
    begin
      for b in 0 .. p_bits - 1
      loop
        l_rv := case bitand( p_code, power( 2, b ) )
                  when 0 then '0'
                  else '1'
                end || l_rv;
      end loop;
      return l_rv;
    end;
    --
    function get_extra( p_bits pls_integer )
    return number
    is
      l_rv number := 0;
    begin
      for i in 0 .. p_bits - 1
      loop
        if get_1bit > 0
        then
          l_rv := l_rv + power( 2, i );
        end if;
      end loop;
      return l_rv;
    end;
    --
    procedure slw2rv( p_max pls_integer )
    is
      l_tmp varchar2(32767);
    begin
      if p_max < 0
      then
         return;
      end if;
      for j in 0 .. 4
      loop
        l_tmp := null;
        for i in j * 16383 .. least( j * 16383 + 16382, p_max )
        loop
          l_tmp := l_tmp || l_sliding_window( i );
        end loop;
        if l_tmp is not null
        then
          dbms_lob.writeappend( l_rv, length( l_tmp ) / 2, l_tmp );
        end if;
      end loop;
    end;
    --
    procedure add2_sliding_window( p_uncpr raw )
    is
    begin
      for i in 1 .. utl_raw.length( p_uncpr )
      loop
        l_sliding_window( l_slw_idx ) := utl_raw.substr( p_uncpr, i, 1 );
        if l_slw_idx >= l_slw_sz
        then
          slw2rv( l_slw_idx );
          l_slw_idx := 0;
        else
          l_slw_idx := l_slw_idx + 1;
        end if;
      end loop;
    end;
    --
    procedure from_slw_to_slw
      ( p_len pls_integer
      , p_distance pls_integer
      )
    is
      l_slw_i pls_integer;
    begin
      l_slw_i := l_slw_idx - p_distance;
      if l_slw_i < 0
      then
        l_slw_i := l_slw_i + l_slw_sz + 1;
      end if;
      for i in 1 .. p_len
      loop
        add2_sliding_window( l_sliding_window( l_slw_i ) );
        if l_slw_i >= l_slw_sz
        then
          l_slw_i := 0;
        else
          l_slw_i := l_slw_i + 1;
        end if;
      end loop;
    end;
    --
    procedure inflate_huffman
      ( p_literal_tree tp_huffman_tree
      , p_distance_tree tp_huffman_tree
      )
    is
      l_code varchar2(16);
      l_symbol number;
      l_distance number;
      l_extra_bits number;
    begin
      loop
        l_code := case get_1bit when 0 then '0' else '1' end;
        while not p_literal_tree.exists( l_code )
        loop
          l_code := l_code || case get_1bit when 0 then '0' else '1' end;
        end loop;
        l_symbol := p_literal_tree( l_code );
        if l_symbol < 256
        then
          add2_sliding_window( to_char( l_symbol, 'fm0X' ) );
        elsif l_symbol = 256
        then
          exit;
        else
          if l_symbol < 265
          then
            l_len := l_symbol - 254;
          elsif l_symbol = 285
          then
            l_len := case when p_deflate64 then 3 + get_extra( 16 ) else 258 end;
          else
            l_extra_bits := trunc( ( l_symbol - 261 ) / 4 );
            l_len := case
                       when l_symbol between 265 and 268 then 11
                       when l_symbol between 269 and 272 then 19
                       when l_symbol between 273 and 276 then 35
                       when l_symbol between 277 and 280 then 67
                       when l_symbol between 281 and 284 then 131
                     end + mod( l_symbol - 1, 4 ) * power( 2, l_extra_bits );
            l_len := l_len + get_extra( l_extra_bits );
          end if;
          l_code := case get_1bit when 0 then '0' else '1' end;
          while not p_distance_tree.exists( l_code )
          loop
            l_code := l_code || case get_1bit when 0 then '0' else '1' end;
          end loop;
          l_distance := p_distance_tree( l_code );
          if l_distance > 3
          then
            l_extra_bits := trunc( l_distance / 2 ) - 1;
            if bitand( l_distance, 1 ) = 0
            then
              l_distance := power( 2, l_extra_bits + 1 );
            else
              l_distance := power( 2, l_extra_bits )
                          + power( 2, l_extra_bits + 1 );
            end if;
            l_distance := l_distance + get_extra( l_extra_bits );
          end if;
          l_distance := l_distance + 1;
          from_slw_to_slw( l_len, l_distance );
        end if;
      end loop;
    end;
    --
    procedure handle_dynamic_huffman_block
    is
      l_hlit number;
      l_hdist number;
      l_hclen number;
      l_tmp number;
      l_tree tp_huffman_tree;
      l_literal_tree tp_huffman_tree;
      l_distance_tree tp_huffman_tree;
      type tp_num_tab is table of pls_integer index by pls_integer;
      l_bit_counts tp_num_tab;
      l_tmp_bit_counts tp_num_tab;
      type tp_remap_tab is table of pls_integer;
      l_remap_tab tp_remap_tab := tp_remap_tab( 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 );
      l_extra number;
      l_i pls_integer;
      --
      procedure build_huffman_tree
        ( p_bit_counts tp_num_tab
        , p_tree out tp_huffman_tree
        , p_max pls_integer
        )
      is
        l_code number := 0;
      begin
        for b in 1 .. p_max
        loop
          for i in p_bit_counts.first .. p_bit_counts.last
          loop
            if p_bit_counts( i ) = b
            then
              p_tree( bit_string( l_code, b ) ) := i;
              l_code := l_code + 1;
            end if;
          end loop;
          l_code := l_code * 2;
        end loop;
      end;
      --
      procedure load_huffman_tree
        ( p_cnt pls_integer
        , p_tree out tp_huffman_tree
        )
      is
        l_i pls_integer;
        l_symbol pls_integer;
        l_code varchar2(16);
        l_bit_counts tp_num_tab;
        l_max pls_integer := 0;
      begin
        l_i := 0;
        while l_i < p_cnt
        loop
          l_code := case get_1bit when 0 then '0' else '1' end;
          while not l_tree.exists( l_code )
          loop
            l_code := l_code || case get_1bit when 0 then '0' else '1' end;
          end loop;
          l_symbol := l_tree( l_code );
          if l_symbol = 16
          then
            for i in 1 .. 3 + get_extra( 2 )
            loop
              l_bit_counts( l_i ) := l_bit_counts( l_i - 1 );
              l_i := l_i + 1;
            end loop;
          elsif l_symbol = 17
          then
            for i in 1 .. 3 + get_extra( 3 )
            loop
              l_bit_counts( l_i ) := 0;
              l_i := l_i + 1;
            end loop;
          elsif l_symbol = 18
          then
            for i in 1 .. 11 + get_extra( 7 )
            loop
              l_bit_counts( l_i ) := 0;
              l_i := l_i + 1;
            end loop;
          else
            l_bit_counts( l_i ) := l_symbol;
            l_i := l_i + 1;
            l_max := greatest( l_max, l_symbol );
          end if;
        end loop;
        build_huffman_tree( l_bit_counts, p_tree, l_max );
      end;
    begin
      l_hlit := get_extra( 5 );
      l_hdist := get_extra( 5 );
      l_hclen := get_extra( 4 );
      for i in 1 .. l_hclen + 4
      loop
        l_tmp_bit_counts( i ) := get_extra( 3 );
      end loop;
      for i in l_hclen + 5 .. 19
      loop
        l_tmp_bit_counts( i ) := 0;
      end loop;
      for i in 1 .. 19
      loop
        l_bit_counts( l_remap_tab( i ) ) := l_tmp_bit_counts( i );
      end loop;
      build_huffman_tree( l_bit_counts, l_tree, 7 );
      load_huffman_tree( l_hlit + 257, l_literal_tree );
      load_huffman_tree( l_hdist + 1, l_distance_tree );
      inflate_huffman( l_literal_tree, l_distance_tree );
    end;
    --
    procedure add_codes_to_tree
      ( huffman_tree in out nocopy tp_huffman_tree
      , bit_cnt       pls_integer
      , cnt           pls_integer
      , start_symbol  pls_integer
      , start_code    pls_integer
      )
    is
    begin
      for i in 0 .. cnt - 1
      loop
        huffman_tree( bit_string( start_symbol + i, bit_cnt ) ) := start_code + i;
      end loop;
    end;
  begin
    dbms_lob.createtemporary( l_rv, true, c_lob_duration );
    l_len := dbms_lob.getlength( p_cmpr );
    loop
      l_final := get_1bit > 0;
      l_type := get_1bit + 2 * get_1bit;
      if l_type = 2
      then
        handle_dynamic_huffman_block;
      elsif l_type = 1
      then
        if l_fixed_literal_tree.count = 0
        then
          add_codes_to_tree( l_fixed_literal_tree, 8, 144, 48, 0 );
          add_codes_to_tree( l_fixed_literal_tree, 9, 112, 400, 144 );
          add_codes_to_tree( l_fixed_literal_tree, 7, 24, 0, 256 );
          add_codes_to_tree( l_fixed_literal_tree, 8, 8, 192, 280 );
          for i in 0 .. 31
          loop
            l_fixed_distance_tree( bit_string( i, 5 ) ) := i;
          end loop;
        end if;
        inflate_huffman( l_fixed_literal_tree, l_fixed_distance_tree );
      elsif l_type = 0
      then
        l_bit_idx := 256; -- ignore remaining bits in current byte
        l_idx := l_idx - length( l_buf ) / 2; -- reset in file to before current buffer
        l_idx := l_idx + ( l_buf_idx - 1 ) / 2; -- add again processed part of buffer
        l_len_stored := to_number( utl_raw.reverse( dbms_lob.substr( p_cmpr, 2, l_idx ) ), 'XXXX' );
        l_idx := l_idx + 4; -- skip LEN and NLEN
        if l_len_stored = 0
        then
          null;
        else
          for i in 0 .. trunc( ( l_len_stored - 1 ) / 16383 )
          loop
            add2_sliding_window( dbms_lob.substr( p_cmpr, least( l_len_stored - i * 16383, 16383 ), l_idx + i * 16383 ) );
          end loop;
        end if;
        l_buf_idx := 32767; -- mark buffer as empty
      else
        raise no_data_found;
      end if;
      exit when l_final;
    end loop;
    slw2rv( l_slw_idx - 1 );
    return l_rv;
  end;
  --
  procedure init_zipcrypto_tab
  is
    l_poly raw(4) := hextoraw( 'EDB88320' );
    l_tmp integer;
  begin
    for i in 0 .. 255
    loop
      l_tmp := i;
      for j in 1 .. 8
      loop
        if mod( l_tmp, 2 ) = 1
        then
          l_tmp := to_number( rawtohex( utl_raw.bit_xor( hextoraw( to_char( trunc( l_tmp / 2 ), 'fm0xxxxxxx' ) ), l_poly ) ), 'xxxxxxxx' );
        else
          l_tmp := trunc( l_tmp / 2 );
        end if;
      end loop;
      l_zipcrypto_tab( to_char( i, 'fm0X' ) ) := hextoraw( to_char( l_tmp, 'fm0xxxxxxx' ) );
    end loop;
  end;
  --
  procedure update_keys( p_char raw )
  is
    l_crc raw(4);
    l_tmp number;
  begin
    l_key1 := utl_raw.bit_xor( l_zipcrypto_tab( utl_raw.bit_xor( p_char, utl_raw.substr( l_key1, 4, 1 ) ) )
                             , utl_raw.concat( hextoraw( '00' ), utl_raw.substr( l_key1, 1, 3 ) )
                             );
    l_tmp := mod( ( to_number( rawtohex( l_key2 ), 'xxxxxxxx' )
                  + to_number( rawtohex( utl_raw.substr( l_key1, 4, 1 ) ), 'xx' )
                  ) * 134775813 + 1
                , 4294967296
                );
    l_key2 := hextoraw( to_char( l_tmp, 'fm0XXXXXXX' ) );
    l_key3 := utl_raw.bit_xor( l_zipcrypto_tab( utl_raw.bit_xor( utl_raw.substr( l_key2, 1, 1 ), utl_raw.substr( l_key3, 4, 1 ) ) )
                             , utl_raw.concat( hextoraw( '00' ), utl_raw.substr( l_key3, 1, 3 ) )
                             );
  end;
  --
  procedure init_keys( p_password raw )
  is
  begin
    l_key1 := hextoraw( '12345678' );
    l_key2 := hextoraw( '23456789' );
    l_key3 := hextoraw( '34567890' );
    for i in 1 .. nvl( utl_raw.length( p_password ), 0 )
    loop
      update_keys( utl_raw.substr( p_password, i, 1 ) );
    end loop;
  end;
  --
  function zipcrypto_crypt( p_chr raw )
  return raw
  is
    l_tmp raw(4);
  begin
    l_tmp := utl_raw.bit_or( l_key3, hextoraw( '00000002' ) );
    l_tmp := to_char( mod( to_number( l_tmp, 'xxxxxxxx' )
                         * to_number( utl_raw.bit_xor( l_tmp, hextoraw( '00000001' ) ), 'xxxxxxxx' )
                         , 4294967296
                         )
                    , 'fm0xxxxxxx'
                    );
    l_tmp := utl_raw.bit_xor( p_chr, utl_raw.substr( l_tmp, 3, 1 ) );
    return l_tmp;
  end;
  --
  function little_endian( p_big number, p_bytes pls_integer := 4 )
  return raw
  is
  begin
    return utl_raw.reverse( to_char( p_big, 'fm' || rpad( '0', 2 * p_bytes, 'X' ) ) );
  end;
  --
  function little_endian( p_num raw, p_pos pls_integer := 1, p_bytes pls_integer := null )
  return integer
  is
  begin
    return to_number( utl_raw.reverse( utl_raw.substr( p_num, p_pos, p_bytes ) ), 'XXXXXXXXXXXXXXXX' );
  end;
  --
  function get_encoding( p_encoding in varchar2 := null )
  return varchar2
  is
    l_encoding varchar2(32767);
  begin
    if p_encoding is not null
    then
      if nls_charset_id( p_encoding ) is null
      then
        l_encoding := utl_i18n.map_charset( p_encoding, utl_i18n.GENERIC_CONTEXT, utl_i18n.IANA_TO_ORACLE );
      else
        l_encoding := p_encoding;
      end if;
    end if;
    return coalesce( l_encoding, 'US8PC437' ); -- IBM codepage 437
  end;
  --
  function get_64k_raw( p_raw1 raw, p_raw2 raw, p_raw3 raw, p_encoding varchar2 := null )
  return clob
  is
    l_rv clob;
    l_tmp blob;
    l_dest_offset integer := 1;
    l_src_offset  integer := 1;
    l_context     integer := dbms_lob.default_lang_ctx;
    l_warning     integer;
    l_csid        integer := nls_charset_id( coalesce( p_encoding, 'CHAR_CS' ) );
  begin
    if p_raw1 is null
    then
      return null;
    end if;
    begin
      if p_raw2 is null
      then
        return utl_i18n.raw_to_char( p_raw1, p_encoding );
      end if;
    exception
      when others then null;
    end;
    l_tmp := p_raw1;
    if p_raw2 is not null
    then
      dbms_lob.writeappend( l_tmp, utl_raw.length( p_raw2 ), p_raw2 );
      if p_raw3 is not null
      then
        dbms_lob.writeappend( l_tmp, utl_raw.length( p_raw3 ), p_raw3 );
      end if;
    end if;
    dbms_lob.createtemporary( l_rv, true );
    dbms_lob.converttoclob( l_rv, l_tmp, dbms_lob.lobmaxsize, l_dest_offset, l_src_offset, l_csid, l_context, l_warning );
    dbms_lob.freetemporary( l_tmp );
    return l_rv;
  end;
  --
  procedure get_zip_info( p_zip blob, p_info out tp_zip_info, p_get_comment boolean := false )
  is
    l_ind integer;
    l_buf_sz pls_integer := 2024;
    l_start_buf integer;
    l_buf raw(32767);
  begin
    p_info.len := nvl( dbms_lob.getlength( p_zip ), 0 );
    if p_info.len < 22
    then -- no (zip) file or empty zip file
      return;
    end if;
    l_start_buf := greatest( p_info.len - l_buf_sz + 1, 1 );
    l_buf := dbms_lob.substr( p_zip, l_buf_sz, l_start_buf );
    l_ind := utl_raw.length( l_buf ) - 21;
    loop
      exit when l_ind < 1 or utl_raw.substr( l_buf, l_ind, 4 ) = c_END_OF_CENTRAL_DIRECTORY;
      l_ind := l_ind - 1;
    end loop;
    if l_ind > 0
    then
      l_ind := l_ind + l_start_buf - 1;
    else
      l_ind := p_info.len - 21;
      loop
        exit when l_ind < 1 or dbms_lob.substr( p_zip, 4, l_ind ) = c_END_OF_CENTRAL_DIRECTORY;
        l_ind := l_ind - 1;
      end loop;
    end if;
    if l_ind <= 0
    then
      raise_application_error( -20001, 'Error parsing the zipfile' );
    end if;
    l_buf := dbms_lob.substr( p_zip, 22, l_ind );
    if    utl_raw.substr( l_buf, 5, 2 ) != utl_raw.substr( l_buf, 7, 2 )  -- this disk = disk with start of Central Dir
       or utl_raw.substr( l_buf, 9, 2 ) != utl_raw.substr( l_buf, 11, 2 ) -- complete CD on this disk
    then
      raise_application_error( -20003, 'Error parsing the zipfile' );
    end if;
    p_info.idx_eocd := l_ind;
    p_info.zip64 :=  (  utl_raw.substr( l_buf,  5, 2 ) = 'FFFF'
                     or utl_raw.substr( l_buf,  7, 2 ) = 'FFFF'
                     or utl_raw.substr( l_buf,  9, 2 ) = 'FFFF'
                     or utl_raw.substr( l_buf, 11, 2 ) = 'FFFF'
                     or utl_raw.substr( l_buf, 13, 4 ) = 'FFFFFFFF'
                     or utl_raw.substr( l_buf, 17, 4 ) = 'FFFFFFFF'
                     ) and l_ind > 21;
    if p_info.zip64
    then
      l_buf := dbms_lob.substr( p_zip, 20, l_ind - 20 );
      if utl_raw.substr( l_buf, 1, 4 ) != c_ZIP64_END_OF_CD_LOCATOR -- Zip64 end of central directory locator
      then
        raise_application_error( -20018, 'Error parsing the zipfile' );
      end if;
      if    utl_raw.substr( l_buf, 5, 4 ) != '00000000'  -- disk with the start of the zip64 end of central directory
         or utl_raw.substr( l_buf, 17, 4 ) != '01000000' -- total number of disks
      then
        raise_application_error( -20002, 'Error parsing the zipfile' );
      end if;
      l_ind := little_endian( l_buf, 9, 8 ) + 1;
      p_info.idx_zip64_eocd := l_ind;
      l_buf := dbms_lob.substr( p_zip, 64, l_ind );
      if utl_raw.substr( l_buf, 1, 4 ) != c_ZIP64_END_OF_CD -- Zip64 end of central directory
      then
        raise_application_error( -20019, 'Error parsing the zipfile' );
      elsif utl_raw.substr( l_buf, 5, 8 ) != '2C00000000000000'
      then
        raise_application_error( -20022, 'zip64 extensible data sector not supported yet' );
      end if;
      p_info.cnt := little_endian( l_buf, 25, 8 );
      p_info.idx_cd := little_endian( l_buf, 49, 8 ) + 1;
    else
      p_info.idx_cd := little_endian( l_buf, 17, 4 ) + 1;
      p_info.cnt := little_endian( l_buf, 9, 2 );
    end if;
    p_info.len_cd := nvl( p_info.idx_zip64_eocd, p_info.idx_eocd ) - p_info.idx_cd;
    p_info.len_comment := little_endian( l_buf, 21, 2 );
    if p_info.len_comment > 0 and p_get_comment
    then
      -- 32765, so size of comment and comment1 fit together in a raw(32767)
      p_info.comment1 := dbms_lob.substr( p_zip
                                        , least( p_info.len_comment, 32765 )
                                        , p_info.idx_eocd + 22
                                        );
      if p_info.len_comment > 32765
      then
        p_info.comment2 := dbms_lob.substr( p_zip
                                          , least( p_info.len_comment - 32765, 32767 )
                                          , p_info.idx_eocd + 22 + 32765
                                          );
      end if;
      if p_info.len_comment > 65532
      then
        p_info.comment3 := dbms_lob.substr( p_zip
                                          , least( p_info.len_comment - 65532, 100 )
                                          , p_info.idx_eocd + 22 + 65532
                                          );
      end if;
    end if;
  end;
  --
  function parse_file
    ( p_zipped_blob blob
    , p_fh in out tp_cfh
    , p_password raw
    )
  return blob
  is
    l_rv blob;
    l_deflate blob;
    l_rv_buf varchar2(32766);
    l_buf raw(3999);
    l_compression_method varchar2(4);
    l_n integer;
    l_m integer;
    l_crypto_2do integer;
    l_crypto_byte raw(1);
    l_crypto_buf varchar2(32767);
    c_crypto_sz constant pls_integer := 16383; -- size in bytes
    l_crc raw(4);
$IF as_zip.use_winzip_encryption
$THEN
    l_idx integer;
    l_key_bits pls_integer;
    l_key_len pls_integer;
    l_salt_len pls_integer;
    l_salt raw(16);
    l_key raw(80);
    l_mac raw(20);
    l_sum raw(20);
    l_block# integer;
    l_decrypted raw(128);
$IF as_zip.use_dbms_crypto
$THEN
$ELSE
    l_aes_key tp_aes_tab;
$END
$END
    --
    function zipcrypto_decrypt( p_chr raw )
    return raw
    is
      l_tmp raw(4) := zipcrypto_crypt( p_chr );
    begin
      update_keys( l_tmp );
      return l_tmp;
    end;
  begin
    if p_fh.original_len is null
    then
      raise_application_error( -20006, 'File not found' );
    end if;
    if nvl( p_fh.original_len, 0 ) = 0
    then
      return empty_blob();
    end if;
    l_buf := dbms_lob.substr( p_zipped_blob, 30, p_fh.offset + 1 );
    if utl_raw.substr( l_buf, 1, 4 ) != c_LOCAL_FILE_HEADER
    then
      raise_application_error( -20007, 'Error parsing the zipfile' );
    end if;
    l_compression_method := utl_raw.substr( l_buf, 9, 2 );
    l_n := little_endian( l_buf, 27, 2 );
    l_m := little_endian( l_buf, 29, 2 );
    dbms_lob.createtemporary( l_rv, true, c_lob_duration );
    if bitand( to_number( utl_raw.substr( l_buf, 7, 1 ), 'XX' ), 1 ) > 0
    then
      if l_compression_method = '6300'
      then -- Winzip AES encrypted
$IF as_zip.use_winzip_encryption
$THEN
        if p_password is null or utl_raw.length( p_password ) = 0
        then
          raise_application_error( -20009, 'No password provided' );
        end if;
        if l_m < 11 or l_m > 32767
        then
          raise_application_error( -20010, 'Error parsing the zipfile' );
        end if;
        l_crypto_buf := dbms_lob.substr( p_zipped_blob, l_m, p_fh.offset + 31 + l_n );
        l_idx := 1;
        loop
          exit when utl_raw.substr( l_crypto_buf, l_idx, 2 ) = '0199'; -- AE-x encryption structure
          l_idx := l_idx + to_number( utl_raw.reverse( utl_raw.substr( l_crypto_buf, l_idx + 2, 2 ) ), 'XXXX' );
          exit when l_idx > l_m;
        end loop;
        if l_idx > l_m or utl_raw.substr( l_crypto_buf, l_idx, 8 ) not in ( '0199070001004145', '0199070002004145' )
        then -- AE-x encryption structure AE1 or AE2
          raise_application_error( -20011, 'Error parsing the zipfile' );
        end if;
        l_compression_method := utl_raw.substr( l_crypto_buf, l_idx + 9, 2 );
        l_key_bits := case utl_raw.substr( l_crypto_buf, l_idx + 8, 1 )
                        when '01' then 128
                        when '02' then 192
                        when '03' then 256
                      end;
        if l_key_bits is null
        then
          raise_application_error( -20012, 'Error parsing the zipfile' );
        end if;
        l_key_len := l_key_bits / 4 + 2;
        l_salt_len := l_key_bits / 16;
        l_crypto_buf := dbms_lob.substr( p_zipped_blob, l_salt_len + 2, p_fh.offset + 31 + l_n + l_m );
        l_salt := utl_raw.substr( l_crypto_buf, 1, l_salt_len );
        for i in 1 .. ceil( l_key_len / 20 )
        loop
$IF as_zip.use_dbms_crypto
$THEN
          l_mac := dbms_crypto.mac( utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) ), dbms_crypto.hmac_sh1, p_password );
$ELSE
          l_mac := mac_sha1( utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) ), p_password );
$END
          l_sum := l_mac;
          for j in 1 .. 999
          loop
$IF as_zip.use_dbms_crypto
$THEN
            l_mac := dbms_crypto.mac( l_mac, dbms_crypto.hmac_sh1, p_password );
$ELSE
            l_mac := mac_sha1( l_mac, p_password );
$END
            l_sum := utl_raw.bit_xor( l_mac, l_sum );
          end loop;
          l_key := utl_raw.concat( l_key, l_sum );
        end loop;
        l_key := utl_raw.substr( l_key, 1, l_key_len );
        if utl_raw.substr( l_crypto_buf, l_salt_len + 1 ) != utl_raw.substr( l_key, -2, 2 ) -- Password verification value
        then
          raise_application_error( -20013, 'Wrong password provided' );
        end if;
        l_key := utl_raw.substr( l_key, 1, l_key_bits / 8 );
$IF as_zip.use_dbms_crypto
$THEN
$ELSE
        aes_encrypt_key( l_key, l_aes_key );
$END
        l_crypto_2do := p_fh.compressed_len - l_salt_len - 2 - 10; -- Password verification value and authentication code
        l_idx := p_fh.offset + 31 + l_n + l_m + l_salt_len + 2;
        l_block# := 1;
        loop
          exit when l_crypto_2do <= 0;
          l_rv_buf := null;
          l_crypto_buf := dbms_lob.substr( p_zipped_blob, least( 16368, l_crypto_2do ), l_idx );
          for i in 0 .. trunc( ( utl_raw.length( l_crypto_buf ) - 1 ) / 16 )
          loop
$IF as_zip.use_dbms_crypto
$THEN
    l_decrypted := dbms_crypto.encrypt( utl_raw.reverse( to_char( l_block#, 'fm' || lpad( 'X', 32, '0' ) ) )
                                      , dbms_crypto.ENCRYPT_AES + dbms_crypto.CHAIN_ECB + dbms_crypto.PAD_NONE
                                      , l_key
                                      );
$ELSE
    l_decrypted := aes_encrypt( utl_raw.reverse( to_char( l_block#, 'fm' || lpad( 'X', 32, '0' ) ) )
                              , l_key_bits / 8
                              , l_aes_key
                              );
$END
            l_rv_buf := utl_raw.concat( l_rv_buf
                                      , utl_raw.bit_xor( utl_raw.substr( l_crypto_buf, 1 + i*16, least( 16, l_crypto_2do - i*16 ) )
                                                       , utl_raw.substr( l_decrypted, 1, least( 16, l_crypto_2do - i*16 ) )
                                                       )
                                      );
            l_block# := l_block# + 1;
          end loop;
          l_idx := l_idx + 16368;
          l_crypto_2do := l_crypto_2do - 16368;
          dbms_lob.writeappend( l_rv, utl_raw.length( l_rv_buf ), l_rv_buf );
        end loop;
        if l_compression_method in ( '0800', '0900' )
        then
          return inflate( l_rv, l_compression_method = '0900' );
        elsif l_compression_method = '0000'
        then
          return l_rv;
        end if;
        raise_application_error( -20014, 'Unhandled compression method ' || l_compression_method );
$ELSE
        raise_application_error( -20015, 'Winzip Encryption is not enabled, change constant "use_winzip_encryption" in the package specication to true and recompile it.' );
$END
      else -- ZipCrypto
        init_zipcrypto_tab;
        init_keys( p_password );
        l_crc := 'FFFFFFFF';
        l_crypto_2do := p_fh.compressed_len;
        for i in 0 .. trunc( ( p_fh.compressed_len - 1 ) / c_crypto_sz )
        loop
          l_crypto_buf := dbms_lob.substr( p_zipped_blob, c_crypto_sz, p_fh.offset + 31 + l_n + l_m + i * c_crypto_sz );
          for j in 0 .. least( c_crypto_sz, l_crypto_2do ) - 1
          loop
            l_crypto_byte := zipcrypto_decrypt( substr( l_crypto_buf, j * 2 + 1, 2 ) );
            if i > 0 or j > 11
            then
              l_rv_buf := l_rv_buf || l_crypto_byte;
              l_crc :=  utl_raw.bit_xor( '00' || utl_raw.substr( l_crc, 1, 3 ), l_zipcrypto_tab( utl_raw.bit_xor(l_crypto_byte, utl_raw.substr( l_crc, 4, 1 ) ) ) );
            end if;
          end loop;
          l_crypto_2do := l_crypto_2do - c_crypto_sz;
          dbms_lob.writeappend( l_rv, length( l_rv_buf ) / 2, l_rv_buf );
          l_rv_buf := null;
        end loop;
        l_crc := utl_raw.bit_xor( l_crc, 'FFFFFFFF' );
      end if;
    else
      dbms_lob.copy( l_rv
                   , p_zipped_blob
                   , p_fh.compressed_len
                   , 1
                   , p_fh.offset + 31 + l_n + l_m
                   );
    end if;
    if l_compression_method in ( '0800', '0900' )
    then
      l_deflate := hextoraw( '1F8B0800000000000003' ); -- gzip header
      dbms_lob.copy( l_deflate
                   , l_rv
                   , p_fh.compressed_len
                   , 11
                   , 1
                   );
      dbms_lob.append( l_deflate
                     , utl_raw.concat( p_fh.crc32
                                     , utl_raw.substr( utl_raw.reverse( to_char( p_fh.original_len, 'fm0XXXXXXXXXXXXXXX' ) ), 1, 4 )
                                     )
                     );
      begin
        return utl_compress.lz_uncompress( l_deflate );
      exception
        when others then
          return inflate( l_rv );
      end;
    elsif l_compression_method = '0000'
    then
      return l_rv;
    end if;
    raise_application_error( -20008, 'Unhandled compression method ' || l_compression_method );
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
    dest_offset integer := 1;
    src_offset  integer := 1;
  begin
    file_lob := bfilename( p_dir, p_file_name );
    dbms_lob.open( file_lob, dbms_lob.file_readonly );
    dbms_lob.createtemporary( file_blob, true, c_lob_duration );
    dbms_lob.loadblobfromfile( file_blob, file_lob, dbms_lob.lobmaxsize, dest_offset, src_offset );
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
  function parse_central_file_header
    ( p_zip blob
    , p_ind integer
    , p_cfh out tp_cfh
    , p_get_comment boolean := false
    )
  return boolean
  is
    l_tmp pls_integer;
    l_len pls_integer;
    l_buf raw(32767);
  begin
    l_buf := dbms_lob.substr( p_zip, 46, p_ind );
    if utl_raw.substr( l_buf, 1, 4 ) != c_CENTRAL_FILE_HEADER
    then
      return false;
    end if;
    p_cfh.crc32 := utl_raw.substr( l_buf, 17, 4 );
    p_cfh.n := little_endian( l_buf, 29, 2 );
    p_cfh.m := little_endian( l_buf, 31, 2 );
    p_cfh.k := little_endian( l_buf, 33, 2 );
    p_cfh.external_file_attr := utl_raw.substr( l_buf, 39, 4 );
    p_cfh.len := 46 + p_cfh.n + p_cfh.m + p_cfh.k;
    --
    p_cfh.encrypted := bitand( to_number( utl_raw.substr( l_buf, 9, 1 ), 'XX' ), 1 ) > 0;
    p_cfh.utf8 := bitand( to_number( utl_raw.substr( l_buf, 10, 1 ), 'XX' ), 8 ) > 0;
    if p_cfh.n > 0
    then
      p_cfh.name1 := dbms_lob.substr( p_zip, least( p_cfh.n, 32767 ), p_ind + 46 );
      if p_cfh.n > 32767
      then
        p_cfh.name2 := dbms_lob.substr( p_zip, least( p_cfh.n - 32767, 32767 ), p_ind + 46 + 32767 );
      end if;
      if p_cfh.n > 65534
      then
        p_cfh.name3 := dbms_lob.substr( p_zip, least( p_cfh.n - 65534, 100 ), p_ind + 46 + 65534 );
      end if;
    end if;
    --
    p_cfh.compressed_len := little_endian( l_buf, 21, 4 );
    p_cfh.original_len := little_endian( l_buf, 25, 4 );
    p_cfh.offset := little_endian( l_buf, 43, 4 );
    p_cfh.zip64_offset := null;
    if   p_cfh.compressed_len = 4294967295 -- FFFFFFFF
      or p_cfh.original_len = 4294967295
      or p_cfh.offset = 4294967295
    then
      if p_cfh.m < 12
      then -- we need a zip64 extension
        raise_application_error( -20004, 'Error parsing the zipfile' );
      end if;
      if p_cfh.m > 32767
      then
        raise_application_error( -20005, 'extra field too large to handle' );
      end if;
      l_buf := dbms_lob.substr( p_zip, p_cfh.m, p_ind + 46 + p_cfh.n );
      l_tmp := 1;
      loop
        exit when utl_raw.substr( l_buf, l_tmp, 2 ) = '0100';
        l_len := little_endian( l_buf, l_tmp + 2, 2 );
        l_tmp := l_tmp + 4 + l_len;
        if l_tmp >= p_cfh.m - 2
        then
          l_tmp := 0;
          exit;
        end if;
      end loop;
      if l_tmp > 0
      then
        l_len := little_endian( l_buf, l_tmp + 2, 2 );
        l_tmp := l_tmp + 4;
        if p_cfh.original_len = 4294967295
        then
          p_cfh.original_len := little_endian( l_buf, l_tmp, 8 );
          l_tmp := l_tmp + 8;
        end if;
        if p_cfh.compressed_len = 4294967295
        then
          p_cfh.compressed_len := little_endian( l_buf, l_tmp, 8 );
          l_tmp := l_tmp + 8;
        end if;
        if p_cfh.offset = 4294967295
        then
          p_cfh.offset := little_endian( l_buf, l_tmp, 8 );
          p_cfh.zip64_offset := 46 + p_cfh.n + l_tmp;
        end if;
      end if;
    end if;
    --
    if p_cfh.k > 0 and p_get_comment
    then
      -- 32765, so size of comment and comment1 fit together in a raw(32767)
      p_cfh.comment1 := dbms_lob.substr( p_zip
                                       , least( p_cfh.k, 32765 )
                                       , p_ind + 46 + p_cfh.n + p_cfh.m
                                       );
      if p_cfh.k > 32765
      then
        p_cfh.comment2 := dbms_lob.substr( p_zip
                                         , least( p_cfh.k - 32765, 32767 )
                                         , p_ind + 46 + p_cfh.n + p_cfh.m + 32765
                                         );
      end if;
      if p_cfh.k > 65532
      then
        p_cfh.comment3 := dbms_lob.substr( p_zip
                                         , least( p_cfh.k - 65532, 100 )
                                         , p_ind + 46 + p_cfh.n + p_cfh.m + 65532
                                         );
      end if;
    end if;
    --
    return true;
  end;
  --
  procedure write_eocd
    ( p_zip in out nocopy blob
    , p_force_zip64 boolean
    , p_count integer
    , p_len_cd integer
    , p_offs_cd integer
    , p_info tp_zip_info
    )
  is
  begin
    if p_force_zip64 or p_count >= 65535 -- FFFF
    then
      dbms_lob.writeappend( p_zip
                          , 96
                          , utl_raw.concat( c_ZIP64_END_OF_CD
                                          , '2C000000000000002D002D000000000000000000'
                                          , little_endian( p_count, 8 )
                                          , little_endian( p_count, 8 )
                                          , little_endian( p_len_cd, 8 )
                                          , little_endian( p_offs_cd, 8 )
                                          , c_ZIP64_END_OF_CD_LOCATOR
                                          , '00000000'
                                          , little_endian( p_offs_cd + p_len_cd, 8 )
                                          , '01000000'
                                          , c_END_OF_CENTRAL_DIRECTORY
                                          , 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
                                          )
                          );
    else
      dbms_lob.writeappend( p_zip
                          , 20
                          , utl_raw.concat( c_END_OF_CENTRAL_DIRECTORY
                                          , '00000000'
                                          , little_endian( p_count, 2 )
                                          , little_endian( p_count, 2 )
                                          , little_endian( p_len_cd )
                                          , little_endian( p_offs_cd )
                                          )
                          );
    end if;
    dbms_lob.writeappend( p_zip
                        , p_info.len_comment + 2
                        , utl_raw.concat( little_endian( p_info.len_comment, 2 ), p_info.comment1 )
                        );
    if p_info.comment2 is not null
    then
      dbms_lob.writeappend( p_zip
                          , utl_raw.length( p_info.comment2 )
                          , p_info.comment2
                          );
    end if;
    if p_info.comment3 is not null
    then
      dbms_lob.writeappend( p_zip
                          , utl_raw.length( p_info.comment3 )
                          , p_info.comment3
                          );
    end if;
  end;
  --
  procedure get_files
    ( p_zipped_blob blob
    , p_encoding    varchar2 := null
    , p_start_entry integer  := null
    , p_max_entries integer  := null
    , p_list boolean
    , p_file_list out  file_list
    , p_file_names out file_names
    )
  is
    l_info tp_zip_info;
    l_cfh tp_cfh;
    l_ind integer;
    l_idx integer;
    l_encoding varchar2(3999);
    l_cnt pls_integer := 0;
  begin
    if p_list
    then
      p_file_list := file_list();
    else
      p_file_names := file_names();
    end if;
    --
    get_zip_info( p_zipped_blob, l_info );
    if nvl( l_info.cnt, 0 ) < 1
    then -- no (zip) file or empty zip file
      return;
    end if;
    --
    l_encoding := get_encoding( p_encoding );
    l_idx := 1;
    l_ind := l_info.idx_cd;
    loop
      exit when nvl( p_start_entry, 1 ) - 1 + p_max_entries < l_idx
                or not parse_central_file_header( p_zipped_blob, l_ind, l_cfh );
      if l_idx >= nvl( p_start_entry, 1 )
      then
        l_cnt := l_cnt + 1;
        if p_list
        then
          p_file_list.extend;
          p_file_list( l_cnt ) := get_64k_raw( l_cfh.name1
                                             , l_cfh.name2
                                             , l_cfh.name3
                                             , case when l_cfh.utf8 then 'AL32UTF8' else l_encoding end
                                             );
        else
          p_file_names.extend;
          p_file_names( l_cnt ) := utl_i18n.raw_to_char( l_cfh.name1
                                                        , case when l_cfh.utf8 then 'AL32UTF8' else l_encoding end
                                                        );
        end if;
      end if;
      l_ind := l_ind + l_cfh.len;
      l_idx := l_idx + 1;
    end loop;
    --
  end;
  --
  function get_file_list
    ( p_zipped_blob blob
    , p_encoding varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_list
  is
    l_file_list  file_list;
    l_file_names file_names;
  begin
    get_files
      ( p_zipped_blob
      , p_encoding
      , p_start_entry
      , p_max_entries
      , true
      , l_file_list
      , l_file_names
      );
    return l_file_list;
  end;
  --
  function get_file_list
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_encoding varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_list
  is
  begin
    return get_file_list( file2blob( p_dir, p_zip_file ), p_encoding, p_start_entry, p_max_entries );
  end;
  --
  function get_file_names
    ( p_zipped_blob blob
    , p_encoding    varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_names
  is
    l_file_list  file_list;
    l_file_names file_names;
  begin
    get_files
      ( p_zipped_blob
      , p_encoding
      , p_start_entry
      , p_max_entries
      , false
      , l_file_list
      , l_file_names
      );
    return l_file_names;
  end;
  --
  function get_file_names
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_encoding varchar2 := null
    , p_start_entry integer := null
    , p_max_entries integer := null
    )
  return file_names
  is
  begin
    return get_file_names( file2blob( p_dir, p_zip_file ), p_encoding, p_start_entry, p_max_entries );
  end;
  --
  function get_central_file_header
    ( p_zip      blob
    , p_name     varchar2 character set any_cs
    , p_idx      number
    , p_encoding varchar2
    , p_cfh      out tp_cfh
    )
  return boolean
  is
    l_rv        boolean;
    l_ind       integer;
    l_idx       integer;
    l_info      tp_zip_info;
    l_name      raw(32767);
    l_utf8_name raw(32767);
    l_charset   varchar2(1000);
  begin
    if p_name is null and p_idx is null
    then
      return false;
    end if;
    get_zip_info( p_zip, l_info, true );
    if nvl( l_info.cnt, 0 ) < 1
    then -- no (zip) file or empty zip file
      return false;
    end if;
    --
    if p_name is not null
    then
      l_charset := case when isnchar( p_name ) then 'N' end || 'CHAR_CS';
      l_charset := nls_charset_name( nls_charset_id( l_charset ) );
      l_name := utl_raw.convert( utl_i18n.string_to_raw( p_name )
                               , get_encoding( p_encoding )
                               , l_charset
                               );
--      l_name := utl_i18n.string_to_raw( p_name, p_cfh.encoding );
      l_utf8_name := utl_raw.convert( utl_i18n.string_to_raw( p_name )
                                    , 'AL32UTF8'
                                    , l_charset
                                    );
    end if;
    --
    l_rv := false;
    l_ind := l_info.idx_cd;
    l_idx := 1;
    loop
      exit when not parse_central_file_header( p_zip, l_ind, p_cfh, true );
      if l_idx = p_idx
         or p_cfh.name1 = case when p_cfh.utf8 then l_utf8_name else l_name end
      then
        l_rv := true;
        exit;
      end if;
      l_ind := l_ind + p_cfh.len;
      l_idx := l_idx + 1;
    end loop;
    --
    p_cfh.idx := l_idx;
    p_cfh.encoding := get_encoding( p_encoding );
    return l_rv;
  end;
  --
  function get_file
    ( p_zipped_blob blob
    , p_file_name varchar2 character set any_cs := null
    , p_encoding varchar2 := null
    , p_nfile_name varchar2 character set any_cs := null
    , p_idx number := null
    , p_password varchar2 := null
    )
  return blob
  is
    l_cfh tp_cfh;
  begin
    if not (  get_central_file_header( p_zipped_blob
                                     , p_file_name
                                     , p_idx
                                     , p_encoding
                                     , l_cfh
                                     )
           or get_central_file_header( p_zipped_blob
                                     , p_nfile_name
                                     , p_idx
                                     , p_encoding
                                     , l_cfh
                                     )
           )
    then
      return null;
    end if;
    return parse_file( p_zipped_blob, l_cfh, utl_raw.cast_to_raw( p_password ) );
  end;
  --
  function get_file
    ( p_dir varchar2
    , p_zip_file varchar2
    , p_file_name varchar2 character set any_cs := null
    , p_encoding varchar2 := null
    , p_nfile_name varchar2 character set any_cs := null
    , p_idx number := null
    , p_password varchar2 := null
    )
  return blob
  is
  begin
    return get_file( file2blob( p_dir, p_zip_file ), p_file_name, p_encoding, p_nfile_name, p_idx, p_password );
  end;
  --
  function encrypt( p_pw varchar2, p_src blob, p_crc32 raw, p_zipcrypto boolean)
  return blob
  is
    l_rv blob;
    l_pw raw(32767) := utl_raw.cast_to_raw( p_pw );
$IF as_zip.use_winzip_encryption
$THEN
    l_salt raw(16);
    l_key  raw(32);
    l_key_bits pls_integer := 256;
    l_key_length pls_integer := l_key_bits / 8 * 2 + 2;
    l_cnt pls_integer := 1000;
    l_keys raw(32767);
    l_sum raw(32767);
    l_mac raw(20);
    l_block raw(16);
    l_encrypted raw(16);
    l_len pls_integer;
    l_tmp blob;
$IF as_zip.use_dbms_crypto
$THEN
$ELSE
    l_aes_key tp_aes_tab;
$END
$END
  l_buf varchar2(32767);
  l_buf2 varchar2(32767);
  --
  function zipcrypto_encrypt( p_chr raw )
  return raw
  is
    l_tmp raw(4) := zipcrypto_crypt( p_chr );
  begin
    update_keys( p_chr );
    return l_tmp;
  end;
  begin
$IF as_zip.use_winzip_encryption
$THEN
   if p_zipcrypto
   then
$END
    init_zipcrypto_tab;
    init_keys( l_pw );
    for i in 1 .. 11
    loop
      l_buf2 := l_buf2 || zipcrypto_encrypt( to_char( trunc( dbms_random.value( 0, 256 ) ), 'fmXX' ) );
    end loop;
    l_buf2 := l_buf2 || zipcrypto_encrypt( utl_raw.substr( p_crc32, 4, 1 ) );
    dbms_lob.createtemporary( l_rv, true, c_lob_duration );
    for i in 0 .. trunc( ( dbms_lob.getlength( p_src ) - 1 ) / 16370 )
    loop
      l_buf := dbms_lob.substr( p_src, 16370, i * 16370 + 1 );
      for j in 1 ..  length( l_buf ) / 2
      loop
        l_buf2 := l_buf2 || zipcrypto_encrypt( substr( l_buf, j * 2 - 1, 2 ) );
      end loop;
      dbms_lob.writeappend( l_rv, length( l_buf2 ) / 2, l_buf2 );
      l_buf2 := null;
    end loop;
    return l_rv;
$IF as_zip.use_winzip_encryption
$THEN
   end if;
$END
$IF as_zip.use_dbms_crypto
$THEN
    l_salt := dbms_crypto.randombytes( l_key_bits / 16 );
$ELSE
    l_salt := utl_raw.substr( sha1( utl_raw.cast_from_binary_integer( dbms_utility.get_time ) ), 1, l_key_bits / 16 );
$END
    for i in 1 .. ceil( l_key_length / 20 )
    loop
$IF as_zip.use_dbms_crypto
$THEN
      l_mac := dbms_crypto.mac( utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) ), dbms_crypto.HMAC_SH1, l_pw );
$ELSE
      l_mac := mac_sha1( utl_raw.concat( l_salt, to_char( i, 'fm0xxxxxxx' ) ), l_pw );
$END
      l_sum := l_mac;
      for j in 1 .. l_cnt - 1
      loop
$IF as_zip.use_dbms_crypto
$THEN
        l_mac := dbms_crypto.mac( l_mac, dbms_crypto.HMAC_SH1, l_pw );
$ELSE
        l_mac := mac_sha1( l_mac, l_pw );
$END
        l_sum := utl_raw.bit_xor( l_mac, l_sum );
      end loop;
      l_keys := utl_raw.concat( l_keys, l_sum );
    end loop;
    l_keys := utl_raw.substr( l_keys, 1, l_key_length );
    l_key := utl_raw.substr( l_keys, 1, l_key_bits / 8 );
$IF as_zip.use_dbms_crypto
$THEN
$ELSE
    aes_encrypt_key( l_key, l_aes_key );
$END
    l_rv := utl_raw.concat( l_salt, utl_raw.substr( l_keys, -2, 2 ) );
--
    for i in 0 .. trunc( ( dbms_lob.getlength( p_src ) - 1 ) / 16 )
    loop
      l_block := dbms_lob.substr( p_src, 16, i * 16 + 1 );
      l_len := utl_raw.length( l_block );
      if l_len < 16
      then
        l_block := utl_raw.concat( l_block, utl_raw.copies( '00', 16 - l_len ) );
      end if;
$IF as_zip.use_dbms_crypto
$THEN
      l_encrypted := dbms_crypto.encrypt( utl_raw.reverse( to_char( i + 1, 'fm' || lpad( 'X', 32, '0' ) ) )
                                        , dbms_crypto.ENCRYPT_AES256 + dbms_crypto.CHAIN_ECB + dbms_crypto.PAD_NONE
                                        , l_key
                                        );
$ELSE
      l_encrypted := aes_encrypt( utl_raw.reverse( to_char( i + 1, 'fm' || lpad( 'X', 32, '0' ) ) )
                                , l_key_bits / 8
                                , l_aes_key
                                );
$END
      dbms_lob.writeappend( l_rv, l_len, utl_raw.bit_xor( l_block, l_encrypted ) );
    end loop;
    --
    dbms_lob.createtemporary( l_tmp, true, c_lob_duration );
    dbms_lob.copy( l_tmp, l_rv, dbms_lob.lobmaxsize, 1, l_key_bits / 16 + 2 + 1 );
$IF as_zip.use_dbms_crypto
$THEN
    l_mac := dbms_crypto.mac( l_tmp, dbms_crypto.HMAC_SH1, utl_raw.substr( l_keys, 1 + l_key_bits / 8, l_key_bits / 8 ) );
$ELSE
    l_mac := mac_sha1( l_tmp, utl_raw.substr( l_keys, 1 + l_key_bits / 8, l_key_bits / 8 ) );
$END
    dbms_lob.freetemporary( l_tmp );
    dbms_lob.writeappend( l_rv, 10, l_mac );
    return l_rv;
  end;
--
  procedure add1file
    ( p_zipped_blob in out nocopy blob
    , p_name      varchar2 character set any_cs
    , p_content   blob
    , p_password  varchar2 := null
    , p_date      date     := null
    , p_zipcrypto boolean  := null
    )
  is
    l_now date;
    l_tmp blob;
    l_blob blob;
    l_len integer;
    l_clen integer;
    l_crc32 raw(4) := hextoraw( '00000000' );
    l_compressed boolean := false;
    l_name raw(32767);
    l_encrypted boolean;
    l_extra raw(12);
  begin
    l_now := coalesce( p_date, current_date );
    l_len := nvl( dbms_lob.getlength( p_content ), 0 );
    if l_len > 0
    then
      l_tmp := utl_compress.lz_compress( p_content );
      l_clen := dbms_lob.getlength( l_tmp ) - 18;
      l_compressed := l_clen < l_len;
      l_crc32 := dbms_lob.substr( l_tmp, 4, l_clen + 11 );
    end if;
    if l_compressed
    then
      dbms_lob.createtemporary( l_blob, true, c_lob_duration );
      dbms_lob.copy( l_blob, l_tmp, l_clen, 1, 11 );
    elsif not l_compressed
    then
      l_clen := l_len;
      l_blob := p_content;
    end if;
    if p_zipped_blob is null
    then
      dbms_lob.createtemporary( p_zipped_blob, true, c_lob_duration );
    end if;
    if p_password is not null and l_len > 0
    then
      l_encrypted := true;
      l_blob := encrypt( p_password, l_blob, l_crc32, p_zipcrypto );
      l_clen := dbms_lob.getlength( l_blob );
$IF as_zip.use_winzip_encryption
$THEN
      if not nvl( p_zipcrypto, false )
      then
        l_crc32 := hextoraw( '00000000' );
        l_extra := hextoraw( '019907000200414503' || case when l_compressed
                                                       then '0800' -- deflate
                                                       else '0000' -- stored
                                                     end
                           );
      end if;
$END
    end if;
    l_name := utl_i18n.string_to_raw( p_name, 'AL32UTF8' );
    dbms_lob.append( p_zipped_blob
                   , utl_raw.concat( c_LOCAL_FILE_HEADER -- Local file header signature
                                   , case when l_encrypted
$IF as_zip.use_winzip_encryption
$THEN
                                       then
                                         case when p_zipcrypto
                                           then
                                             hextoraw( '140001' ) -- version 2.0, encrypted
                                           else
                                             hextoraw( '330001' ) -- version 5.1, encrypted
                                         end
$ELSE
                                       then hextoraw( '140001' ) -- version 2.0, encrypted
$END
                                       else hextoraw( '140000' ) -- version 2.0, not encrypted
                                     end
                                   , case when l_name = utl_i18n.string_to_raw( p_name, 'US8PC437' ) or l_name is null
                                       then hextoraw( '00' )
                                       else hextoraw( '08' ) -- set Language encoding flag (EFS)
                                     end
$IF as_zip.use_winzip_encryption
$THEN
                                   , case when l_encrypted and not nvl( p_zipcrypto, false )
                                       then '6300' -- AE-x encryption marker
                                       else
                                         case when l_compressed
                                           then hextoraw( '0800' ) -- deflate
                                           else hextoraw( '0000' ) -- stored
                                         end
                                     end
$ELSE
                                   , case when l_compressed
                                       then hextoraw( '0800' ) -- deflate
                                       else hextoraw( '0000' ) -- stored
                                      end
$END
                                   , little_endian( to_number( to_char( l_now, 'ss' ) ) / 2
                                                  + to_number( to_char( l_now, 'mi' ) ) * 32
                                                  + to_number( to_char( l_now, 'hh24' ) ) * 2048
                                                  , 2
                                                  ) -- File last modification time
                                   , little_endian( to_number( to_char( l_now, 'dd' ) )
                                                  + to_number( to_char( l_now, 'mm' ) ) * 32
                                                  + ( to_number( to_char( l_now, 'yyyy' ) ) - 1980 ) * 512
                                                  , 2
                                                  ) -- File last modification date
                                   , l_crc32                                                 -- CRC-32
                                   , little_endian( l_clen )                                 -- compressed size
                                   , little_endian( l_len )                                  -- uncompressed size
                                   , little_endian( nvl( utl_raw.length( l_name ), 0 ), 2 )  -- File name length
                                   , little_endian( nvl( utl_raw.length( l_extra ), 0 ), 2 ) -- Extra field length
                                   , utl_raw.concat( l_name                                  -- File name
                                                   , l_extra                                 -- extra
                                                   )
                                   )
                   );
    if l_clen > 0
    then
      dbms_lob.copy( p_zipped_blob, l_blob, l_clen, dbms_lob.getlength( p_zipped_blob ) + 1, 1 );
    end if;
    if dbms_lob.istemporary( l_tmp ) = 1
    then
      dbms_lob.freetemporary( l_tmp );
    end if;
    if dbms_lob.istemporary( l_blob ) = 1
    then
      dbms_lob.freetemporary( l_blob );
    end if;
  end;
  --
  procedure finish_zip(
      p_zipped_blob in out nocopy blob
     ,p_comment varchar2 default null
  ) is
    l_cnt integer := 0;
    l_offs integer;
    l_n pls_integer;
    l_m pls_integer;
    l_buf raw(3999);
    l_compressed_len integer;
    l_offs_dir_header integer;
    l_offs_end_header integer;
    l_comment raw(32767) := utl_raw.cast_to_raw( p_comment );
  begin
    l_offs_dir_header := dbms_lob.getlength( p_zipped_blob );
    l_offs := 1;
    loop
      l_buf := dbms_lob.substr( p_zipped_blob, 30, l_offs );
      exit when c_LOCAL_FILE_HEADER != utl_raw.substr( l_buf, 1, 4 ) or nvl( utl_raw.length( l_buf ), 0 ) < 4;
      l_cnt := l_cnt + 1;
      l_compressed_len := little_endian( l_buf, 19, 4 );
      l_n := little_endian( l_buf, 27, 2 );
      l_m := little_endian( l_buf, 29, 2 );
      dbms_lob.append( p_zipped_blob
                     , utl_raw.concat( c_CENTRAL_FILE_HEADER       -- Central directory file header signature
                                     , c_version
                                     , hextoraw( '03' )            -- Unix
                                     , utl_raw.substr( l_buf, 5 )
                                     , hextoraw( '0000' )          -- File comment length
                                     , hextoraw( '0000' )          -- Disk number where file starts
                                     , hextoraw( '0000' )          -- Internal file attributes =>
                                                                   --     0000 binary file
                                                                   --     0100 (ascii)text file
                                     , case
                                         when l_compressed_len = 0
                                          and dbms_lob.substr( p_zipped_blob
                                                             , 1
                                                             , l_offs + 30 + l_n - 1
                                                             ) in ( hextoraw( '2F' ) -- /
                                                                  , hextoraw( '5C' ) -- \
                                                                  )
                                         then hextoraw( '1000ff41' ) -- a directory/folder
                                         else hextoraw( '0000ff81' ) -- a file
                                       end                         -- External file attributes
/*
  wx                r owner
    rw x              group
        rwx fd p      other
            1000 0001 r--------
          1 1000 0001 r-------x
         10 1000 0001 r------w-
        100 1000 0001 r-----r--
       1000 1000 0001 r----x---
*/
                                     , little_endian( l_offs - 1 ) -- Relative offset of local file header
                                     , dbms_lob.substr( p_zipped_blob
                                                      , l_n
                                                      + l_m
                                                      , l_offs + 30
                                                      )            -- File name + Extra field
                                     )
                     );
      l_offs := l_offs + 30 + l_compressed_len
                            + l_n  -- File name length
                            + l_m; -- Extra field length
    end loop;
    l_offs_end_header := dbms_lob.getlength( p_zipped_blob );
    dbms_lob.append( p_zipped_blob
                   , utl_raw.concat( c_END_OF_CENTRAL_DIRECTORY                                -- End of central directory signature
                                   , hextoraw( '0000' )                                        -- Number of this disk
                                   , hextoraw( '0000' )                                        -- Disk where central directory starts
                                   , little_endian( l_cnt, 2 )                                 -- Number of central directory records on this disk
                                   , little_endian( l_cnt, 2 )                                 -- Total number of central directory records
                                   , little_endian( l_offs_end_header - l_offs_dir_header )    -- Size of central directory
                                   , little_endian( l_offs_dir_header )                        -- Offset of start of central directory, relative to start of archive
                                   , little_endian( nvl( utl_raw.length( l_comment ), 0 ), 2 ) -- ZIP file comment length
                                   , l_comment
                                   )
                   );
  end;
  --
  procedure save_zip
    ( p_zipped_blob blob
    , p_dir varchar2
    , p_filename varchar2
    )
  is
$IF as_zip.use_utl_file
$THEN
    l_fh utl_file.file_type;
    l_sz pls_integer := 32767;
  begin
    l_fh := utl_file.fopen( p_dir, p_filename, 'wb', 32767 );
    if p_zipped_blob is not null
    then
      for i in 0 .. trunc( ( dbms_lob.getlength( p_zipped_blob ) - 1 ) / l_sz )
      loop
        utl_file.put_raw( l_fh, dbms_lob.substr( p_zipped_blob, l_sz, i * l_sz + 1 ), true );
      end loop;
    end if;
    utl_file.fclose( l_fh );
$ELSE
  begin
    raise_application_error( -20024, 'as_zip.save_zip/utl_file not available.' );
$END
  end;
  --
  procedure delete_file
    ( p_zipped_blob in out nocopy blob
    , p_name varchar2 character set any_cs := null
    , p_idx number := null
    , p_encoding varchar2 := null
    )
  is
    l_len integer;
    l_ind integer;
    l_idx integer;
    l_nuo_entries integer;
    l_ln integer;
    l_lm integer;
    l_sz integer;
    l_cd_len integer;
    l_data_len integer;
    l_buf raw(32767);
    l_charset varchar2(3999);
    l_name raw(32767);
    l_utf8_name raw(32767);
    l_cd   blob;
    l_data blob;
    l_info tp_zip_info;
    l_cfh tp_cfh;
  begin
    if p_name is null and p_idx is null
    then
      return;
    end if;
    get_zip_info( p_zipped_blob, l_info, true );
    if nvl( l_info.cnt, 0 ) < 1
    then -- no (zip) file or empty zip file
      return;
    end if;
    --
    if p_encoding is not null
    then
      if nls_charset_id( p_encoding ) is null
      then
        l_cfh.encoding := utl_i18n.map_charset( p_encoding, utl_i18n.GENERIC_CONTEXT, utl_i18n.IANA_TO_ORACLE );
      else
        l_cfh.encoding := p_encoding;
      end if;
    else
      l_cfh.encoding := 'US8PC437';
    end if;
    --
    if p_name is not null
    then
      l_charset := case when isnchar( p_name ) then 'N' end || 'CHAR_CS';
      l_charset := nls_charset_name( nls_charset_id( l_charset ) );
      l_name := utl_raw.convert( utl_i18n.string_to_raw( p_name )
                               , l_cfh.encoding
                               , l_charset
                               );
--      l_name := utl_i18n.string_to_raw( p_name, l_cfh.encoding );
      l_utf8_name := utl_raw.convert( utl_i18n.string_to_raw( p_name )
                                    , 'AL32UTF8'
                                    , l_charset
                                    );
    end if;
    --
    l_ind := l_info.idx_cd;
    l_idx := 1;
    l_nuo_entries := 0;
    l_cd_len := 0;
    l_data_len := 0;
    dbms_lob.createtemporary( l_cd, true, c_lob_duration );
    dbms_lob.createtemporary( l_data, true, c_lob_duration );
    loop
      exit when not parse_central_file_header( p_zipped_blob, l_ind, l_cfh );
      if l_idx = p_idx
         or l_cfh.name1 = case when l_cfh.utf8 then l_utf8_name else l_name end
      then -- skip this file
        null;
      else
        if l_cfh.len > 32767
        then
          raise_application_error( -20016, 'Unhandled CD entry' );
        end if;
        l_buf := dbms_lob.substr( p_zipped_blob, 30, l_cfh.offset + 1 );
        l_ln := little_endian( l_buf, 27, 2 );
        l_lm := little_endian( l_buf, 29, 2 );
        l_sz := 30 + l_ln + l_lm + l_cfh.compressed_len;
        if bitand( to_number( utl_raw.substr( l_buf, 7, 1 ), 'XX' ), 8 ) > 0
        then
          l_buf := dbms_lob.substr( p_zipped_blob, 30, l_cfh.offset + 1 + l_sz );
          if utl_raw.substr( l_buf, 1, 4 ) = c_DATA_DESCRIPTOR -- optional signature
          then
            l_sz := l_sz + 4;
            l_buf := utl_raw.substr( l_buf, 5 );
          end if;
          if utl_raw.substr( l_buf, 13, 4 ) in ( c_LOCAL_FILE_HEADER, c_CENTRAL_FILE_HEADER )
          then
            l_sz := l_sz + 12;
          elsif utl_raw.substr( l_buf, 21, 4 ) in ( c_LOCAL_FILE_HEADER, c_CENTRAL_FILE_HEADER )
          then  -- zip64 sizes
            l_sz := l_sz + 20;
          else
            raise_application_error( -20017, 'Error parsing the zipfile' );
          end if;
        end if;
        --
        l_nuo_entries := l_nuo_entries + 1;
        dbms_lob.copy( l_data, p_zipped_blob, l_sz, l_data_len + 1, l_cfh.offset + 1 );
        l_buf := dbms_lob.substr( p_zipped_blob, l_cfh.len, l_ind );
        if utl_raw.substr( l_buf, 43, 4 ) = hextoraw( 'FFFFFFFF' )
        then
          l_buf := utl_raw.overlay( little_endian( l_data_len, 8 ), l_buf, l_cfh.zip64_offset, 8 );
        else
          l_buf := utl_raw.overlay( little_endian( l_data_len ), l_buf, 43, 4 );
        end if;
        dbms_lob.writeappend( l_cd, utl_raw.length( l_buf ), l_buf );
        --
        l_data_len := l_data_len + l_sz;
        l_cd_len := l_cd_len + l_cfh.len;
      end if;
      l_ind := l_ind + l_cfh.len;
      l_idx := l_idx + 1;
    end loop;
    --
    if l_nuo_entries = l_info.cnt
    then
      dbms_lob.freetemporary( l_data );
      dbms_lob.freetemporary( l_cd );
      return;
    end if;
    --
    dbms_lob.trim( p_zipped_blob, 0 );
    if l_nuo_entries > 0
    then
      dbms_lob.append( p_zipped_blob, l_data );
      dbms_lob.append( p_zipped_blob, l_cd );
    end if;
    write_eocd( p_zipped_blob
              , l_info.zip64
              , l_nuo_entries
              , l_cd_len
              , l_data_len
              , l_info
              );
    dbms_lob.freetemporary( l_data );
    dbms_lob.freetemporary( l_cd );
  end;
  --
  procedure add_file
    ( p_zipped_blob in out nocopy blob
    , p_name      varchar2 character set any_cs
    , p_content   blob
    , p_comment   varchar2 character set any_cs := null
    , p_password  varchar2 := null
    , p_date      date     := null
    , p_zipcrypto boolean  := null
    )
  is
    l_offs_lfh  integer;
    l_offs_cd   integer;
    l_len_cd    integer;
    l_compressed_len integer;
    l_n pls_integer;
    l_m pls_integer;
    l_k pls_integer := 0;
    l_buf raw(32767);
    l_cd blob;
    l_data blob;
    l_comment raw(32767);
    l_info tp_zip_info;
  begin
    if p_zipped_blob is null
    then
      p_zipped_blob := hextoraw( '504B0506000000000000000000000000000000000000' );
    end if;
    get_zip_info( p_zipped_blob, l_info, true );
    l_offs_lfh := l_info.idx_cd - 1;
    --
    if l_info.idx_cd >= 4294967295 -- FFFFFFFF
    then
      raise_application_error( -20020, 'Zip64 not yet handled' );
    end if;
    dbms_lob.createtemporary( l_cd, true, c_lob_duration );
    dbms_lob.copy( l_cd, p_zipped_blob, dbms_lob.lobmaxsize, 1, l_info.idx_cd );
    dbms_lob.trim( p_zipped_blob, l_info.idx_cd - 1 );
    add1file( l_data, p_name, p_content, p_password, p_date, p_zipcrypto );
    dbms_lob.append( p_zipped_blob, l_data );
    l_offs_cd := l_offs_lfh + dbms_lob.getlength( l_data );
    --
    if l_info.len_cd > 0
    then -- add old Central Directory again
      if l_info.len_cd < 32767
      then
        dbms_lob.writeappend( p_zipped_blob
                            , l_info.len_cd
                            , dbms_lob.substr( l_cd, l_info.len_cd, 1 )
                            );
      else
        dbms_lob.copy( p_zipped_blob
                     , l_cd
                     , l_info.len_cd
                     , l_offs_cd + 1
                     , 1
                     );
      end if;
    end if;
    -- add new entry to Central Directory
    l_buf := dbms_lob.substr( l_data, 32767, 1 );
    l_compressed_len := little_endian( l_buf, 19, 4 );
    l_n := little_endian( l_buf, 27, 2 );
    l_m := little_endian( l_buf, 29, 2 );
    if p_comment is not null
    then
      begin
        l_comment := utl_i18n.string_to_raw( p_comment, 'AL32UTF8' );
        l_k := utl_raw.length( l_comment );
      exception
        when others then
          l_comment := null;
          l_k := 0;
      end;
    end if;
    l_len_cd := l_info.len_cd + 46 + l_n + l_m + l_k;
    dbms_lob.writeappend
      ( p_zipped_blob
      , 46
      , utl_raw.concat( c_CENTRAL_FILE_HEADER       -- Central directory file header signature
                      , c_version
                      , hextoraw( '03' )            -- Unix
                      , utl_raw.substr( l_buf, 5, 26 )
                      , little_endian( l_k, 2 )     -- File comment length
                      , hextoraw( '0000' )          -- Disk number where file starts
                      , hextoraw( '0000' )          -- Internal file attributes =>
                                                    --     0000 binary file
                                                    --     0100 (ascii)text file
                      , case when l_compressed_len = 0
                              and substr( p_name, -1 ) in ( '/', '\' )
                          then hextoraw( '1000ff41' ) -- a directory/folder
                          else hextoraw( '0000ff81' ) -- a file
                        end                           -- External file attributes
                      , little_endian( l_offs_lfh )   -- Relative offset of local file header
                      )
      );
    if l_n + l_m + l_k < 32767
    then
      dbms_lob.writeappend( p_zipped_blob
                          , l_n + l_m + l_k
                          , utl_raw.concat( utl_raw.substr( l_buf, 31, l_n + l_m )  -- File name + Extra field
                                          , l_comment
                                          )
                          );
    else
      dbms_lob.copy( p_zipped_blob
                   , l_data
                   , l_n + l_m
                   , l_offs_cd + l_info.len_cd + 46 + 1
                   , 31
                   );
      if l_k > 0
      then
        dbms_lob.writeappend( p_zipped_blob, l_k, l_comment );
      end if;
    end if;
    --
    write_eocd( p_zipped_blob
              , l_info.zip64
              , l_info.cnt + 1
              , l_len_cd
              , l_offs_cd
              , l_info
              );
    --
    dbms_lob.freetemporary( l_data );
    dbms_lob.freetemporary( l_cd );
  end;
  --
  function get_count( p_zipped_blob blob )
  return integer
  is
    l_info tp_zip_info;
  begin
    get_zip_info( p_zipped_blob, l_info );
    return nvl( l_info.cnt, 0 );
  end;
--
  function get_comment( p_zipped_blob blob )
  return clob
  is
    l_info tp_zip_info;
  begin
    get_zip_info( p_zipped_blob, l_info, true );
    return get_64k_raw( l_info.comment1
                      , l_info.comment2
                      , l_info.comment3
                      );
  end;
--
  procedure set_comment
    ( p_zipped_blob in out nocopy blob
    , p_comment varchar2 character set any_cs := null
    )
  is
    l_info tp_zip_info;
    l_len pls_integer;
    l_comment raw(32767);
  begin
    if p_zipped_blob is null
    then
      p_zipped_blob := hextoraw( '504B0506000000000000000000000000000000000000' );
    end if;
    get_zip_info( p_zipped_blob, l_info );
    if p_comment is null
    then
      l_len := 0;
    else
      l_comment := utl_i18n.string_to_raw( p_comment, 'AL32UTF8' );
      l_len := utl_raw.length( l_comment );
    end if;
    dbms_lob.trim( p_zipped_blob, l_info.idx_eocd + 19 );
    dbms_lob.writeappend( p_zipped_blob
                        , l_len + 2
                        , utl_raw.concat( little_endian( l_len, 2 ), l_comment )
                        );
  end;
  --
  function get_file_info
    ( p_zipped_blob blob
    , p_file_info in out file_info
    , p_name varchar2 character set any_cs := null
    , p_idx number := null
    , p_encoding varchar2 := null
    )
  return boolean
  is
    l_cfh tp_cfh;
  begin
    p_file_info := null;
    p_file_info.found := get_central_file_header( p_zipped_blob
                                                , p_name
                                                , p_idx
                                                , p_encoding
                                                , l_cfh
                                                );
    if p_file_info.found
    then
      p_file_info.found := true;
      p_file_info.is_encrypted := l_cfh.encrypted;
      p_file_info.is_directory := l_cfh.original_len = 0
                              and utl_raw.substr( l_cfh.external_file_attr, 1, 2 ) = '1000';
      p_file_info.idx  := l_cfh.idx;
      p_file_info.len  := l_cfh.original_len;
      p_file_info.clen := l_cfh.compressed_len;
      p_file_info.name := get_64k_raw( l_cfh.name1
                                     , l_cfh.name2
                                     , l_cfh.name3
                                     , case when l_cfh.utf8 then 'AL32UTF8' else l_cfh.encoding end
                                     );
      p_file_info.comment := get_64k_raw( l_cfh.comment1
                                        , l_cfh.comment2
                                        , l_cfh.comment3
                                        , case when l_cfh.utf8 then 'AL32UTF8' end
                                        );
      p_file_info.nname := utl_i18n.raw_to_nchar( l_cfh.name1
                                                , case when l_cfh.utf8 then 'AL32UTF8' else l_cfh.encoding end
                                                );
    end if;
    --
    return p_file_info.found;
  end;
--
  function get_file_info
    ( p_zipped_blob blob
    , p_name varchar2 character set any_cs := null
    , p_idx number := null
    , p_encoding varchar2 := null
    )
  return file_info
  is
    l_dummy boolean;
    l_file_info file_info;
  begin
    l_dummy := get_file_info( p_zipped_blob
                            , l_file_info
                            , p_name
                            , p_idx
                            , p_encoding
                            );
    return l_file_info;
  end;
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
    )
  is
    l_c   integer;
    l_csv clob;
    l_csv_blob blob;
    l_col_cnt integer;
    l_desc_tab dbms_sql.desc_tab2;
    v_tab dbms_sql.varchar2_table;
    c_tab dbms_sql.clob_table;
    l_first pls_integer;
    l_r integer;
    l_cnt pls_integer;
    c_bulk_size constant pls_integer   := nvl( p_bulk_size, 200 );
    c_separator constant varchar2(100) := nvl( substr( p_separator, 1, 100 ), ',' );
    c_newline   constant varchar2(10)  := nvl( p_newline, chr(13) || chr(10) );
    l_last_col pls_integer;
    l_dest_offset integer := 1;
    l_src_offset  integer := 1;
    l_context     integer := dbms_lob.default_lang_ctx;
    l_warning     integer;
    l_csid        integer := nls_charset_id( coalesce( p_encoding, 'CHAR_CS' ) );
    --
    procedure append( p_val varchar2, p_sep boolean )
    is
    begin
      if p_enclosed_by is null
      then
        l_csv := l_csv || ( p_val || case when p_sep then c_separator else c_newline end );
      else
        l_csv := l_csv || (  p_enclosed_by
                          || replace( p_val, p_enclosed_by, p_enclosed_by || p_enclosed_by )
                          || p_enclosed_by
                          || case when p_sep then c_separator else c_newline end
                          );
      end if;
    end;
    --
    procedure append_clob( p_val clob, p_sep boolean )
    is
    begin
      if p_enclosed_by is null
      then
        l_csv := l_csv || ( p_val || case when p_sep then c_separator else c_newline end );
      else
        l_csv := l_csv || (  p_enclosed_by
                          || replace( p_val, p_enclosed_by, p_enclosed_by || p_enclosed_by )
                          || p_enclosed_by
                          || case when p_sep then c_separator else c_newline end
                          );
      end if;
    end;
  begin
    l_c := dbms_sql.to_cursor_number( p_cursor );
    dbms_lob.createtemporary( l_csv, true, c_lob_duration );
    dbms_sql.describe_columns2( l_c, l_col_cnt, l_desc_tab );
    for c in 1 .. l_col_cnt
    loop
      if l_desc_tab( c ).col_type in ( 2, 100, 101
                                     , 12, 180, 181, 231
                                     , 1, 9, 96
                                     , 112
                                     , 182, 183
                                     )
      then
        l_last_col := c;
      end if;
    end loop;
    for c in 1 .. l_col_cnt
    loop
      if (   p_column_headers
         and l_desc_tab( c ).col_type in ( 2   -- number
                                         , 100 -- bfloat
                                         , 101 -- bdouble
                                         , 12  -- date
                                         , 180 -- timestamp
                                         , 181 -- timestamp with timezone
                                         , 231 -- timestamp with local timezone
                                         , 1   -- varchar
                                         , 9   -- varchar2
                                         , 96  -- char
--                                         , 8   -- long
                                         , 112 -- clob
                                         , 182 -- interval year to month
                                         , 183 -- interval day to second
                                         )
         )
      then
        append( l_desc_tab( c ).col_name, c < l_last_col );
      end if;
      case
        when l_desc_tab( c ).col_type in ( 2, 100, 101
                                         , 12, 180, 181, 231
                                         , 1, 9, 96
                                         , 182, 183
                                         )
        then
          dbms_sql.define_array( l_c, c, v_tab, c_bulk_size, 1 );
        when l_desc_tab( c ).col_type in ( 112 )
        then
          dbms_sql.define_array( l_c, c, c_tab, c_bulk_size, 1 );
        else
          null;
      end case;
    end loop;
    --
    l_cnt := 0;
    loop
      l_r := dbms_sql.fetch_rows( l_c );
      if l_r > 0
      then
        l_cnt := l_cnt + l_r;
        for c in 1 .. l_col_cnt
        loop
          case
            when l_desc_tab( c ).col_type in ( 2, 100, 101
                                             , 12, 180, 181, 231
                                             , 1, 9, 96
                                             , 182, 183
                                             )
            then
              dbms_sql.column_value( l_c, c, v_tab );
              l_first := v_tab.first;
              for i in 0 .. l_r - 1
              loop
                append( v_tab( i + l_first ), c < l_last_col );
              end loop;
              v_tab.delete;
            when l_desc_tab( c ).col_type in ( 8, 112 )
            then
              dbms_sql.column_value( l_c, c, c_tab );
              l_first := c_tab.first;
              for i in 0 .. l_r - 1
              loop
                append_clob( c_tab( i + l_first ), c < l_last_col );
              end loop;
              v_tab.delete;
            else
              null;
          end case;
        end loop;
      end if;
      exit when l_r != c_bulk_size;
    end loop;
    dbms_sql.close_cursor( l_c );
    --
    dbms_lob.createtemporary( l_csv_blob, true, c_lob_duration );
    dbms_lob.converttoblob( l_csv_blob, l_csv, dbms_lob.lobmaxsize, l_dest_offset, l_src_offset, l_csid, l_context, l_warning );

    add_file
      ( p_zipped_blob
      , p_name
      , l_csv_blob
      , p_comment
      , p_password
      , p_date
      , p_zipcrypto
      );
    --
    dbms_lob.freetemporary( l_csv );
  exception
    when value_error
    then
      if dbms_sql.is_open( l_c )
      then
        dbms_sql.close_cursor( l_c );
      end if;
      if dbms_lob.istemporary( l_csv ) = 1
      then
        dbms_lob.freetemporary( l_csv );
      end if;
      if dbms_lob.istemporary( l_csv_blob ) = 1
      then
        dbms_lob.freetemporary( l_csv_blob );
      end if;
      raise;
  end add_csv;
--
end;
/

declare
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
  as_zip.finish_zip( l_zip, 'Zipfile containing one file with unpressed size of ' || dbms_lob.getlength( l_txt_blob ) || '  bytes' );
  --
  dbms_lob.freetemporary( l_txt );
  dbms_lob.freetemporary( l_txt_blob );
  --
  as_zip.save_zip( l_zip, 'VAGRANT', 'zip2.zip' );
  dbms_lob.freetemporary( l_zip );
end;
/
