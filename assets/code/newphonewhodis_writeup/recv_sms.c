// local variable allocation has failed, the output may be wrong!
void *__fastcall recv_sms(int a1, int a2, _BYTE *tpdu)
{
  int v3; // r4
  int v4; // r5 OVERLAPPED
  int v6; // r7 OVERLAPPED
  int v8; // r9 OVERLAPPED
  int v10; // r11
  int v11; // lr
  char *tpdu_ctr; // r7
  int v13; // r11
  smsdata *v14; // r0
  smsdata *userbuf; // r5
  unsigned int data_offset; // r6
  unsigned int addr_length; // r4
  char *tpdu_noprot; // r8
  int v19; // r10
  unsigned int v20; // r3
  int v21; // r3
  char *v22; // r6
  size_t addr_len; // r0
  int v24; // r0
  size_t v25; // r2
  int v26; // r4
  unsigned int v27; // r0
  size_t v28; // r2
  void *result; // r0
  unsigned int nparts; // r10
  int refnum; // r7
  char seqnum; // r9
  void **v33; // r4
  sms_parts *v34; // r6
  sms_parts *v35; // r0
  char **v36; // r4
  void **v37; // r3
  sms_parts *v38; // r5
  sms_parts *v39; // r9
  sms_parts *v40; // r7
  sms_parts *v41; // r3
  unsigned __int8 v42; // r2
  int v43; // r4
  int i; // r3
  int v45; // r3
  char *v46; // r3
  sms_schifo *v47; // r4
  sms_schifo *v48; // r6
  size_t v49; // r2
  unsigned int v50; // r3
  int v51; // r0
  __int64 v52; // kr00_8
  sms_schifo *v53; // r0
  int v54; // r3
  unsigned int v55; // r0
  __int64 v56; // kr08_8
  _DWORD *v57; // r3
  char address[8]; // [sp+1Ch] [bp-20Ch]
  __int64 v59; // [sp+24h] [bp-204h]
  char payload[464]; // [sp+34h] [bp-1F4h]
  int v61; // [sp+204h] [bp-24h]
  __int64 v62; // [sp+208h] [bp-20h]
  __int64 v63; // [sp+210h] [bp-18h]
  __int64 v64; // [sp+218h] [bp-10h]
  int v65; // [sp+220h] [bp-8h]
  int v66; // [sp+224h] [bp-4h]

  v61 = v3;
  v62 = *&v4;
  v63 = *&v6;
  tpdu_ctr = tpdu;
  v64 = *&v8;
  v65 = v10;
  v66 = v11;
  v13 = a1;
  v14 = talloc_zero(a1, 192, 114872);
  userbuf = v14;
  if ( *tpdu_ctr & 3 )
    return talloc_free(userbuf, 114932);
  v14->ud_hdr_ind = *tpdu_ctr & 0x40;
  data_offset = (tpdu_ctr[1] & 1) + (tpdu_ctr[1] >> 1);
  addr_length = (data_offset + 2);
  if ( addr_length > 0xC )
  {
    puts("SMS Originate Address > 12 bytes ?!?");
    return talloc_free(userbuf, 114932);
  }
  tpdu_noprot = tpdu_ctr + 1;
  v19 = v14->addr;
  *payload = 0LL;
  *&payload[4] = 0LL;
  memcpy(payload, tpdu_ctr + 1, (data_offset + 2));
  v20 = tpdu_ctr[2];
  payload[0] = data_offset + 1;
  v21 = (v20 >> 4) & 7;
  if ( v21 == 1 )
  {
    *userbuf->addr = '+';
  }
  else if ( v21 == 2 )
  {
    *userbuf->addr = '0';
  }
  else
  {
    userbuf->addr[0] = 0;
  }
  v22 = &tpdu_noprot[addr_length];
  addr_len = strlen(userbuf->addr);
  gsm48_decode_bcd_number(addr_len + v19, 21 - addr_len, payload, 1);
  userbuf->p1 = tpdu_noprot[addr_length];
  v24 = tpdu_noprot[addr_length + 1];
  userbuf->encode_type = v24;
  if ( gsm338_get_sms_alphabet(v24) == -1 )
    return talloc_free(userbuf, 114932);
  *userbuf->unk = gsm340_scts(v22 + 2);
  v25 = v22[9];
  userbuf->data_len = v25;
  if ( v25 )
    memcpy(userbuf->encoded_data, v22 + 10, v25);
  v26 = userbuf->ud_hdr_ind;
  if ( !userbuf->ud_hdr_ind )
  {
    puts("Received normal SMS");
    memset(payload, v26, 161u);
    v27 = gsm338_get_sms_alphabet(userbuf->encode_type);
    if ( v27 == 1 )
    {
      gsm_7bit_decode_n_hdr(payload, 160, userbuf->encoded_data, userbuf->data_len, userbuf->ud_hdr_ind);
    }
    else
    {
      if ( !v27 || v27 > 3 )
        puts("Unknown data coding scheme in sms. Copying raw data");
      v28 = userbuf->data_len;
      if ( v28 >= 140 )
        v28 = 140;
      memcpy(payload, userbuf->encoded_data, v28);
    }
    store_sms(userbuf->addr, payload);
    ++*(v13 + 80);
    return talloc_free(userbuf, 115028);
  }
  puts("Received SMS with UDH");
  if ( userbuf->encoded_data[1] )
  {
    printf("Got unknown information element in UDH: 0x%02x\n", userbuf->encoded_data[1]);
    goto FAIL;
  }
  if ( userbuf->encoded_data[0] != 5 )
  {
    puts("Concatenated SMS UDH with length != 5?");
FAIL:
    puts("Received SMS with malformed/unknown UDH. Discarding...");
    result = talloc_free(userbuf, 115284);
    goto LABEL_33;
  }
  if ( userbuf->encoded_data[2] != 3 )
  {
    puts("Concatenated SMS UDH with header length != 3?");
    goto FAIL;
  }
  nparts = userbuf->encoded_data[4];
  if ( nparts > 3 )
  {
    puts("Too many parts");
    goto FAIL;
  }
  refnum = userbuf->encoded_data[3];
  seqnum = userbuf->encoded_data[5];
  v33 = off_35A70;
  v34 = (off_35A70 - 12);
  if ( &off_35A70 != off_35A70 )
  {
    if ( *(off_35A70 + 0xFFFFFFF4) == refnum )
    {
LABEL_57:
      v36 = (v33 - 2);
      goto LABEL_58;
    }
    while ( 1 )
    {
      v33 = v34->next;
      v34 = (v33 - 3);
      if ( &off_35A70 == v33 )
        break;
      if ( *(v33 - 12) == refnum )
        goto LABEL_57;
    }
  }
  v35 = talloc_zero(v13, 20, 115536);
  v35->refnum = refnum;
  v36 = &v35->dword4;
  v35->numpart = nparts;
  v37 = off_35A74;
  v34 = v35;
  v35->dword4 = &v35->dword4;
  off_35A74 = &v35->next;
  v35->dword8 = &v35->dword4;
  v35->next = &off_35A70;
  v35->dword10 = v37;
  *v37 = &v35->next;
LABEL_58:
  result = talloc_zero(v13, 16, 115308);
  *(result + 4) = seqnum;
  v57 = v34->dword8;
  *result = userbuf;
  v34->dword8 = result + 8;
  *(result + 2) = v36;
  *(result + 3) = v57;
  *v57 = result + 8;
LABEL_33:
  v38 = (off_35A70 + 0xFFFFFFF4);
  v39 = (*off_35A70 - 12);
  if ( &off_35A70 != off_35A70 )
  {
    v40 = (v38 + 4);
    v41 = v38->dword4;
    if ( &v38->dword4 == v41 )
      goto LABEL_41;
LABEL_35:
    v42 = 0;
    do
    {
      v41 = *&v41->refnum;
      ++v42;
    }
    while ( v40 != v41 );
    v43 = v42;
    for ( i = v42; ; i = 0 )
    {
      result = printf("CSMS 0x%02x has 0x%02x parts. Current part count: 0x%02x\n", v38->refnum, v38->numpart, i);
      if ( v38->numpart == v43 )
      {
        memset(payload, 0, 460u);
        *address = 0LL;
        v59 = 0LL;
        *(&v59 + 5) = 0LL;
        v46 = v38->dword4;
        v47 = (v46 - 8);
        v48 = (*v46 - 8);
        if ( v40 != v46 )
        {
          do
          {
            v55 = gsm338_get_sms_alphabet(*(v47->scamuff + 2));
            if ( v55 == 1 )
            {
              gsm_7bit_decode_n_hdr(
                &payload[153 * v47->refnum - 153],
                154,
                v47->scamuff + 29,
                *(v47->scamuff + 28),
                *v47->scamuff);
            }
            else
            {
              if ( !v55 || v55 > 3 )
                puts("Unknown data coding scheme in sms. Copying raw data after UDH");
              puts("8 bit encoding");
              v49 = 134;
              v50 = *(v47->scamuff + 28);
              if ( v50 <= 0x8C )
                v49 = v50 - 6;
              memcpy(&payload[134 * v47->refnum - 134], (v47->scamuff + 35), v49);
            }
            strncpy(address, (v47->scamuff + 3), 20u);
            v51 = v47->scamuff;
            v52 = *&v47->dword4;
            *(v52 + 4) = HIDWORD(v52);
            *HIDWORD(v52) = v52;
            v47->dword4 = 1048832;
            v47->dword8 = 2097664;
            talloc_free(v51, 115488);
            v53 = v47;
            v47 = v48;
            talloc_free(v53, 115512);
            v54 = &v48->dword4;
            v48 = (v48->dword4 - 8);
          }
          while ( v40 != v54 );
        }
        store_sms(address, payload);
        v56 = *&v38->next;
        ++*(v13 + 80);
        *(v56 + 4) = HIDWORD(v56);
        *HIDWORD(v56) = v56;
        v38->next = 0x100100;
        v38->dword10 = 0x200200;
        result = talloc_free(v38, 0x1C2B8);
      }
      v38 = v39;
      v45 = &v39->next;
      v39 = (v39->next - 12);
      if ( v45 == 0x35A70 )
        break;
      v41 = v38->dword4;
      v40 = (v38 + 4);
      if ( &v38->dword4 != v41 )
        goto LABEL_35;
LABEL_41:
      v43 = 0;
    }
  }
  return result;
}