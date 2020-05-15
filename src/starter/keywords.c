/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -m 10 -C -G -D -t  */
/* Computed positions: -k'2-3,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif


/*
 * Copyright (C) 2005 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>

#define IN_GPERF_GENERATED_FILE
#include "keywords.h"

struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 144
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 10
#define MAX_HASH_VALUE 261
/* maximum key range = 252, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (register const char *str, register size_t len)
{
  static const unsigned short asso_values[] =
    {
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262,  11,
       76, 262, 262, 262,   5, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262,  83, 262,  20,   2,  78,
       59,   4,   7,   0, 109,   0, 262, 120,  57,  31,
       31,  67,  52,   0,  11,   0,  16, 123,   1,   0,
      262,   1,   0, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262, 262, 262, 262, 262,
      262, 262, 262, 262, 262, 262
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const struct kw_entry wordlist[] =
  {
    {"pfs",               KW_PFS_DEPRECATED},
    {"rightgroups",       KW_RIGHTGROUPS},
    {"rightsigkey",       KW_RIGHTSIGKEY},
    {"aggressive",        KW_AGGRESSIVE},
    {"keyingtries",       KW_KEYINGTRIES},
    {"lifebytes",         KW_LIFEBYTES},
    {"lifetime",          KW_KEYLIFE},
    {"right",             KW_RIGHT},
    {"leftsigkey",        KW_LEFTSIGKEY},
    {"keylife",           KW_KEYLIFE},
    {"leftrsasigkey",     KW_LEFTSIGKEY},
    {"rightrsasigkey",    KW_RIGHTSIGKEY},
    {"rightsubnet",       KW_RIGHTSUBNET},
    {"rightikeport",      KW_RIGHTIKEPORT},
    {"rightsendcert",     KW_RIGHTSENDCERT},
    {"leftcertpolicy",    KW_LEFTCERTPOLICY},
    {"left",              KW_LEFT},
    {"leftgroups",        KW_LEFTGROUPS},
    {"rightallowany",     KW_RIGHTALLOWANY},
    {"lifepackets",       KW_LIFEPACKETS},
    {"leftcert",          KW_LEFTCERT},
    {"certuribase",       KW_CERTURIBASE},
    {"keep_alive",        KW_SETUP_DEPRECATED},
    {"leftsendcert",      KW_LEFTSENDCERT},
    {"uniqueids",         KW_UNIQUEIDS},
    {"unique",            KW_UNIQUE},
    {"rightsubnetwithin", KW_RIGHTSUBNET},
    {"leftdns",           KW_LEFTDNS},
    {"virtual_private",   KW_SETUP_DEPRECATED},
    {"leftprotoport",     KW_LEFTPROTOPORT},
    {"leftca",            KW_LEFTCA},
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
    {"type",              KW_TYPE},
    {"inactivity",        KW_INACTIVITY},
    {"interfaces",        KW_SETUP_DEPRECATED},
    {"rightsourceip",     KW_RIGHTSOURCEIP},
    {"rightid",           KW_RIGHTID},
    {"rightdns",          KW_RIGHTDNS},
    {"reqid",             KW_REQID},
    {"certuribase",       KW_CERTURIBASE},
    {"leftnexthop",       KW_LEFT_DEPRECATED},
    {"replay_window",     KW_REPLAY_WINDOW},
    {"leftprotoport",     KW_LEFTPROTOPORT},
    {"compress",          KW_COMPRESS},
    {"mobike",	           KW_MOBIKE},
    {"me_peerid",         KW_ME_PEERID},
    {"interfaces",        KW_SETUP_DEPRECATED},
    {"virtual_private",   KW_SETUP_DEPRECATED},
    {"lefthostaccess",    KW_LEFTHOSTACCESS},
    {"leftca",            KW_LEFTCA},
    {"rightfirewall",     KW_RIGHTFIREWALL},
    {"rightprotoport",    KW_RIGHTPROTOPORT},
    {"inactivity",        KW_INACTIVITY},
    {"leftfirewall",      KW_LEFTFIREWALL},
    {"esp",               KW_ESP},
    {"rightnexthop",      KW_RIGHT_DEPRECATED},
    {"forceencaps",       KW_FORCEENCAPS},
    {"leftallowany",      KW_LEFTALLOWANY},
    {"crluri",            KW_CRLURI},
    {"leftupdown",        KW_LEFTUPDOWN},
    {"mark_in",           KW_MARK_IN},
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
    {"force_keepalive",   KW_SETUP_DEPRECATED},
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
    {"marginbytes",       KW_MARGINBYTES},
    {"crluri",            KW_CRLURI},
    {"marginpackets",     KW_MARGINPACKETS},
    {"margintime",        KW_REKEYMARGIN},
    {"rightfirewall",     KW_RIGHTFIREWALL},
    {"leftnexthop",       KW_LEFT_DEPRECATED},
    {"fragmentation",     KW_FRAGMENTATION},
    {"pfsgroup",          KW_PFS_DEPRECATED},
    {"crluri1",           KW_CRLURI},
    {"no_reauth_passive", KW_NO_REAUTH_PASSIVE},
    {"rightcertpolicy",   KW_RIGHTCERTPOLICY},
    {"hidetos",           KW_SETUP_DEPRECATED},
    {"keyexchange",       KW_KEYEXCHANGE},
    {"leftsourceip",      KW_LEFTSOURCEIP},
    {"ocspuri",           KW_OCSPURI},
    {"leftid",            KW_LEFTID},
    {"eap",               KW_CONN_DEPRECATED},
    {"installpolicy",     KW_INSTALLPOLICY},
    {"also",              KW_ALSO},
    {"rightcert",         KW_RIGHTCERT},
    {"rightauth",         KW_RIGHTAUTH},
    {"mediation",         KW_MEDIATION},
    {"rightca",           KW_RIGHTCA},
    {"klipsdebug",        KW_SETUP_DEPRECATED},
    {"ldapbase",          KW_CA_DEPRECATED},
    {"overridemtu",       KW_SETUP_DEPRECATED},
    {"sha256_96",         KW_SHA256_96},
    {"ocspuri1",          KW_OCSPURI},
    {"dpdtimeout",        KW_DPDTIMEOUT},
    {"aaa_identity",      KW_AAA_IDENTITY},
    {"ike",               KW_IKE},
    {"mark_out",          KW_MARK_OUT},
    {"dumpdir",           KW_SETUP_DEPRECATED},
    {"rekey",             KW_REKEY},
    {"rightid2",          KW_RIGHTID2},
    {"crluri1",           KW_CRLURI},
    {"rightgroups2",      KW_RIGHTGROUPS2},
    {"ikelifetime",       KW_IKELIFETIME},
    {"leftsubnet",        KW_LEFTSUBNET},
    {"rightupdown",       KW_RIGHTUPDOWN},
    {"authby",            KW_AUTHBY},
    {"leftcert2",         KW_LEFTCERT2},
    {"nat_traversal",     KW_SETUP_DEPRECATED},
    {"charondebug",       KW_CHARONDEBUG},
    {"dpdaction",         KW_DPDACTION},
    {"xauth_identity",    KW_XAUTH_IDENTITY},
    {"ah",                KW_AH},
    {"leftsubnetwithin",  KW_LEFTSUBNET},
    {"modeconfig",        KW_MODECONFIG},
    {"ldaphost",          KW_CA_DEPRECATED},
    {"leftikeport",       KW_LEFTIKEPORT},
    {"crlcheckinterval",  KW_SETUP_DEPRECATED},
    {"dpddelay",          KW_DPDDELAY},
    {"cacert",            KW_CACERT},
    {"leftgroups2",       KW_LEFTGROUPS2},
    {"rightauth2",        KW_RIGHTAUTH2},
    {"tfc",               KW_TFC},
    {"postpluto",         KW_SETUP_DEPRECATED},
    {"rekeymargin",       KW_REKEYMARGIN},
    {"leftca2",           KW_LEFTCA2},
    {"nat_traversal",     KW_SETUP_DEPRECATED},
    {"mediation",         KW_MEDIATION},
    {"mark_out",          KW_MARK_OUT},
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
    {"klipsdebug",        KW_SETUP_DEPRECATED},
    {"eap",               KW_CONN_DEPRECATED},
    {"also",              KW_ALSO},
    {"rekey",             KW_REKEY},
    {"ike",               KW_IKE},
    {"hidetos",           KW_SETUP_DEPRECATED},
    {"pfsgroup",          KW_PFS_DEPRECATED},
    {"leftid",            KW_LEFTID},
    {"cacert",            KW_CACERT},
    {"rightauth",         KW_RIGHTAUTH},
    {"overridemtu",       KW_SETUP_DEPRECATED},
    {"rekeyfuzz",         KW_REKEYFUZZ},
    {"leftsourceip",      KW_LEFTSOURCEIP},
    {"packetdefault",     KW_SETUP_DEPRECATED},
    {"mark",              KW_MARK},
    {"charonstart",       KW_SETUP_DEPRECATED},
    {"plutostderrlog",    KW_SETUP_DEPRECATED},
    {"auto",              KW_AUTO},
    {"fragicmp",          KW_SETUP_DEPRECATED},
    {"closeaction",       KW_CLOSEACTION},
    {"prepluto",          KW_SETUP_DEPRECATED},
    {"leftid2",           KW_LEFTID2},
    {"nocrsend",          KW_SETUP_DEPRECATED},
    {"leftauth",          KW_LEFTAUTH},
    {"reauth",            KW_REAUTH},
    {"plutostart",        KW_SETUP_DEPRECATED},
    {"cachecrls",         KW_CACHECRLS},
    {"xauth",             KW_XAUTH},
    {"crluri2",           KW_CRLURI2},
    {"leftid2",           KW_LEFTID2},
    {"mark",              KW_MARK},
    {"leftikeport",       KW_LEFTIKEPORT},
    {"me_peerid",         KW_ME_PEERID},
    {"leftsubnet",        KW_LEFTSUBNET},
    {"rightca2",          KW_RIGHTCA2},
    {"rightcert2",        KW_RIGHTCERT2},
    {"rightupdown",       KW_RIGHTUPDOWN},
    {"tfc",               KW_TFC},
    {"dpdaction",         KW_DPDACTION},
    {"dpdtimeout",        KW_DPDTIMEOUT},
    {"fragicmp",          KW_SETUP_DEPRECATED},
    {"ldaphost",          KW_CA_DEPRECATED},
    {"charondebug",       KW_CHARONDEBUG},
    {"dumpdir",           KW_SETUP_DEPRECATED},
    {"ocspuri2",          KW_OCSPURI2},
    {"dpddelay",          KW_DPDDELAY},
    {"force_keepalive",   KW_SETUP_DEPRECATED},
    {"leftsubnetwithin",  KW_LEFTSUBNET},
    {"cachecrls",         KW_CACHECRLS},
    {"closeaction",       KW_CLOSEACTION},
    {"charonstart",       KW_SETUP_DEPRECATED},
    {"no_reauth_passive", KW_NO_REAUTH_PASSIVE},
    {"plutostderrlog",    KW_SETUP_DEPRECATED},
    {"rekeymargin",       KW_REKEYMARGIN},
    {"if_id_out",         KW_IF_ID_OUT},
    {"postpluto",         KW_SETUP_DEPRECATED},
    {"modeconfig",        KW_MODECONFIG},
    {"plutostart",        KW_SETUP_DEPRECATED},
    {"auto",              KW_AUTO},
    {"if_id_in",          KW_IF_ID_IN},
    {"prepluto",          KW_SETUP_DEPRECATED},
    {"nocrsend",          KW_SETUP_DEPRECATED},
    {"leftauth2",         KW_LEFTAUTH2},
    {"ah",                KW_AH},
    {"pkcs11proxy",       KW_PKCS11_DEPRECATED},
    {"pkcs11initargs",    KW_PKCS11_DEPRECATED},
    {"pkcs11module",      KW_PKCS11_DEPRECATED},
    {"pkcs11keepstate",   KW_PKCS11_DEPRECATED},
    {"xauth_identity",    KW_XAUTH_IDENTITY},
    {"reauth",            KW_REAUTH},
    {"plutodebug",        KW_SETUP_DEPRECATED},
    {"leftauth",          KW_LEFTAUTH},
    {"xauth",             KW_XAUTH},
    {"ikedscp",           KW_IKEDSCP,}
  };

static const short lookup[] =
  {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
      0,   1,   2,  -1,   3,  -1,   4,   5,  -1,   6,
     -1,   7,   8,   9,  -1,  10,  11,  12,  13,  14,
     15,  16,  17,  -1,  18,  -1,  -1,  -1,  19,  20,
     -1,  21,  22,  23,  24,  25,  -1,  -1,  26,  27,
     28,  29,  -1,  -1,  -1,  -1,  -1,  30,  -1,  31,
     -1,  32,  33,  -1,  34,  35,  36,  37,  38,  39,
     40,  -1,  -1,  41,  42,  43,  44,  45,  46,  47,
     48,  49,  50,  51,  52,  -1,  53,  -1,  54,  -1,
     -1,  55,  56,  57,  58,  59,  60,  -1,  61,  -1,
     62,  -1,  63,  64,  65,  66,  67,  68,  69,  70,
     71,  72,  73,  -1,  74,  -1,  -1,  75,  -1,  76,
     -1,  -1,  77,  -1,  78,  -1,  79,  80,  81,  -1,
     82,  83,  -1,  84,  85,  86,  87,  -1,  88,  89,
     90,  -1,  91,  92,  93,  94,  95,  96,  97,  -1,
     -1,  98,  -1,  99,  -1, 100,  -1,  -1, 101, 102,
    103,  -1, 104,  -1, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114,  -1,  -1,  -1, 115,  -1,  -1,
    116, 117,  -1,  -1,  -1, 118, 119, 120,  -1,  -1,
     -1, 121,  -1,  -1, 122,  -1,  -1, 123, 124,  -1,
    125,  -1,  -1, 126,  -1,  -1, 127,  -1,  -1,  -1,
    128,  -1, 129, 130,  -1,  -1, 131,  -1,  -1, 132,
    133, 134,  -1, 135,  -1, 136,  -1,  -1, 137,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 138,  -1,  -1,  -1,  -1,  -1,  -1, 139, 140,
     -1, 141,  -1,  -1,  -1,  -1,  -1, 142,  -1,  -1,
     -1, 143
  };

const struct kw_entry *
in_word_set (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              register const char *s = wordlist[index].name;

              if (*str == *s && !strcmp (str + 1, s + 1))
                return &wordlist[index];
            }
        }
    }
  return 0;
}
