
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.4.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 25 "ircd_parser.y"


#define YY_NO_UNPUT
#include <sys/types.h>

#include "stdinc.h"
#include "ircd.h"
#include "tools.h"
#include "list.h"
#include "s_conf.h"
#include "event.h"
#include "s_log.h"
#include "client.h"	/* for UMODE_ALL only */
#include "pcre.h"
#include "irc_string.h"
#include "irc_getaddrinfo.h"
#include "sprintf_irc.h"
#include "memory.h"
#include "modules.h"
#include "s_serv.h" /* for CAP_LL / IsCapable */
#include "s_misc.h" /* for certfp funcs */
#include "hostmask.h"
#include "send.h"
#include "listener.h"
#include "resv.h"
#include "numeric.h"
#include "s_user.h"

#ifdef HAVE_LIBCRYPTO
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#endif

static char *class_name = NULL;
static struct ConfItem *yy_conf = NULL;
static struct AccessItem *yy_aconf = NULL;
static struct MatchItem *yy_match_item = NULL;
static struct ClassItem *yy_class = NULL;
static struct DnsblItem *yy_dconf = NULL;
static char *yy_class_name = NULL;

static dlink_list col_conf_list  = { NULL, NULL, 0 };
static dlink_list hub_conf_list  = { NULL, NULL, 0 };
static dlink_list leaf_conf_list = { NULL, NULL, 0 };
static unsigned int listener_flags = 0;
static unsigned int regex_ban = 0;
static char userbuf[IRCD_BUFSIZE];
static char hostbuf[IRCD_BUFSIZE];
static char reasonbuf[REASONLEN + 1];
static char gecos_name[REALLEN * 4];

extern dlink_list gdeny_items; /* XXX */

static char *resv_reason = NULL;
static char *listener_address = NULL;
static int not_atom = 0;

struct CollectItem {
  dlink_node node;
  char *name;
  char *user;
  char *host;
  char *passwd;
  int  port;
  int  flags;
#ifdef HAVE_LIBCRYPTO
  char *rsa_public_key_file;
  RSA *rsa_public_key;
#endif
};

static void
free_collect_item(struct CollectItem *item)
{
  MyFree(item->name);
  MyFree(item->user);
  MyFree(item->host);
  MyFree(item->passwd);
#ifdef HAVE_LIBCRYPTO
  MyFree(item->rsa_public_key_file);
#endif
  MyFree(item);
}

static void
unhook_hub_leaf_confs(void)
{
  dlink_node *ptr;
  dlink_node *next_ptr;
  struct CollectItem *yy_hconf;
  struct CollectItem *yy_lconf;

  DLINK_FOREACH_SAFE(ptr, next_ptr, hub_conf_list.head)
  {
    yy_hconf = ptr->data;
    dlinkDelete(&yy_hconf->node, &hub_conf_list);
    free_collect_item(yy_hconf);
  }

  DLINK_FOREACH_SAFE(ptr, next_ptr, leaf_conf_list.head)
  {
    yy_lconf = ptr->data;
    dlinkDelete(&yy_lconf->node, &leaf_conf_list);
    free_collect_item(yy_lconf);
  }
}



/* Line 189 of yacc.c  */
#line 184 "y.tab.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ACCEPT_PASSWORD = 258,
     ACTION = 259,
     ADMIN = 260,
     AFTYPE = 261,
     T_ALLOW = 262,
     ANTI_NICK_FLOOD = 263,
     ANTI_SPAM_EXIT_MESSAGE_TIME = 264,
     ANTI_SPAM_CONNECT_NUMERIC = 265,
     AUTOCONN = 266,
     T_BLOCK = 267,
     BURST_AWAY = 268,
     BURST_TOPICWHO = 269,
     BYTES = 270,
     KBYTES = 271,
     MBYTES = 272,
     GBYTES = 273,
     TBYTES = 274,
     CALLER_ID_WAIT = 275,
     CAN_FLOOD = 276,
     CAN_IDLE = 277,
     CHANNEL = 278,
     CIDR_BITLEN_IPV4 = 279,
     CIDR_BITLEN_IPV6 = 280,
     CIPHER_PREFERENCE = 281,
     CLASS = 282,
     CLIENTCERT_HASH = 283,
     CLOAK_KEY1 = 284,
     CLOAK_KEY2 = 285,
     CLOAK_KEY3 = 286,
     COMPRESSED = 287,
     COMPRESSION_LEVEL = 288,
     CONNECT = 289,
     CONNECTFREQ = 290,
     CRYPTLINK = 291,
     CYCLE_ON_HOSTCHANGE = 292,
     DEFAULT_CIPHER_PREFERENCE = 293,
     DEFAULT_FLOODCOUNT = 294,
     DEFAULT_SPLIT_SERVER_COUNT = 295,
     DEFAULT_SPLIT_USER_COUNT = 296,
     DENY = 297,
     DESCRIPTION = 298,
     DIE = 299,
     DISABLE_AUTH = 300,
     DISABLE_FAKE_CHANNELS = 301,
     DISABLE_HIDDEN = 302,
     DISABLE_LOCAL_CHANNELS = 303,
     DISABLE_REMOTE_COMMANDS = 304,
     DNSBL = 305,
     DNSBL_EXEMPT = 306,
     DOT_IN_IP6_ADDR = 307,
     DOTS_IN_IDENT = 308,
     DURATION = 309,
     EGDPOOL_PATH = 310,
     EMAIL = 311,
     ENABLE = 312,
     ENCRYPTED = 313,
     EXCEED_LIMIT = 314,
     EXEMPT = 315,
     FAILED_OPER_NOTICE = 316,
     FAKENAME = 317,
     IRCD_FLAGS = 318,
     FLATTEN_LINKS = 319,
     FFAILED_OPERLOG = 320,
     FKILLLOG = 321,
     FKLINELOG = 322,
     FGLINELOG = 323,
     FIOERRLOG = 324,
     FOPERLOG = 325,
     FOPERSPYLOG = 326,
     FUSERLOG = 327,
     GECOS = 328,
     GENERAL = 329,
     GLINE = 330,
     GLINES = 331,
     GLINE_EXEMPT = 332,
     GLINE_LOG = 333,
     GLINE_TIME = 334,
     GLINE_MIN_CIDR = 335,
     GLINE_MIN_CIDR6 = 336,
     GLOBAL_KILL = 337,
     IRCD_AUTH = 338,
     NEED_IDENT = 339,
     HAVENT_READ_CONF = 340,
     HIDDEN = 341,
     HIDDEN_ADMIN = 342,
     HIDDEN_NAME = 343,
     HIDDEN_OPER = 344,
     HIDE_SERVER_IPS = 345,
     HIDE_SERVERS = 346,
     HIDE_SPOOF_IPS = 347,
     HOST = 348,
     HUB = 349,
     HUB_MASK = 350,
     IDLETIME = 351,
     IGNORE_BOGUS_TS = 352,
     INVISIBLE_ON_CONNECT = 353,
     IP = 354,
     KILL = 355,
     KILL_CHASE_TIME_LIMIT = 356,
     KLINE = 357,
     KLINE_EXEMPT = 358,
     KLINE_REASON = 359,
     KLINE_WITH_REASON = 360,
     KNOCK_DELAY = 361,
     KNOCK_DELAY_CHANNEL = 362,
     LAZYLINK = 363,
     LEAF_MASK = 364,
     LINKS_DELAY = 365,
     LISTEN = 366,
     T_LOG = 367,
     LOGGING = 368,
     LOG_LEVEL = 369,
     MAX_ACCEPT = 370,
     MAX_BANS = 371,
     MAX_CHANS_PER_USER = 372,
     MAX_GLOBAL = 373,
     MAX_IDENT = 374,
     MAX_LOCAL = 375,
     MAX_NICK_CHANGES = 376,
     MAX_NICK_TIME = 377,
     MAX_NUMBER = 378,
     MAX_TARGETS = 379,
     MESSAGE_LOCALE = 380,
     MIN_NONWILDCARD = 381,
     MIN_NONWILDCARD_SIMPLE = 382,
     MODULE = 383,
     MODULES = 384,
     NAME = 385,
     NEED_PASSWORD = 386,
     IS_WEBIRC = 387,
     NETWORK_DESC = 388,
     NETWORK_NAME = 389,
     NICK = 390,
     NICK_CHANGES = 391,
     NO_CREATE_ON_SPLIT = 392,
     NO_JOIN_ON_SPLIT = 393,
     NO_OPER_FLOOD = 394,
     NO_TILDE = 395,
     NOT = 396,
     NUMBER = 397,
     NUMBER_PER_IDENT = 398,
     NUMBER_PER_CIDR = 399,
     NUMBER_PER_IP = 400,
     NUMBER_PER_IP_GLOBAL = 401,
     OPERATOR = 402,
     OPERS_BYPASS_CALLERID = 403,
     OPER_LOG = 404,
     OPER_ONLY_UMODES = 405,
     OPER_PASS_RESV = 406,
     OPER_SPY_T = 407,
     OPER_UMODES = 408,
     JOIN_FLOOD_COUNT = 409,
     JOIN_FLOOD_TIME = 410,
     PACE_WAIT = 411,
     PACE_WAIT_SIMPLE = 412,
     PASSWORD = 413,
     PATH = 414,
     PING_COOKIE = 415,
     PING_TIME = 416,
     PING_WARNING = 417,
     PORT = 418,
     QSTRING = 419,
     QUIET_ON_BAN = 420,
     REASON = 421,
     REDIRPORT = 422,
     REDIRSERV = 423,
     REGEX_T = 424,
     REHASH = 425,
     TREJECT_HOLD_TIME = 426,
     REMOTE = 427,
     REMOTEBAN = 428,
     RESTRICT_CHANNELS = 429,
     RESTRICTED = 430,
     RSA_PRIVATE_KEY_FILE = 431,
     RSA_PUBLIC_KEY_FILE = 432,
     SSL_CERTIFICATE_FILE = 433,
     RESV = 434,
     RESV_EXEMPT = 435,
     SECONDS = 436,
     MINUTES = 437,
     HOURS = 438,
     DAYS = 439,
     WEEKS = 440,
     SENDQ = 441,
     SEND_PASSWORD = 442,
     SERVERHIDE = 443,
     SERVERINFO = 444,
     SERVICES = 445,
     SERVICES_NAME = 446,
     SERVLINK_PATH = 447,
     IRCD_SID = 448,
     TKLINE_EXPIRE_NOTICES = 449,
     T_SHARED = 450,
     T_CLUSTER = 451,
     TYPE = 452,
     SHORT_MOTD = 453,
     SILENT = 454,
     SPOOF = 455,
     SPOOF_NOTICE = 456,
     STATS_E_DISABLED = 457,
     STATS_I_OPER_ONLY = 458,
     STATS_K_OPER_ONLY = 459,
     STATS_O_OPER_ONLY = 460,
     STATS_P_OPER_ONLY = 461,
     TBOOL = 462,
     TMASKED = 463,
     T_REJECT = 464,
     TS_MAX_DELTA = 465,
     TS_WARN_DELTA = 466,
     TWODOTS = 467,
     T_ALL = 468,
     T_BOTS = 469,
     T_SOFTCALLERID = 470,
     T_CALLERID = 471,
     T_CCONN = 472,
     T_CCONN_FULL = 473,
     T_CLIENT_FLOOD = 474,
     T_DEAF = 475,
     T_DEBUG = 476,
     T_DRONE = 477,
     T_EXTERNAL = 478,
     T_FULL = 479,
     T_HIDECHANNELS = 480,
     T_INVISIBLE = 481,
     T_IPV4 = 482,
     T_IPV6 = 483,
     T_LOCOPS = 484,
     T_LOGPATH = 485,
     T_L_CRIT = 486,
     T_L_DEBUG = 487,
     T_L_ERROR = 488,
     T_L_INFO = 489,
     T_L_NOTICE = 490,
     T_L_TRACE = 491,
     T_L_WARN = 492,
     T_MAX_CLIENTS = 493,
     T_NCHANGE = 494,
     T_OPERWALL = 495,
     T_REJ = 496,
     T_SERVNOTICE = 497,
     T_SKILL = 498,
     T_SPY = 499,
     T_SSL = 500,
     T_UMODES = 501,
     T_UNAUTH = 502,
     T_UNRESV = 503,
     T_UNXLINE = 504,
     T_WALLOP = 505,
     THROTTLE_TIME = 506,
     TOPICBURST = 507,
     TRUE_NO_OPER_FLOOD = 508,
     TKLINE = 509,
     TXLINE = 510,
     TRESV = 511,
     UNKLINE = 512,
     USER = 513,
     USE_EGD = 514,
     USE_EXCEPT = 515,
     USE_INVEX = 516,
     HIDE_KILLER = 517,
     USE_REGEX_BANS = 518,
     USE_KNOCK = 519,
     USE_LOGGING = 520,
     USE_WHOIS_ACTUALLY = 521,
     VHOST = 522,
     VHOST6 = 523,
     XLINE = 524,
     WARN = 525,
     WARN_NO_NLINE = 526
   };
#endif
/* Tokens.  */
#define ACCEPT_PASSWORD 258
#define ACTION 259
#define ADMIN 260
#define AFTYPE 261
#define T_ALLOW 262
#define ANTI_NICK_FLOOD 263
#define ANTI_SPAM_EXIT_MESSAGE_TIME 264
#define ANTI_SPAM_CONNECT_NUMERIC 265
#define AUTOCONN 266
#define T_BLOCK 267
#define BURST_AWAY 268
#define BURST_TOPICWHO 269
#define BYTES 270
#define KBYTES 271
#define MBYTES 272
#define GBYTES 273
#define TBYTES 274
#define CALLER_ID_WAIT 275
#define CAN_FLOOD 276
#define CAN_IDLE 277
#define CHANNEL 278
#define CIDR_BITLEN_IPV4 279
#define CIDR_BITLEN_IPV6 280
#define CIPHER_PREFERENCE 281
#define CLASS 282
#define CLIENTCERT_HASH 283
#define CLOAK_KEY1 284
#define CLOAK_KEY2 285
#define CLOAK_KEY3 286
#define COMPRESSED 287
#define COMPRESSION_LEVEL 288
#define CONNECT 289
#define CONNECTFREQ 290
#define CRYPTLINK 291
#define CYCLE_ON_HOSTCHANGE 292
#define DEFAULT_CIPHER_PREFERENCE 293
#define DEFAULT_FLOODCOUNT 294
#define DEFAULT_SPLIT_SERVER_COUNT 295
#define DEFAULT_SPLIT_USER_COUNT 296
#define DENY 297
#define DESCRIPTION 298
#define DIE 299
#define DISABLE_AUTH 300
#define DISABLE_FAKE_CHANNELS 301
#define DISABLE_HIDDEN 302
#define DISABLE_LOCAL_CHANNELS 303
#define DISABLE_REMOTE_COMMANDS 304
#define DNSBL 305
#define DNSBL_EXEMPT 306
#define DOT_IN_IP6_ADDR 307
#define DOTS_IN_IDENT 308
#define DURATION 309
#define EGDPOOL_PATH 310
#define EMAIL 311
#define ENABLE 312
#define ENCRYPTED 313
#define EXCEED_LIMIT 314
#define EXEMPT 315
#define FAILED_OPER_NOTICE 316
#define FAKENAME 317
#define IRCD_FLAGS 318
#define FLATTEN_LINKS 319
#define FFAILED_OPERLOG 320
#define FKILLLOG 321
#define FKLINELOG 322
#define FGLINELOG 323
#define FIOERRLOG 324
#define FOPERLOG 325
#define FOPERSPYLOG 326
#define FUSERLOG 327
#define GECOS 328
#define GENERAL 329
#define GLINE 330
#define GLINES 331
#define GLINE_EXEMPT 332
#define GLINE_LOG 333
#define GLINE_TIME 334
#define GLINE_MIN_CIDR 335
#define GLINE_MIN_CIDR6 336
#define GLOBAL_KILL 337
#define IRCD_AUTH 338
#define NEED_IDENT 339
#define HAVENT_READ_CONF 340
#define HIDDEN 341
#define HIDDEN_ADMIN 342
#define HIDDEN_NAME 343
#define HIDDEN_OPER 344
#define HIDE_SERVER_IPS 345
#define HIDE_SERVERS 346
#define HIDE_SPOOF_IPS 347
#define HOST 348
#define HUB 349
#define HUB_MASK 350
#define IDLETIME 351
#define IGNORE_BOGUS_TS 352
#define INVISIBLE_ON_CONNECT 353
#define IP 354
#define KILL 355
#define KILL_CHASE_TIME_LIMIT 356
#define KLINE 357
#define KLINE_EXEMPT 358
#define KLINE_REASON 359
#define KLINE_WITH_REASON 360
#define KNOCK_DELAY 361
#define KNOCK_DELAY_CHANNEL 362
#define LAZYLINK 363
#define LEAF_MASK 364
#define LINKS_DELAY 365
#define LISTEN 366
#define T_LOG 367
#define LOGGING 368
#define LOG_LEVEL 369
#define MAX_ACCEPT 370
#define MAX_BANS 371
#define MAX_CHANS_PER_USER 372
#define MAX_GLOBAL 373
#define MAX_IDENT 374
#define MAX_LOCAL 375
#define MAX_NICK_CHANGES 376
#define MAX_NICK_TIME 377
#define MAX_NUMBER 378
#define MAX_TARGETS 379
#define MESSAGE_LOCALE 380
#define MIN_NONWILDCARD 381
#define MIN_NONWILDCARD_SIMPLE 382
#define MODULE 383
#define MODULES 384
#define NAME 385
#define NEED_PASSWORD 386
#define IS_WEBIRC 387
#define NETWORK_DESC 388
#define NETWORK_NAME 389
#define NICK 390
#define NICK_CHANGES 391
#define NO_CREATE_ON_SPLIT 392
#define NO_JOIN_ON_SPLIT 393
#define NO_OPER_FLOOD 394
#define NO_TILDE 395
#define NOT 396
#define NUMBER 397
#define NUMBER_PER_IDENT 398
#define NUMBER_PER_CIDR 399
#define NUMBER_PER_IP 400
#define NUMBER_PER_IP_GLOBAL 401
#define OPERATOR 402
#define OPERS_BYPASS_CALLERID 403
#define OPER_LOG 404
#define OPER_ONLY_UMODES 405
#define OPER_PASS_RESV 406
#define OPER_SPY_T 407
#define OPER_UMODES 408
#define JOIN_FLOOD_COUNT 409
#define JOIN_FLOOD_TIME 410
#define PACE_WAIT 411
#define PACE_WAIT_SIMPLE 412
#define PASSWORD 413
#define PATH 414
#define PING_COOKIE 415
#define PING_TIME 416
#define PING_WARNING 417
#define PORT 418
#define QSTRING 419
#define QUIET_ON_BAN 420
#define REASON 421
#define REDIRPORT 422
#define REDIRSERV 423
#define REGEX_T 424
#define REHASH 425
#define TREJECT_HOLD_TIME 426
#define REMOTE 427
#define REMOTEBAN 428
#define RESTRICT_CHANNELS 429
#define RESTRICTED 430
#define RSA_PRIVATE_KEY_FILE 431
#define RSA_PUBLIC_KEY_FILE 432
#define SSL_CERTIFICATE_FILE 433
#define RESV 434
#define RESV_EXEMPT 435
#define SECONDS 436
#define MINUTES 437
#define HOURS 438
#define DAYS 439
#define WEEKS 440
#define SENDQ 441
#define SEND_PASSWORD 442
#define SERVERHIDE 443
#define SERVERINFO 444
#define SERVICES 445
#define SERVICES_NAME 446
#define SERVLINK_PATH 447
#define IRCD_SID 448
#define TKLINE_EXPIRE_NOTICES 449
#define T_SHARED 450
#define T_CLUSTER 451
#define TYPE 452
#define SHORT_MOTD 453
#define SILENT 454
#define SPOOF 455
#define SPOOF_NOTICE 456
#define STATS_E_DISABLED 457
#define STATS_I_OPER_ONLY 458
#define STATS_K_OPER_ONLY 459
#define STATS_O_OPER_ONLY 460
#define STATS_P_OPER_ONLY 461
#define TBOOL 462
#define TMASKED 463
#define T_REJECT 464
#define TS_MAX_DELTA 465
#define TS_WARN_DELTA 466
#define TWODOTS 467
#define T_ALL 468
#define T_BOTS 469
#define T_SOFTCALLERID 470
#define T_CALLERID 471
#define T_CCONN 472
#define T_CCONN_FULL 473
#define T_CLIENT_FLOOD 474
#define T_DEAF 475
#define T_DEBUG 476
#define T_DRONE 477
#define T_EXTERNAL 478
#define T_FULL 479
#define T_HIDECHANNELS 480
#define T_INVISIBLE 481
#define T_IPV4 482
#define T_IPV6 483
#define T_LOCOPS 484
#define T_LOGPATH 485
#define T_L_CRIT 486
#define T_L_DEBUG 487
#define T_L_ERROR 488
#define T_L_INFO 489
#define T_L_NOTICE 490
#define T_L_TRACE 491
#define T_L_WARN 492
#define T_MAX_CLIENTS 493
#define T_NCHANGE 494
#define T_OPERWALL 495
#define T_REJ 496
#define T_SERVNOTICE 497
#define T_SKILL 498
#define T_SPY 499
#define T_SSL 500
#define T_UMODES 501
#define T_UNAUTH 502
#define T_UNRESV 503
#define T_UNXLINE 504
#define T_WALLOP 505
#define THROTTLE_TIME 506
#define TOPICBURST 507
#define TRUE_NO_OPER_FLOOD 508
#define TKLINE 509
#define TXLINE 510
#define TRESV 511
#define UNKLINE 512
#define USER 513
#define USE_EGD 514
#define USE_EXCEPT 515
#define USE_INVEX 516
#define HIDE_KILLER 517
#define USE_REGEX_BANS 518
#define USE_KNOCK 519
#define USE_LOGGING 520
#define USE_WHOIS_ACTUALLY 521
#define VHOST 522
#define VHOST6 523
#define XLINE 524
#define WARN 525
#define WARN_NO_NLINE 526




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 135 "ircd_parser.y"

  int number;
  char *string;



/* Line 214 of yacc.c  */
#line 769 "y.tab.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 264 of yacc.c  */
#line 781 "y.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1506

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  277
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  361
/* YYNRULES -- Number of rules.  */
#define YYNRULES  779
/* YYNRULES -- Number of states.  */
#define YYNSTATES  1576

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   526

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint16 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   276,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,   272,
       2,   275,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   274,     2,   273,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,     9,    11,    13,    15,    17,
      19,    21,    23,    25,    27,    29,    31,    33,    35,    37,
      39,    41,    43,    45,    47,    49,    52,    55,    56,    58,
      61,    65,    69,    73,    77,    81,    82,    84,    87,    91,
      95,    99,   105,   108,   110,   112,   114,   117,   122,   127,
     128,   135,   138,   140,   142,   144,   146,   149,   154,   159,
     164,   170,   173,   175,   177,   179,   181,   183,   185,   187,
     189,   191,   193,   195,   197,   200,   205,   210,   215,   220,
     225,   230,   235,   240,   245,   250,   255,   261,   264,   266,
     268,   270,   272,   275,   280,   285,   290,   296,   299,   301,
     303,   305,   307,   309,   311,   313,   315,   317,   319,   321,
     323,   325,   328,   333,   338,   343,   348,   353,   358,   363,
     368,   373,   378,   383,   388,   393,   398,   403,   408,   413,
     418,   419,   427,   428,   430,   433,   435,   437,   439,   441,
     443,   445,   447,   449,   451,   453,   455,   457,   459,   461,
     463,   465,   467,   469,   471,   473,   475,   477,   479,   481,
     483,   486,   491,   493,   498,   503,   508,   513,   518,   523,
     524,   530,   534,   536,   538,   540,   542,   544,   546,   548,
     550,   552,   554,   556,   558,   560,   562,   564,   566,   568,
     570,   572,   574,   576,   581,   586,   591,   596,   601,   606,
     611,   616,   621,   626,   631,   636,   641,   646,   651,   652,
     658,   662,   664,   665,   669,   670,   673,   675,   677,   679,
     681,   683,   685,   687,   689,   691,   693,   695,   697,   699,
     701,   703,   705,   706,   714,   715,   717,   720,   722,   724,
     726,   728,   730,   732,   734,   736,   738,   740,   742,   744,
     746,   748,   751,   756,   758,   763,   768,   773,   778,   783,
     788,   793,   798,   803,   808,   813,   818,   819,   826,   827,
     833,   837,   839,   841,   843,   846,   848,   850,   852,   854,
     856,   859,   860,   866,   870,   872,   874,   878,   883,   888,
     889,   896,   899,   901,   903,   905,   907,   909,   911,   913,
     915,   917,   919,   921,   923,   925,   927,   929,   931,   933,
     935,   937,   940,   945,   950,   955,   960,   965,   970,   971,
     977,   981,   983,   984,   988,   989,   992,   994,   996,   998,
    1000,  1002,  1004,  1006,  1008,  1010,  1012,  1014,  1016,  1021,
    1026,  1031,  1036,  1041,  1046,  1051,  1056,  1061,  1066,  1071,
    1072,  1079,  1082,  1084,  1086,  1088,  1090,  1093,  1098,  1103,
    1108,  1109,  1116,  1119,  1121,  1123,  1125,  1127,  1130,  1135,
    1140,  1141,  1147,  1151,  1153,  1155,  1157,  1159,  1161,  1163,
    1165,  1167,  1169,  1171,  1173,  1175,  1177,  1179,  1180,  1187,
    1190,  1192,  1194,  1196,  1199,  1204,  1205,  1211,  1215,  1217,
    1219,  1221,  1223,  1225,  1227,  1229,  1231,  1233,  1235,  1237,
    1239,  1240,  1248,  1249,  1251,  1254,  1256,  1258,  1260,  1262,
    1264,  1266,  1268,  1270,  1272,  1274,  1276,  1278,  1280,  1282,
    1284,  1286,  1288,  1290,  1292,  1294,  1297,  1302,  1304,  1309,
    1314,  1319,  1324,  1329,  1334,  1339,  1344,  1345,  1351,  1355,
    1357,  1358,  1362,  1363,  1366,  1368,  1370,  1372,  1374,  1376,
    1378,  1383,  1388,  1393,  1398,  1403,  1408,  1413,  1418,  1423,
    1428,  1429,  1436,  1437,  1443,  1447,  1449,  1451,  1454,  1456,
    1458,  1460,  1462,  1464,  1469,  1474,  1475,  1482,  1485,  1487,
    1489,  1491,  1493,  1498,  1503,  1509,  1512,  1514,  1516,  1518,
    1520,  1525,  1530,  1531,  1538,  1539,  1545,  1549,  1551,  1553,
    1556,  1558,  1560,  1562,  1564,  1566,  1571,  1576,  1582,  1585,
    1587,  1589,  1591,  1593,  1595,  1597,  1599,  1601,  1603,  1605,
    1607,  1609,  1611,  1613,  1615,  1617,  1619,  1621,  1623,  1625,
    1627,  1629,  1631,  1633,  1635,  1637,  1639,  1641,  1643,  1645,
    1647,  1649,  1651,  1653,  1655,  1657,  1659,  1661,  1663,  1665,
    1667,  1669,  1671,  1673,  1675,  1677,  1679,  1681,  1683,  1685,
    1687,  1689,  1691,  1693,  1695,  1697,  1699,  1701,  1703,  1705,
    1707,  1709,  1711,  1716,  1721,  1726,  1731,  1736,  1741,  1746,
    1751,  1756,  1761,  1766,  1771,  1776,  1781,  1786,  1791,  1796,
    1801,  1806,  1811,  1816,  1821,  1826,  1831,  1836,  1841,  1846,
    1851,  1856,  1861,  1866,  1871,  1876,  1881,  1886,  1891,  1896,
    1901,  1906,  1911,  1916,  1921,  1926,  1931,  1936,  1941,  1946,
    1951,  1956,  1961,  1966,  1971,  1976,  1981,  1986,  1991,  1992,
    1998,  2002,  2004,  2006,  2008,  2010,  2012,  2014,  2016,  2018,
    2020,  2022,  2024,  2026,  2028,  2030,  2032,  2034,  2036,  2038,
    2040,  2042,  2044,  2045,  2051,  2055,  2057,  2059,  2061,  2063,
    2065,  2067,  2069,  2071,  2073,  2075,  2077,  2079,  2081,  2083,
    2085,  2087,  2089,  2091,  2093,  2095,  2097,  2102,  2107,  2112,
    2117,  2122,  2123,  2130,  2133,  2135,  2137,  2139,  2141,  2143,
    2145,  2147,  2149,  2154,  2159,  2160,  2166,  2170,  2172,  2174,
    2176,  2181,  2186,  2187,  2193,  2197,  2199,  2201,  2203,  2209,
    2212,  2214,  2216,  2218,  2220,  2222,  2224,  2226,  2228,  2230,
    2232,  2234,  2236,  2238,  2240,  2242,  2244,  2246,  2248,  2250,
    2252,  2254,  2256,  2261,  2266,  2271,  2276,  2281,  2286,  2291,
    2296,  2301,  2306,  2311,  2316,  2321,  2326,  2331,  2336,  2341,
    2346,  2351,  2356,  2362,  2365,  2367,  2369,  2371,  2373,  2375,
    2377,  2379,  2381,  2383,  2388,  2393,  2398,  2403,  2408,  2413
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     278,     0,    -1,    -1,   278,   279,    -1,   310,    -1,   316,
      -1,   331,    -1,   605,    -1,   370,    -1,   389,    -1,   403,
      -1,   296,    -1,   628,    -1,   431,    -1,   438,    -1,   448,
      -1,   457,    -1,   488,    -1,   498,    -1,   504,    -1,   519,
      -1,   589,    -1,   509,    -1,   284,    -1,   289,    -1,     1,
     272,    -1,     1,   273,    -1,    -1,   281,    -1,   142,   280,
      -1,   142,   181,   280,    -1,   142,   182,   280,    -1,   142,
     183,   280,    -1,   142,   184,   280,    -1,   142,   185,   280,
      -1,    -1,   283,    -1,   142,   282,    -1,   142,    15,   282,
      -1,   142,    16,   282,    -1,   142,    17,   282,    -1,   129,
     274,   285,   273,   272,    -1,   285,   286,    -1,   286,    -1,
     287,    -1,   288,    -1,     1,   272,    -1,   128,   275,   164,
     272,    -1,   159,   275,   164,   272,    -1,    -1,    50,   290,
     274,   291,   273,   272,    -1,   291,   292,    -1,   292,    -1,
     293,    -1,   294,    -1,   295,    -1,     1,   272,    -1,   130,
     275,   164,   272,    -1,    54,   275,   281,   272,    -1,   166,
     275,   164,   272,    -1,   189,   274,   297,   273,   272,    -1,
     297,   298,    -1,   298,    -1,   301,    -1,   306,    -1,   309,
      -1,   303,    -1,   304,    -1,   305,    -1,   308,    -1,   300,
      -1,   307,    -1,   302,    -1,   299,    -1,     1,   272,    -1,
     178,   275,   164,   272,    -1,   176,   275,   164,   272,    -1,
     130,   275,   164,   272,    -1,   193,   275,   164,   272,    -1,
      43,   275,   164,   272,    -1,   134,   275,   164,   272,    -1,
     133,   275,   164,   272,    -1,   267,   275,   164,   272,    -1,
     268,   275,   164,   272,    -1,   238,   275,   142,   272,    -1,
      94,   275,   207,   272,    -1,     5,   274,   311,   273,   272,
      -1,   311,   312,    -1,   312,    -1,   313,    -1,   315,    -1,
     314,    -1,     1,   272,    -1,   130,   275,   164,   272,    -1,
      56,   275,   164,   272,    -1,    43,   275,   164,   272,    -1,
     113,   274,   317,   273,   272,    -1,   317,   318,    -1,   318,
      -1,   319,    -1,   320,    -1,   329,    -1,   330,    -1,   321,
      -1,   323,    -1,   325,    -1,   326,    -1,   328,    -1,   324,
      -1,   327,    -1,   322,    -1,     1,   272,    -1,   230,   275,
     164,   272,    -1,   149,   275,   164,   272,    -1,    72,   275,
     164,   272,    -1,    65,   275,   164,   272,    -1,    70,   275,
     164,   272,    -1,    71,   275,   164,   272,    -1,    68,   275,
     164,   272,    -1,    67,   275,   164,   272,    -1,    69,   275,
     164,   272,    -1,    66,   275,   164,   272,    -1,   114,   275,
     231,   272,    -1,   114,   275,   233,   272,    -1,   114,   275,
     237,   272,    -1,   114,   275,   235,   272,    -1,   114,   275,
     236,   272,    -1,   114,   275,   234,   272,    -1,   114,   275,
     232,   272,    -1,   265,   275,   207,   272,    -1,    -1,   147,
     332,   333,   274,   334,   273,   272,    -1,    -1,   337,    -1,
     334,   335,    -1,   335,    -1,   336,    -1,   338,    -1,   340,
      -1,   359,    -1,   360,    -1,   344,    -1,   343,    -1,   348,
      -1,   349,    -1,   351,    -1,   352,    -1,   353,    -1,   354,
      -1,   355,    -1,   350,    -1,   356,    -1,   357,    -1,   358,
      -1,   362,    -1,   341,    -1,   342,    -1,   339,    -1,   361,
      -1,   363,    -1,     1,   272,    -1,   130,   275,   164,   272,
      -1,   164,    -1,   258,   275,   164,   272,    -1,    28,   275,
     164,   272,    -1,   158,   275,   164,   272,    -1,    58,   275,
     207,   272,    -1,   177,   275,   164,   272,    -1,    27,   275,
     164,   272,    -1,    -1,   246,   345,   275,   346,   272,    -1,
     346,   276,   347,    -1,   347,    -1,   214,    -1,   217,    -1,
     218,    -1,   220,    -1,   221,    -1,   224,    -1,   243,    -1,
     239,    -1,   241,    -1,   247,    -1,   244,    -1,   223,    -1,
     240,    -1,   242,    -1,   226,    -1,   250,    -1,   215,    -1,
     216,    -1,   229,    -1,   225,    -1,    82,   275,   207,   272,
      -1,   172,   275,   207,   272,    -1,   173,   275,   207,   272,
      -1,   102,   275,   207,   272,    -1,   269,   275,   207,   272,
      -1,   257,   275,   207,   272,    -1,    75,   275,   207,   272,
      -1,   136,   275,   207,   272,    -1,    44,   275,   207,   272,
      -1,   170,   275,   207,   272,    -1,     5,   275,   207,   272,
      -1,    87,   275,   207,   272,    -1,    89,   275,   207,   272,
      -1,   152,   275,   207,   272,    -1,   240,   275,   207,   272,
      -1,    -1,    63,   364,   275,   365,   272,    -1,   365,   276,
     366,    -1,   366,    -1,    -1,   141,   367,   369,    -1,    -1,
     368,   369,    -1,    82,    -1,   172,    -1,   102,    -1,   257,
      -1,   269,    -1,    75,    -1,    44,    -1,   170,    -1,     5,
      -1,    87,    -1,   136,    -1,   240,    -1,   152,    -1,    89,
      -1,   173,    -1,    58,    -1,    -1,    27,   371,   372,   274,
     373,   273,   272,    -1,    -1,   376,    -1,   373,   374,    -1,
     374,    -1,   375,    -1,   386,    -1,   387,    -1,   377,    -1,
     378,    -1,   388,    -1,   379,    -1,   380,    -1,   381,    -1,
     382,    -1,   383,    -1,   384,    -1,   385,    -1,     1,   272,
      -1,   130,   275,   164,   272,    -1,   164,    -1,   161,   275,
     281,   272,    -1,   162,   275,   281,   272,    -1,   145,   275,
     142,   272,    -1,    35,   275,   281,   272,    -1,   123,   275,
     142,   272,    -1,   118,   275,   142,   272,    -1,   120,   275,
     142,   272,    -1,   119,   275,   142,   272,    -1,   186,   275,
     283,   272,    -1,    24,   275,   142,   272,    -1,    25,   275,
     142,   272,    -1,   144,   275,   142,   272,    -1,    -1,   111,
     390,   274,   395,   273,   272,    -1,    -1,    63,   392,   275,
     393,   272,    -1,   393,   276,   394,    -1,   394,    -1,   245,
      -1,    86,    -1,   395,   396,    -1,   396,    -1,   397,    -1,
     391,    -1,   401,    -1,   402,    -1,     1,   272,    -1,    -1,
     163,   275,   399,   398,   272,    -1,   399,   276,   400,    -1,
     400,    -1,   142,    -1,   142,   212,   142,    -1,    99,   275,
     164,   272,    -1,    93,   275,   164,   272,    -1,    -1,    83,
     404,   274,   405,   273,   272,    -1,   405,   406,    -1,   406,
      -1,   407,    -1,   408,    -1,   411,    -1,   413,    -1,   420,
      -1,   421,    -1,   422,    -1,   424,    -1,   425,    -1,   426,
      -1,   410,    -1,   429,    -1,   427,    -1,   428,    -1,   423,
      -1,   430,    -1,   412,    -1,   409,    -1,     1,   272,    -1,
     258,   275,   164,   272,    -1,   158,   275,   164,   272,    -1,
      28,   275,   164,   272,    -1,   201,   275,   207,   272,    -1,
      27,   275,   164,   272,    -1,    58,   275,   207,   272,    -1,
      -1,    63,   414,   275,   415,   272,    -1,   415,   276,   416,
      -1,   416,    -1,    -1,   141,   417,   419,    -1,    -1,   418,
     419,    -1,   201,    -1,    59,    -1,   103,    -1,    84,    -1,
      21,    -1,    22,    -1,   140,    -1,    77,    -1,   180,    -1,
      51,    -1,   132,    -1,   131,    -1,   103,   275,   207,   272,
      -1,    84,   275,   207,   272,    -1,    59,   275,   207,   272,
      -1,    21,   275,   207,   272,    -1,   140,   275,   207,   272,
      -1,    77,   275,   207,   272,    -1,   200,   275,   164,   272,
      -1,   168,   275,   164,   272,    -1,   167,   275,   142,   272,
      -1,   132,   275,   207,   272,    -1,   131,   275,   207,   272,
      -1,    -1,   179,   432,   274,   433,   273,   272,    -1,   433,
     434,    -1,   434,    -1,   435,    -1,   436,    -1,   437,    -1,
       1,   272,    -1,   166,   275,   164,   272,    -1,    23,   275,
     164,   272,    -1,   135,   275,   164,   272,    -1,    -1,   195,
     439,   274,   440,   273,   272,    -1,   440,   441,    -1,   441,
      -1,   442,    -1,   443,    -1,   444,    -1,     1,   272,    -1,
     130,   275,   164,   272,    -1,   258,   275,   164,   272,    -1,
      -1,   197,   445,   275,   446,   272,    -1,   446,   276,   447,
      -1,   447,    -1,   102,    -1,   254,    -1,   257,    -1,   269,
      -1,   255,    -1,   249,    -1,   179,    -1,   256,    -1,   248,
      -1,   229,    -1,   190,    -1,   170,    -1,   213,    -1,    -1,
     196,   449,   274,   450,   273,   272,    -1,   450,   451,    -1,
     451,    -1,   452,    -1,   453,    -1,     1,   272,    -1,   130,
     275,   164,   272,    -1,    -1,   197,   454,   275,   455,   272,
      -1,   455,   276,   456,    -1,   456,    -1,   102,    -1,   254,
      -1,   257,    -1,   269,    -1,   255,    -1,   249,    -1,   179,
      -1,   256,    -1,   248,    -1,   229,    -1,   213,    -1,    -1,
      34,   458,   459,   274,   460,   273,   272,    -1,    -1,   463,
      -1,   460,   461,    -1,   461,    -1,   462,    -1,   464,    -1,
     465,    -1,   466,    -1,   467,    -1,   469,    -1,   468,    -1,
     470,    -1,   471,    -1,   484,    -1,   485,    -1,   486,    -1,
     482,    -1,   479,    -1,   481,    -1,   480,    -1,   478,    -1,
     487,    -1,   483,    -1,     1,   272,    -1,   130,   275,   164,
     272,    -1,   164,    -1,    93,   275,   164,   272,    -1,   267,
     275,   164,   272,    -1,   187,   275,   164,   272,    -1,     3,
     275,   164,   272,    -1,   163,   275,   142,   272,    -1,     6,
     275,   227,   272,    -1,     6,   275,   228,   272,    -1,    62,
     275,   164,   272,    -1,    -1,    63,   472,   275,   473,   272,
      -1,   473,   276,   474,    -1,   474,    -1,    -1,   141,   475,
     477,    -1,    -1,   476,   477,    -1,   108,    -1,    32,    -1,
      36,    -1,    11,    -1,    13,    -1,   252,    -1,   177,   275,
     164,   272,    -1,    58,   275,   207,   272,    -1,    36,   275,
     207,   272,    -1,    32,   275,   207,   272,    -1,    11,   275,
     207,   272,    -1,   252,   275,   207,   272,    -1,    95,   275,
     164,   272,    -1,   109,   275,   164,   272,    -1,    27,   275,
     164,   272,    -1,    26,   275,   164,   272,    -1,    -1,   100,
     489,   274,   494,   273,   272,    -1,    -1,   197,   491,   275,
     492,   272,    -1,   492,   276,   493,    -1,   493,    -1,   169,
      -1,   494,   495,    -1,   495,    -1,   496,    -1,   497,    -1,
     490,    -1,     1,    -1,   258,   275,   164,   272,    -1,   166,
     275,   164,   272,    -1,    -1,    42,   499,   274,   500,   273,
     272,    -1,   500,   501,    -1,   501,    -1,   502,    -1,   503,
      -1,     1,    -1,    99,   275,   164,   272,    -1,   166,   275,
     164,   272,    -1,    60,   274,   505,   273,   272,    -1,   505,
     506,    -1,   506,    -1,   507,    -1,   508,    -1,     1,    -1,
      99,   275,   164,   272,    -1,    28,   275,   164,   272,    -1,
      -1,    73,   510,   274,   515,   273,   272,    -1,    -1,   197,
     512,   275,   513,   272,    -1,   513,   276,   514,    -1,   514,
      -1,   169,    -1,   515,   516,    -1,   516,    -1,   517,    -1,
     518,    -1,   511,    -1,     1,    -1,   130,   275,   164,   272,
      -1,   166,   275,   164,   272,    -1,    74,   274,   520,   273,
     272,    -1,   520,   521,    -1,   521,    -1,   529,    -1,   530,
      -1,   532,    -1,   533,    -1,   534,    -1,   535,    -1,   536,
      -1,   537,    -1,   538,    -1,   539,    -1,   540,    -1,   528,
      -1,   542,    -1,   543,    -1,   548,    -1,   549,    -1,   566,
      -1,   551,    -1,   554,    -1,   556,    -1,   555,    -1,   559,
      -1,   552,    -1,   560,    -1,   561,    -1,   562,    -1,   563,
      -1,   565,    -1,   564,    -1,   580,    -1,   567,    -1,   571,
      -1,   572,    -1,   576,    -1,   557,    -1,   558,    -1,   586,
      -1,   584,    -1,   585,    -1,   568,    -1,   531,    -1,   569,
      -1,   550,    -1,   570,    -1,   587,    -1,   575,    -1,   541,
      -1,   588,    -1,   573,    -1,   574,    -1,   524,    -1,   527,
      -1,   522,    -1,   523,    -1,   525,    -1,   526,    -1,   553,
      -1,   544,    -1,   545,    -1,   546,    -1,   547,    -1,     1,
      -1,    80,   275,   142,   272,    -1,    81,   275,   142,   272,
      -1,    13,   275,   207,   272,    -1,   266,   275,   207,   272,
      -1,   171,   275,   281,   272,    -1,   194,   275,   207,   272,
      -1,   101,   275,   142,   272,    -1,    92,   275,   207,   272,
      -1,    97,   275,   207,   272,    -1,    49,   275,   207,   272,
      -1,    61,   275,   207,   272,    -1,     8,   275,   207,   272,
      -1,   122,   275,   281,   272,    -1,   121,   275,   142,   272,
      -1,   115,   275,   142,   272,    -1,     9,   275,   281,   272,
      -1,    10,   275,   207,   272,    -1,   211,   275,   281,   272,
      -1,   210,   275,   281,   272,    -1,    85,   275,   142,   272,
      -1,   105,   275,   207,   272,    -1,   104,   275,   164,   272,
      -1,    29,   275,   164,   272,    -1,    30,   275,   164,   272,
      -1,    31,   275,   164,   272,    -1,   191,   275,   164,   272,
      -1,    98,   275,   207,   272,    -1,   271,   275,   207,   272,
      -1,   202,   275,   207,   272,    -1,   205,   275,   207,   272,
      -1,   206,   275,   207,   272,    -1,   262,   275,   207,   272,
      -1,   204,   275,   207,   272,    -1,   204,   275,   208,   272,
      -1,   203,   275,   207,   272,    -1,   203,   275,   208,   272,
      -1,   156,   275,   281,   272,    -1,    20,   275,   281,   272,
      -1,   148,   275,   207,   272,    -1,   157,   275,   281,   272,
      -1,   198,   275,   207,   272,    -1,   139,   275,   207,   272,
      -1,   253,   275,   207,   272,    -1,   151,   275,   207,   272,
      -1,   125,   275,   164,   272,    -1,    96,   275,   281,   272,
      -1,    53,   275,   142,   272,    -1,   124,   275,   142,   272,
      -1,   192,   275,   164,   272,    -1,    38,   275,   164,   272,
      -1,    33,   275,   142,   272,    -1,   259,   275,   207,   272,
      -1,    55,   275,   164,   272,    -1,   160,   275,   207,   272,
      -1,    45,   275,   207,   272,    -1,   251,   275,   281,   272,
      -1,    -1,   153,   577,   275,   578,   272,    -1,   578,   276,
     579,    -1,   579,    -1,   214,    -1,   217,    -1,   218,    -1,
     220,    -1,   221,    -1,   224,    -1,   243,    -1,   239,    -1,
     241,    -1,   247,    -1,   244,    -1,   223,    -1,   240,    -1,
     242,    -1,   226,    -1,   250,    -1,   215,    -1,   216,    -1,
     229,    -1,   225,    -1,    -1,   150,   581,   275,   582,   272,
      -1,   582,   276,   583,    -1,   583,    -1,   214,    -1,   217,
      -1,   218,    -1,   220,    -1,   221,    -1,   224,    -1,   243,
      -1,   239,    -1,   241,    -1,   247,    -1,   244,    -1,   223,
      -1,   240,    -1,   242,    -1,   226,    -1,   250,    -1,   215,
      -1,   216,    -1,   229,    -1,   225,    -1,   126,   275,   142,
     272,    -1,   127,   275,   142,   272,    -1,    39,   275,   142,
     272,    -1,   219,   275,   283,   272,    -1,    52,   275,   207,
     272,    -1,    -1,    76,   590,   274,   591,   273,   272,    -1,
     591,   592,    -1,   592,    -1,   593,    -1,   594,    -1,   595,
      -1,   599,    -1,   600,    -1,   601,    -1,     1,    -1,    57,
     275,   207,   272,    -1,    54,   275,   281,   272,    -1,    -1,
     113,   596,   275,   597,   272,    -1,   597,   276,   598,    -1,
     598,    -1,   209,    -1,    12,    -1,   258,   275,   164,   272,
      -1,   130,   275,   164,   272,    -1,    -1,     4,   602,   275,
     603,   272,    -1,   603,   276,   604,    -1,   604,    -1,   209,
      -1,    12,    -1,    23,   274,   606,   273,   272,    -1,   606,
     607,    -1,   607,    -1,   611,    -1,   612,    -1,   613,    -1,
     615,    -1,   614,    -1,   620,    -1,   616,    -1,   617,    -1,
     618,    -1,   619,    -1,   621,    -1,   622,    -1,   623,    -1,
     610,    -1,   624,    -1,   625,    -1,   626,    -1,   627,    -1,
     609,    -1,   608,    -1,     1,    -1,    37,   275,   207,   272,
      -1,    46,   275,   207,   272,    -1,   174,   275,   207,   272,
      -1,    48,   275,   207,   272,    -1,   260,   275,   207,   272,
      -1,   261,   275,   207,   272,    -1,   263,   275,   207,   272,
      -1,   264,   275,   207,   272,    -1,   106,   275,   281,   272,
      -1,   107,   275,   281,   272,    -1,   117,   275,   142,   272,
      -1,   165,   275,   207,   272,    -1,   116,   275,   142,   272,
      -1,    41,   275,   142,   272,    -1,    40,   275,   142,   272,
      -1,   137,   275,   207,   272,    -1,   138,   275,   207,   272,
      -1,    14,   275,   207,   272,    -1,   154,   275,   142,   272,
      -1,   155,   275,   281,   272,    -1,   188,   274,   629,   273,
     272,    -1,   629,   630,    -1,   630,    -1,   631,    -1,   632,
      -1,   634,    -1,   636,    -1,   635,    -1,   633,    -1,   637,
      -1,     1,    -1,    64,   275,   207,   272,    -1,    91,   275,
     207,   272,    -1,    88,   275,   164,   272,    -1,   110,   275,
     281,   272,    -1,    86,   275,   207,   272,    -1,    47,   275,
     207,   272,    -1,    90,   275,   207,   272,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   410,   410,   411,   414,   415,   416,   417,   418,   419,
     420,   421,   422,   423,   424,   425,   426,   427,   428,   429,
     430,   431,   432,   433,   434,   435,   436,   440,   440,   441,
     445,   449,   453,   457,   461,   467,   467,   468,   469,   470,
     471,   478,   481,   481,   482,   482,   482,   484,   501,   514,
     513,   534,   534,   536,   536,   536,   536,   538,   547,   553,
     565,   568,   569,   570,   570,   571,   571,   572,   572,   573,
     574,   574,   575,   575,   576,   578,   612,   672,   686,   701,
     710,   724,   733,   761,   791,   814,   864,   866,   866,   867,
     867,   868,   868,   870,   879,   888,   901,   903,   904,   906,
     906,   907,   908,   908,   909,   909,   910,   910,   911,   911,
     912,   913,   915,   919,   923,   930,   937,   944,   951,   958,
     965,   972,   979,   983,   987,   991,   995,   999,  1003,  1009,
    1019,  1018,  1120,  1120,  1121,  1121,  1122,  1122,  1122,  1122,
    1123,  1123,  1124,  1124,  1124,  1125,  1125,  1125,  1126,  1126,
    1126,  1127,  1127,  1127,  1127,  1128,  1128,  1128,  1128,  1129,
    1129,  1131,  1143,  1155,  1189,  1208,  1220,  1231,  1273,  1283,
    1282,  1288,  1288,  1289,  1293,  1297,  1301,  1305,  1309,  1313,
    1317,  1321,  1325,  1329,  1333,  1337,  1341,  1345,  1349,  1353,
    1357,  1361,  1365,  1371,  1382,  1393,  1404,  1415,  1426,  1437,
    1448,  1459,  1470,  1481,  1492,  1503,  1514,  1525,  1537,  1536,
    1540,  1540,  1541,  1541,  1542,  1542,  1544,  1551,  1558,  1565,
    1572,  1579,  1586,  1593,  1600,  1607,  1614,  1621,  1628,  1635,
    1642,  1649,  1663,  1662,  1711,  1711,  1713,  1713,  1714,  1715,
    1715,  1716,  1717,  1718,  1719,  1720,  1721,  1722,  1723,  1724,
    1725,  1726,  1728,  1737,  1746,  1752,  1758,  1764,  1770,  1776,
    1782,  1788,  1794,  1800,  1806,  1812,  1822,  1821,  1838,  1837,
    1842,  1842,  1843,  1847,  1853,  1853,  1854,  1854,  1854,  1854,
    1854,  1856,  1856,  1858,  1858,  1860,  1874,  1894,  1903,  1916,
    1915,  1990,  1990,  1991,  1991,  1991,  1991,  1992,  1992,  1993,
    1993,  1993,  1994,  1994,  1994,  1995,  1995,  1995,  1996,  1996,
    1996,  1996,  1998,  2035,  2048,  2067,  2078,  2087,  2099,  2098,
    2102,  2102,  2103,  2103,  2104,  2104,  2106,  2114,  2121,  2128,
    2135,  2142,  2149,  2156,  2163,  2170,  2177,  2184,  2193,  2204,
    2215,  2226,  2237,  2248,  2260,  2279,  2289,  2298,  2309,  2325,
    2324,  2340,  2340,  2341,  2341,  2341,  2341,  2343,  2352,  2367,
    2381,  2380,  2396,  2396,  2397,  2397,  2397,  2397,  2399,  2408,
    2431,  2430,  2436,  2436,  2437,  2441,  2445,  2449,  2453,  2457,
    2461,  2465,  2469,  2473,  2477,  2481,  2485,  2495,  2494,  2511,
    2511,  2512,  2512,  2512,  2514,  2521,  2520,  2526,  2526,  2527,
    2531,  2535,  2539,  2543,  2547,  2551,  2555,  2559,  2563,  2567,
    2577,  2576,  2722,  2722,  2723,  2723,  2724,  2724,  2724,  2725,
    2725,  2726,  2726,  2727,  2727,  2727,  2728,  2728,  2728,  2729,
    2729,  2729,  2730,  2730,  2731,  2731,  2733,  2745,  2757,  2766,
    2792,  2810,  2828,  2834,  2838,  2846,  2856,  2855,  2859,  2859,
    2860,  2860,  2861,  2861,  2863,  2870,  2881,  2888,  2895,  2902,
    2912,  2953,  2964,  2975,  2990,  3001,  3012,  3025,  3038,  3047,
    3083,  3082,  3146,  3145,  3149,  3149,  3150,  3156,  3156,  3157,
    3157,  3157,  3157,  3159,  3178,  3188,  3187,  3209,  3209,  3210,
    3210,  3210,  3212,  3221,  3233,  3235,  3235,  3236,  3236,  3236,
    3238,  3256,  3289,  3288,  3330,  3329,  3333,  3333,  3334,  3340,
    3340,  3341,  3341,  3341,  3341,  3343,  3349,  3358,  3361,  3361,
    3362,  3362,  3363,  3363,  3364,  3364,  3365,  3365,  3366,  3367,
    3367,  3368,  3368,  3369,  3369,  3370,  3370,  3371,  3371,  3372,
    3372,  3373,  3373,  3374,  3374,  3375,  3375,  3376,  3376,  3377,
    3377,  3378,  3378,  3379,  3379,  3380,  3380,  3381,  3381,  3382,
    3382,  3383,  3383,  3384,  3384,  3385,  3385,  3386,  3386,  3387,
    3387,  3388,  3388,  3389,  3389,  3390,  3390,  3391,  3391,  3391,
    3392,  3393,  3397,  3402,  3407,  3412,  3417,  3422,  3427,  3432,
    3437,  3442,  3447,  3452,  3457,  3462,  3467,  3472,  3477,  3482,
    3487,  3493,  3504,  3509,  3518,  3527,  3536,  3545,  3554,  3559,
    3564,  3569,  3574,  3579,  3584,  3587,  3592,  3595,  3600,  3605,
    3610,  3615,  3620,  3625,  3630,  3635,  3640,  3651,  3656,  3661,
    3666,  3675,  3707,  3725,  3730,  3739,  3744,  3749,  3755,  3754,
    3759,  3759,  3760,  3763,  3766,  3769,  3772,  3775,  3778,  3781,
    3784,  3787,  3790,  3793,  3796,  3799,  3802,  3805,  3808,  3811,
    3814,  3817,  3823,  3822,  3827,  3827,  3828,  3831,  3834,  3837,
    3840,  3843,  3846,  3849,  3852,  3855,  3858,  3861,  3864,  3867,
    3870,  3873,  3876,  3879,  3882,  3885,  3890,  3895,  3900,  3905,
    3910,  3919,  3918,  3942,  3942,  3943,  3944,  3945,  3946,  3947,
    3948,  3949,  3951,  3957,  3964,  3963,  3968,  3968,  3969,  3973,
    3979,  4013,  4023,  4022,  4072,  4072,  4073,  4077,  4086,  4089,
    4089,  4090,  4090,  4091,  4091,  4091,  4092,  4092,  4093,  4093,
    4094,  4094,  4095,  4096,  4096,  4097,  4097,  4098,  4098,  4099,
    4100,  4100,  4102,  4107,  4112,  4117,  4122,  4127,  4132,  4137,
    4142,  4147,  4152,  4157,  4162,  4167,  4172,  4177,  4182,  4187,
    4192,  4197,  4205,  4208,  4208,  4209,  4209,  4210,  4211,  4212,
    4212,  4213,  4214,  4216,  4222,  4228,  4237,  4251,  4257,  4263
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ACCEPT_PASSWORD", "ACTION", "ADMIN",
  "AFTYPE", "T_ALLOW", "ANTI_NICK_FLOOD", "ANTI_SPAM_EXIT_MESSAGE_TIME",
  "ANTI_SPAM_CONNECT_NUMERIC", "AUTOCONN", "T_BLOCK", "BURST_AWAY",
  "BURST_TOPICWHO", "BYTES", "KBYTES", "MBYTES", "GBYTES", "TBYTES",
  "CALLER_ID_WAIT", "CAN_FLOOD", "CAN_IDLE", "CHANNEL", "CIDR_BITLEN_IPV4",
  "CIDR_BITLEN_IPV6", "CIPHER_PREFERENCE", "CLASS", "CLIENTCERT_HASH",
  "CLOAK_KEY1", "CLOAK_KEY2", "CLOAK_KEY3", "COMPRESSED",
  "COMPRESSION_LEVEL", "CONNECT", "CONNECTFREQ", "CRYPTLINK",
  "CYCLE_ON_HOSTCHANGE", "DEFAULT_CIPHER_PREFERENCE", "DEFAULT_FLOODCOUNT",
  "DEFAULT_SPLIT_SERVER_COUNT", "DEFAULT_SPLIT_USER_COUNT", "DENY",
  "DESCRIPTION", "DIE", "DISABLE_AUTH", "DISABLE_FAKE_CHANNELS",
  "DISABLE_HIDDEN", "DISABLE_LOCAL_CHANNELS", "DISABLE_REMOTE_COMMANDS",
  "DNSBL", "DNSBL_EXEMPT", "DOT_IN_IP6_ADDR", "DOTS_IN_IDENT", "DURATION",
  "EGDPOOL_PATH", "EMAIL", "ENABLE", "ENCRYPTED", "EXCEED_LIMIT", "EXEMPT",
  "FAILED_OPER_NOTICE", "FAKENAME", "IRCD_FLAGS", "FLATTEN_LINKS",
  "FFAILED_OPERLOG", "FKILLLOG", "FKLINELOG", "FGLINELOG", "FIOERRLOG",
  "FOPERLOG", "FOPERSPYLOG", "FUSERLOG", "GECOS", "GENERAL", "GLINE",
  "GLINES", "GLINE_EXEMPT", "GLINE_LOG", "GLINE_TIME", "GLINE_MIN_CIDR",
  "GLINE_MIN_CIDR6", "GLOBAL_KILL", "IRCD_AUTH", "NEED_IDENT",
  "HAVENT_READ_CONF", "HIDDEN", "HIDDEN_ADMIN", "HIDDEN_NAME",
  "HIDDEN_OPER", "HIDE_SERVER_IPS", "HIDE_SERVERS", "HIDE_SPOOF_IPS",
  "HOST", "HUB", "HUB_MASK", "IDLETIME", "IGNORE_BOGUS_TS",
  "INVISIBLE_ON_CONNECT", "IP", "KILL", "KILL_CHASE_TIME_LIMIT", "KLINE",
  "KLINE_EXEMPT", "KLINE_REASON", "KLINE_WITH_REASON", "KNOCK_DELAY",
  "KNOCK_DELAY_CHANNEL", "LAZYLINK", "LEAF_MASK", "LINKS_DELAY", "LISTEN",
  "T_LOG", "LOGGING", "LOG_LEVEL", "MAX_ACCEPT", "MAX_BANS",
  "MAX_CHANS_PER_USER", "MAX_GLOBAL", "MAX_IDENT", "MAX_LOCAL",
  "MAX_NICK_CHANGES", "MAX_NICK_TIME", "MAX_NUMBER", "MAX_TARGETS",
  "MESSAGE_LOCALE", "MIN_NONWILDCARD", "MIN_NONWILDCARD_SIMPLE", "MODULE",
  "MODULES", "NAME", "NEED_PASSWORD", "IS_WEBIRC", "NETWORK_DESC",
  "NETWORK_NAME", "NICK", "NICK_CHANGES", "NO_CREATE_ON_SPLIT",
  "NO_JOIN_ON_SPLIT", "NO_OPER_FLOOD", "NO_TILDE", "NOT", "NUMBER",
  "NUMBER_PER_IDENT", "NUMBER_PER_CIDR", "NUMBER_PER_IP",
  "NUMBER_PER_IP_GLOBAL", "OPERATOR", "OPERS_BYPASS_CALLERID", "OPER_LOG",
  "OPER_ONLY_UMODES", "OPER_PASS_RESV", "OPER_SPY_T", "OPER_UMODES",
  "JOIN_FLOOD_COUNT", "JOIN_FLOOD_TIME", "PACE_WAIT", "PACE_WAIT_SIMPLE",
  "PASSWORD", "PATH", "PING_COOKIE", "PING_TIME", "PING_WARNING", "PORT",
  "QSTRING", "QUIET_ON_BAN", "REASON", "REDIRPORT", "REDIRSERV", "REGEX_T",
  "REHASH", "TREJECT_HOLD_TIME", "REMOTE", "REMOTEBAN",
  "RESTRICT_CHANNELS", "RESTRICTED", "RSA_PRIVATE_KEY_FILE",
  "RSA_PUBLIC_KEY_FILE", "SSL_CERTIFICATE_FILE", "RESV", "RESV_EXEMPT",
  "SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS", "SENDQ", "SEND_PASSWORD",
  "SERVERHIDE", "SERVERINFO", "SERVICES", "SERVICES_NAME", "SERVLINK_PATH",
  "IRCD_SID", "TKLINE_EXPIRE_NOTICES", "T_SHARED", "T_CLUSTER", "TYPE",
  "SHORT_MOTD", "SILENT", "SPOOF", "SPOOF_NOTICE", "STATS_E_DISABLED",
  "STATS_I_OPER_ONLY", "STATS_K_OPER_ONLY", "STATS_O_OPER_ONLY",
  "STATS_P_OPER_ONLY", "TBOOL", "TMASKED", "T_REJECT", "TS_MAX_DELTA",
  "TS_WARN_DELTA", "TWODOTS", "T_ALL", "T_BOTS", "T_SOFTCALLERID",
  "T_CALLERID", "T_CCONN", "T_CCONN_FULL", "T_CLIENT_FLOOD", "T_DEAF",
  "T_DEBUG", "T_DRONE", "T_EXTERNAL", "T_FULL", "T_HIDECHANNELS",
  "T_INVISIBLE", "T_IPV4", "T_IPV6", "T_LOCOPS", "T_LOGPATH", "T_L_CRIT",
  "T_L_DEBUG", "T_L_ERROR", "T_L_INFO", "T_L_NOTICE", "T_L_TRACE",
  "T_L_WARN", "T_MAX_CLIENTS", "T_NCHANGE", "T_OPERWALL", "T_REJ",
  "T_SERVNOTICE", "T_SKILL", "T_SPY", "T_SSL", "T_UMODES", "T_UNAUTH",
  "T_UNRESV", "T_UNXLINE", "T_WALLOP", "THROTTLE_TIME", "TOPICBURST",
  "TRUE_NO_OPER_FLOOD", "TKLINE", "TXLINE", "TRESV", "UNKLINE", "USER",
  "USE_EGD", "USE_EXCEPT", "USE_INVEX", "HIDE_KILLER", "USE_REGEX_BANS",
  "USE_KNOCK", "USE_LOGGING", "USE_WHOIS_ACTUALLY", "VHOST", "VHOST6",
  "XLINE", "WARN", "WARN_NO_NLINE", "';'", "'}'", "'{'", "'='", "','",
  "$accept", "conf", "conf_item", "timespec_", "timespec", "sizespec_",
  "sizespec", "modules_entry", "modules_items", "modules_item",
  "modules_module", "modules_path", "dnsbl_entry", "$@1", "dnsbl_items",
  "dnsbl_item", "dnsbl_name", "dnsbl_duration", "dnsbl_reason",
  "serverinfo_entry", "serverinfo_items", "serverinfo_item",
  "serverinfo_ssl_certificate_file", "serverinfo_rsa_private_key_file",
  "serverinfo_name", "serverinfo_sid", "serverinfo_description",
  "serverinfo_network_name", "serverinfo_network_desc", "serverinfo_vhost",
  "serverinfo_vhost6", "serverinfo_max_clients", "serverinfo_hub",
  "admin_entry", "admin_items", "admin_item", "admin_name", "admin_email",
  "admin_description", "logging_entry", "logging_items", "logging_item",
  "logging_path", "logging_oper_log", "logging_fuserlog",
  "logging_ffailed_operlog", "logging_foperlog", "logging_foperspylog",
  "logging_fglinelog", "logging_fklinelog", "logging_ioerrlog",
  "logging_killlog", "logging_log_level", "logging_use_logging",
  "oper_entry", "$@2", "oper_name_b", "oper_items", "oper_item",
  "oper_name", "oper_name_t", "oper_user", "oper_client_certificate_hash",
  "oper_password", "oper_encrypted", "oper_rsa_public_key_file",
  "oper_class", "oper_umodes", "$@3", "oper_umodes_items",
  "oper_umodes_item", "oper_global_kill", "oper_remote", "oper_remoteban",
  "oper_kline", "oper_xline", "oper_unkline", "oper_gline",
  "oper_nick_changes", "oper_die", "oper_rehash", "oper_admin",
  "oper_hidden_admin", "oper_hidden_oper", "oper_spy", "oper_operwall",
  "oper_flags", "$@4", "oper_flags_items", "oper_flags_item", "$@5", "$@6",
  "oper_flags_item_atom", "class_entry", "$@7", "class_name_b",
  "class_items", "class_item", "class_name", "class_name_t",
  "class_ping_time", "class_ping_warning", "class_number_per_ip",
  "class_connectfreq", "class_max_number", "class_max_global",
  "class_max_local", "class_max_ident", "class_sendq",
  "class_cidr_bitlen_ipv4", "class_cidr_bitlen_ipv6",
  "class_number_per_cidr", "listen_entry", "$@8", "listen_flags", "$@9",
  "listen_flags_items", "listen_flags_item", "listen_items", "listen_item",
  "listen_port", "$@10", "port_items", "port_item", "listen_address",
  "listen_host", "auth_entry", "$@11", "auth_items", "auth_item",
  "auth_user", "auth_passwd", "auth_client_certificate_hash",
  "auth_spoof_notice", "auth_class", "auth_encrypted", "auth_flags",
  "$@12", "auth_flags_items", "auth_flags_item", "$@13", "$@14",
  "auth_flags_item_atom", "auth_kline_exempt", "auth_need_ident",
  "auth_exceed_limit", "auth_can_flood", "auth_no_tilde",
  "auth_gline_exempt", "auth_spoof", "auth_redir_serv", "auth_redir_port",
  "auth_webirc", "auth_need_password", "resv_entry", "$@15", "resv_items",
  "resv_item", "resv_creason", "resv_channel", "resv_nick", "shared_entry",
  "$@16", "shared_items", "shared_item", "shared_name", "shared_user",
  "shared_type", "$@17", "shared_types", "shared_type_item",
  "cluster_entry", "$@18", "cluster_items", "cluster_item", "cluster_name",
  "cluster_type", "$@19", "cluster_types", "cluster_type_item",
  "connect_entry", "$@20", "connect_name_b", "connect_items",
  "connect_item", "connect_name", "connect_name_t", "connect_host",
  "connect_vhost", "connect_send_password", "connect_accept_password",
  "connect_port", "connect_aftype", "connect_fakename", "connect_flags",
  "$@21", "connect_flags_items", "connect_flags_item", "$@22", "$@23",
  "connect_flags_item_atom", "connect_rsa_public_key_file",
  "connect_encrypted", "connect_cryptlink", "connect_compressed",
  "connect_auto", "connect_topicburst", "connect_hub_mask",
  "connect_leaf_mask", "connect_class", "connect_cipher_preference",
  "kill_entry", "$@24", "kill_type", "$@25", "kill_type_items",
  "kill_type_item", "kill_items", "kill_item", "kill_user", "kill_reason",
  "deny_entry", "$@26", "deny_items", "deny_item", "deny_ip",
  "deny_reason", "exempt_entry", "exempt_items", "exempt_item",
  "exempt_ip", "exempt_client_certificate_hash", "gecos_entry", "$@27",
  "gecos_flags", "$@28", "gecos_flags_items", "gecos_flags_item",
  "gecos_items", "gecos_item", "gecos_name", "gecos_reason",
  "general_entry", "general_items", "general_item",
  "general_gline_min_cidr", "general_gline_min_cidr6",
  "general_burst_away", "general_use_whois_actually",
  "general_reject_hold_time", "general_tkline_expire_notices",
  "general_kill_chase_time_limit", "general_hide_spoof_ips",
  "general_ignore_bogus_ts", "general_disable_remote_commands",
  "general_failed_oper_notice", "general_anti_nick_flood",
  "general_max_nick_time", "general_max_nick_changes",
  "general_max_accept", "general_anti_spam_exit_message_time",
  "general_anti_spam_connect_numeric", "general_ts_warn_delta",
  "general_ts_max_delta", "general_havent_read_conf",
  "general_kline_with_reason", "general_kline_reason",
  "general_cloak_key1", "general_cloak_key2", "general_cloak_key3",
  "general_services_name", "general_invisible_on_connect",
  "general_warn_no_nline", "general_stats_e_disabled",
  "general_stats_o_oper_only", "general_stats_P_oper_only",
  "general_hide_killer", "general_stats_k_oper_only",
  "general_stats_i_oper_only", "general_pace_wait",
  "general_caller_id_wait", "general_opers_bypass_callerid",
  "general_pace_wait_simple", "general_short_motd",
  "general_no_oper_flood", "general_true_no_oper_flood",
  "general_oper_pass_resv", "general_message_locale", "general_idletime",
  "general_dots_in_ident", "general_max_targets", "general_servlink_path",
  "general_default_cipher_preference", "general_compression_level",
  "general_use_egd", "general_egdpool_path", "general_ping_cookie",
  "general_disable_auth", "general_throttle_time", "general_oper_umodes",
  "$@29", "umode_oitems", "umode_oitem", "general_oper_only_umodes",
  "$@30", "umode_items", "umode_item", "general_min_nonwildcard",
  "general_min_nonwildcard_simple", "general_default_floodcount",
  "general_client_flood", "general_dot_in_ip6_addr", "gline_entry", "$@31",
  "gline_items", "gline_item", "gline_enable", "gline_duration",
  "gline_logging", "$@32", "gline_logging_types",
  "gline_logging_type_item", "gline_user", "gline_server", "gline_action",
  "$@33", "gdeny_types", "gdeny_type_item", "channel_entry",
  "channel_items", "channel_item", "channel_cycle_on_hostchange",
  "channel_disable_fake_channels", "channel_restrict_channels",
  "channel_disable_local_channels", "channel_use_except",
  "channel_use_invex", "channel_use_regex_bans", "channel_use_knock",
  "channel_knock_delay", "channel_knock_delay_channel",
  "channel_max_chans_per_user", "channel_quiet_on_ban", "channel_max_bans",
  "channel_default_split_user_count", "channel_default_split_server_count",
  "channel_no_create_on_split", "channel_no_join_on_split",
  "channel_burst_topicwho", "channel_jflood_count", "channel_jflood_time",
  "serverhide_entry", "serverhide_items", "serverhide_item",
  "serverhide_flatten_links", "serverhide_hide_servers",
  "serverhide_hidden_name", "serverhide_links_delay", "serverhide_hidden",
  "serverhide_disable_hidden", "serverhide_hide_server_ips", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   468,   469,   470,   471,   472,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,   496,   497,   498,   499,   500,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
     515,   516,   517,   518,   519,   520,   521,   522,   523,   524,
     525,   526,    59,   125,   123,    61,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   277,   278,   278,   279,   279,   279,   279,   279,   279,
     279,   279,   279,   279,   279,   279,   279,   279,   279,   279,
     279,   279,   279,   279,   279,   279,   279,   280,   280,   281,
     281,   281,   281,   281,   281,   282,   282,   283,   283,   283,
     283,   284,   285,   285,   286,   286,   286,   287,   288,   290,
     289,   291,   291,   292,   292,   292,   292,   293,   294,   295,
     296,   297,   297,   298,   298,   298,   298,   298,   298,   298,
     298,   298,   298,   298,   298,   299,   300,   301,   302,   303,
     304,   305,   306,   307,   308,   309,   310,   311,   311,   312,
     312,   312,   312,   313,   314,   315,   316,   317,   317,   318,
     318,   318,   318,   318,   318,   318,   318,   318,   318,   318,
     318,   318,   319,   320,   321,   322,   323,   324,   325,   326,
     327,   328,   329,   329,   329,   329,   329,   329,   329,   330,
     332,   331,   333,   333,   334,   334,   335,   335,   335,   335,
     335,   335,   335,   335,   335,   335,   335,   335,   335,   335,
     335,   335,   335,   335,   335,   335,   335,   335,   335,   335,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   345,
     344,   346,   346,   347,   347,   347,   347,   347,   347,   347,
     347,   347,   347,   347,   347,   347,   347,   347,   347,   347,
     347,   347,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   364,   363,
     365,   365,   367,   366,   368,   366,   369,   369,   369,   369,
     369,   369,   369,   369,   369,   369,   369,   369,   369,   369,
     369,   369,   371,   370,   372,   372,   373,   373,   374,   374,
     374,   374,   374,   374,   374,   374,   374,   374,   374,   374,
     374,   374,   375,   376,   377,   378,   379,   380,   381,   382,
     383,   384,   385,   386,   387,   388,   390,   389,   392,   391,
     393,   393,   394,   394,   395,   395,   396,   396,   396,   396,
     396,   398,   397,   399,   399,   400,   400,   401,   402,   404,
     403,   405,   405,   406,   406,   406,   406,   406,   406,   406,
     406,   406,   406,   406,   406,   406,   406,   406,   406,   406,
     406,   406,   407,   408,   409,   410,   411,   412,   414,   413,
     415,   415,   417,   416,   418,   416,   419,   419,   419,   419,
     419,   419,   419,   419,   419,   419,   419,   419,   420,   421,
     422,   423,   424,   425,   426,   427,   428,   429,   430,   432,
     431,   433,   433,   434,   434,   434,   434,   435,   436,   437,
     439,   438,   440,   440,   441,   441,   441,   441,   442,   443,
     445,   444,   446,   446,   447,   447,   447,   447,   447,   447,
     447,   447,   447,   447,   447,   447,   447,   449,   448,   450,
     450,   451,   451,   451,   452,   454,   453,   455,   455,   456,
     456,   456,   456,   456,   456,   456,   456,   456,   456,   456,
     458,   457,   459,   459,   460,   460,   461,   461,   461,   461,
     461,   461,   461,   461,   461,   461,   461,   461,   461,   461,
     461,   461,   461,   461,   461,   461,   462,   463,   464,   465,
     466,   467,   468,   469,   469,   470,   472,   471,   473,   473,
     475,   474,   476,   474,   477,   477,   477,   477,   477,   477,
     478,   479,   480,   481,   482,   483,   484,   485,   486,   487,
     489,   488,   491,   490,   492,   492,   493,   494,   494,   495,
     495,   495,   495,   496,   497,   499,   498,   500,   500,   501,
     501,   501,   502,   503,   504,   505,   505,   506,   506,   506,
     507,   508,   510,   509,   512,   511,   513,   513,   514,   515,
     515,   516,   516,   516,   516,   517,   518,   519,   520,   520,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   521,   521,   521,   521,   521,   521,   521,   521,
     521,   521,   522,   523,   524,   525,   526,   527,   528,   529,
     530,   531,   532,   533,   534,   535,   536,   537,   538,   539,
     540,   541,   542,   543,   544,   545,   546,   547,   548,   549,
     550,   551,   552,   553,   554,   554,   555,   555,   556,   557,
     558,   559,   560,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,   571,   572,   573,   574,   575,   577,   576,
     578,   578,   579,   579,   579,   579,   579,   579,   579,   579,
     579,   579,   579,   579,   579,   579,   579,   579,   579,   579,
     579,   579,   581,   580,   582,   582,   583,   583,   583,   583,
     583,   583,   583,   583,   583,   583,   583,   583,   583,   583,
     583,   583,   583,   583,   583,   583,   584,   585,   586,   587,
     588,   590,   589,   591,   591,   592,   592,   592,   592,   592,
     592,   592,   593,   594,   596,   595,   597,   597,   598,   598,
     599,   600,   602,   601,   603,   603,   604,   604,   605,   606,
     606,   607,   607,   607,   607,   607,   607,   607,   607,   607,
     607,   607,   607,   607,   607,   607,   607,   607,   607,   607,
     607,   607,   608,   609,   610,   611,   612,   613,   614,   615,
     616,   617,   618,   619,   620,   621,   622,   623,   624,   625,
     626,   627,   628,   629,   629,   630,   630,   630,   630,   630,
     630,   630,   630,   631,   632,   633,   634,   635,   636,   637
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     0,     1,     2,
       3,     3,     3,     3,     3,     0,     1,     2,     3,     3,
       3,     5,     2,     1,     1,     1,     2,     4,     4,     0,
       6,     2,     1,     1,     1,     1,     2,     4,     4,     4,
       5,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     5,     2,     1,     1,
       1,     1,     2,     4,     4,     4,     5,     2,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       0,     7,     0,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     4,     1,     4,     4,     4,     4,     4,     4,     0,
       5,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     0,     5,
       3,     1,     0,     3,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     0,     7,     0,     1,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     4,     1,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     0,     6,     0,     5,
       3,     1,     1,     1,     2,     1,     1,     1,     1,     1,
       2,     0,     5,     3,     1,     1,     3,     4,     4,     0,
       6,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     4,     4,     4,     4,     4,     4,     0,     5,
       3,     1,     0,     3,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     0,
       6,     2,     1,     1,     1,     1,     2,     4,     4,     4,
       0,     6,     2,     1,     1,     1,     1,     2,     4,     4,
       0,     5,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     0,     6,     2,
       1,     1,     1,     2,     4,     0,     5,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       0,     7,     0,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     4,     1,     4,     4,
       4,     4,     4,     4,     4,     4,     0,     5,     3,     1,
       0,     3,     0,     2,     1,     1,     1,     1,     1,     1,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       0,     6,     0,     5,     3,     1,     1,     2,     1,     1,
       1,     1,     1,     4,     4,     0,     6,     2,     1,     1,
       1,     1,     4,     4,     5,     2,     1,     1,     1,     1,
       4,     4,     0,     6,     0,     5,     3,     1,     1,     2,
       1,     1,     1,     1,     1,     4,     4,     5,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     0,     5,
       3,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     0,     5,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     4,     4,     4,     4,
       4,     0,     6,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     4,     4,     0,     5,     3,     1,     1,     1,
       4,     4,     0,     5,     3,     1,     1,     1,     5,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     5,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     4,     4,     4,     4,     4,     4,     4
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       2,     0,     1,     0,     0,     0,   232,   410,   485,    49,
       0,   502,     0,   691,   289,   470,   266,     0,     0,   130,
     349,     0,     0,   360,   387,     3,    23,    24,    11,     4,
       5,     6,     8,     9,    10,    13,    14,    15,    16,    17,
      18,    19,    22,    20,    21,     7,    12,    25,    26,     0,
       0,   234,   412,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   132,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    88,    89,    91,    90,   741,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   720,   740,   739,   734,   721,   722,   723,   725,   724,
     727,   728,   729,   730,   726,   731,   732,   733,   735,   736,
     737,   738,   253,     0,   235,   437,     0,   413,     0,     0,
     499,     0,     0,     0,   496,   497,   498,     0,   581,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   662,     0,   638,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   519,   572,   573,   570,   574,   575,   571,   531,   520,
     521,   560,   522,   523,   524,   525,   526,   527,   528,   529,
     530,   566,   532,   533,   577,   578,   579,   580,   534,   535,
     562,   537,   542,   576,   538,   540,   539,   554,   555,   541,
     543,   544,   545,   546,   548,   547,   536,   550,   559,   561,
     563,   551,   552,   568,   569,   565,   553,   549,   557,   558,
     556,   564,   567,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    98,    99,   100,   103,   110,   104,   108,   105,   106,
     109,   107,   101,   102,     0,     0,     0,     0,    43,    44,
      45,   162,     0,   133,     0,   772,     0,     0,     0,     0,
       0,     0,     0,     0,   764,   765,   766,   770,   767,   769,
     768,   771,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    62,    73,    70,    63,    72,
      66,    67,    68,    64,    71,    69,    65,     0,     0,    92,
       0,     0,     0,     0,    87,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   719,     0,     0,   491,
       0,     0,     0,   488,   489,   490,     0,     0,     0,     0,
       0,    52,    53,    54,    55,     0,     0,     0,   495,   514,
       0,     0,   504,   513,     0,   510,   511,   512,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     518,   701,   712,     0,     0,   704,     0,     0,     0,   694,
     695,   696,   697,   698,   699,   700,     0,     0,     0,     0,
       0,     0,   318,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   292,   293,   294,   310,
     303,   295,   309,   296,   297,   298,   299,   307,   300,   301,
     302,   305,   306,   304,   308,   482,     0,   472,     0,   481,
       0,   478,   479,   480,     0,   268,     0,     0,     0,   277,
       0,   275,   276,   278,   279,   111,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    97,
      46,     0,     0,     0,    42,     0,     0,     0,     0,     0,
       0,   352,   353,   354,   355,     0,     0,     0,     0,     0,
       0,     0,     0,   763,    74,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    61,     0,     0,
     370,     0,     0,   363,   364,   365,   366,     0,     0,   395,
       0,   390,   391,   392,     0,     0,     0,    86,     0,     0,
       0,     0,     0,     0,    27,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   718,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   237,   238,   241,   242,   244,
     245,   246,   247,   248,   249,   250,   239,   240,   243,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   446,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     415,   416,   417,   418,   419,   420,   422,   421,   423,   424,
     432,   429,   431,   430,   428,   434,   425,   426,   427,   433,
       0,     0,     0,   487,    56,     0,     0,     0,     0,    51,
       0,     0,   494,     0,     0,     0,     0,   509,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    35,     0,     0,     0,     0,     0,
       0,     0,   517,     0,     0,     0,     0,     0,     0,     0,
     693,   311,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   291,     0,     0,     0,     0,   477,   280,     0,     0,
       0,     0,     0,   274,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    96,     0,     0,    41,     0,     0,     0,     0,
       0,     0,   208,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   169,     0,     0,
       0,     0,   135,   136,   137,   157,   138,   155,   156,   142,
     141,   143,   144,   150,   145,   146,   147,   148,   149,   151,
     152,   153,   139,   140,   158,   154,   159,   356,     0,     0,
       0,     0,   351,     0,     0,     0,     0,     0,     0,     0,
     762,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    60,   367,     0,     0,     0,     0,   362,   393,
       0,     0,     0,   389,    95,    94,    93,   759,   742,   756,
     755,   743,   745,    27,    27,    27,    27,    27,    29,    28,
     750,   751,   754,   752,   757,   758,   760,   761,   753,   744,
     746,   747,   748,   749,   251,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   236,
     435,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   414,     0,     0,   486,     0,     0,     0,    50,   501,
     500,     0,     0,     0,   503,   593,   597,   598,   584,   619,
     604,   605,   606,   632,   631,   688,   636,   591,   690,   628,
     634,   592,   582,   583,   601,   589,   627,   590,   608,   588,
     603,   602,   596,   595,   594,   629,   626,   686,   687,   623,
     620,   666,   682,   683,   667,   668,   669,   670,   677,   671,
     685,   680,   684,   673,   678,   674,   679,   672,   676,   675,
     681,     0,   665,   625,   642,   658,   659,   643,   644,   645,
     646,   653,   647,   661,   656,   660,   649,   654,   650,   655,
     648,   652,   651,   657,     0,   641,   618,   621,   635,   586,
     607,   630,   587,   622,   610,   616,   617,   614,   615,   611,
     612,   600,   599,    35,    35,    35,    37,    36,   689,   637,
     624,   633,   613,   585,   609,     0,     0,     0,     0,     0,
       0,   692,     0,     0,     0,     0,     0,   324,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     290,     0,     0,     0,   471,     0,     0,     0,   285,   281,
     284,   267,   115,   121,   119,   118,   120,   116,   117,   114,
     122,   128,   123,   127,   125,   126,   124,   113,   112,   129,
      47,    48,   160,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   134,     0,
       0,     0,   350,   778,   773,   777,   775,   779,   774,   776,
      79,    85,    77,    81,    80,    76,    75,    78,    84,    82,
      83,     0,     0,     0,   361,     0,     0,   388,    30,    31,
      32,    33,    34,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   233,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   452,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   411,   492,   493,
      58,    57,    59,   515,   516,   508,     0,   507,   663,     0,
     639,     0,    38,    39,    40,   717,   716,     0,   715,   703,
     702,   709,   708,     0,   707,   711,   710,   341,   316,   314,
     317,   340,   322,     0,   321,     0,   343,   339,   338,   348,
     347,   342,   313,   346,   345,   344,   315,   312,   484,   476,
       0,   475,   483,   273,   272,     0,   271,   288,   287,     0,
       0,     0,     0,     0,     0,     0,     0,   214,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   131,   358,   359,   357,
     368,   374,   385,   380,   384,   386,   383,   382,   379,   375,
     378,   381,   376,   377,     0,   373,   369,   394,   399,   405,
     409,   408,   407,   404,   400,   403,   406,   401,   402,     0,
     398,   263,   264,   257,   259,   261,   260,   258,   252,   265,
     256,   254,   255,   262,   441,   443,   444,   464,   469,   468,
     463,   462,   461,   445,   450,     0,   449,     0,   438,   466,
     467,   436,   442,   460,   440,   465,   439,   505,     0,   664,
     640,   713,     0,   705,     0,     0,   319,   324,   330,   331,
     335,   327,   333,   329,   328,   337,   336,   332,   334,   326,
     325,   473,     0,   269,     0,   286,   283,   282,   203,   168,
     164,   201,   166,   212,     0,   211,     0,   199,   193,   204,
     205,   196,   161,   200,   206,   165,   202,   194,   195,   167,
     207,   173,   189,   190,   174,   175,   176,   177,   184,   178,
     192,   187,   191,   180,   185,   181,   186,   179,   183,   182,
     188,     0,   172,   198,   163,   197,   371,     0,   396,     0,
       0,   447,   452,   457,   458,   455,   456,   454,   459,   453,
     506,   714,   706,   323,   320,   474,   270,     0,   209,   214,
     224,   222,   231,   221,   216,   225,   229,   218,   226,   228,
     223,   217,   230,   227,   219,   220,   215,   170,     0,   372,
     397,   451,   448,   213,   210,   171
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    25,   958,   959,  1126,  1127,    26,   297,   298,
     299,   300,    27,    54,   390,   391,   392,   393,   394,    28,
     334,   335,   336,   337,   338,   339,   340,   341,   342,   343,
     344,   345,   346,    29,    74,    75,    76,    77,    78,    30,
     280,   281,   282,   283,   284,   285,   286,   287,   288,   289,
     290,   291,   292,   293,    31,    64,   302,   881,   882,   883,
     303,   884,   885,   886,   887,   888,   889,   890,  1213,  1521,
    1522,   891,   892,   893,   894,   895,   896,   897,   898,   899,
     900,   901,   902,   903,   904,   905,   906,  1198,  1484,  1485,
    1547,  1486,  1566,    32,    51,   123,   654,   655,   656,   124,
     657,   658,   659,   660,   661,   662,   663,   664,   665,   666,
     667,   668,    33,    61,   539,   828,  1345,  1346,   540,   541,
     542,  1351,  1169,  1170,   543,   544,    34,    59,   505,   506,
     507,   508,   509,   510,   511,   512,   513,   807,  1323,  1324,
    1455,  1325,  1470,   514,   515,   516,   517,   518,   519,   520,
     521,   522,   523,   524,    35,    65,   570,   571,   572,   573,
     574,    36,    68,   602,   603,   604,   605,   606,   935,  1394,
    1395,    37,    69,   610,   611,   612,   613,   941,  1409,  1410,
      38,    52,   126,   689,   690,   691,   127,   692,   693,   694,
     695,   696,   697,   698,   699,  1000,  1435,  1436,  1530,  1437,
    1539,   700,   701,   702,   703,   704,   705,   706,   707,   708,
     709,    39,    60,   529,   823,  1340,  1341,   530,   531,   532,
     533,    40,    53,   382,   383,   384,   385,    41,   133,   134,
     135,   136,    42,    56,   403,   725,  1296,  1297,   404,   405,
     406,   407,    43,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   209,   210,   211,   212,   213,   214,   215,   216,
     217,   218,   219,   220,   221,   222,   223,   224,   225,   226,
     227,   228,   229,   230,   231,   232,   233,   234,   235,   236,
     237,   238,   239,   240,   241,   242,   243,   244,   245,   246,
     247,   248,   249,   250,   251,   252,   253,   254,   255,   256,
     446,  1104,  1105,   257,   444,  1081,  1082,   258,   259,   260,
     261,   262,    44,    58,   478,   479,   480,   481,   482,   796,
    1313,  1314,   483,   484,   485,   793,  1307,  1308,    45,   100,
     101,   102,   103,   104,   105,   106,   107,   108,   109,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   119,   120,
     121,    46,   313,   314,   315,   316,   317,   318,   319,   320,
     321
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -813
static const yytype_int16 yypact[] =
{
    -813,   983,  -813,  -255,  -268,  -259,  -813,  -813,  -813,  -813,
    -251,  -813,  -231,  -813,  -813,  -813,  -813,  -200,  -197,  -813,
    -813,  -195,  -170,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,     9,
     826,   -54,   -51,  -155,  -145,    25,  -143,   530,  -121,  -119,
    -114,  -105,   646,    69,    19,   -89,   585,   576,   -84,   -80,
     -38,   -87,   -39,   -29,    24,  -813,  -813,  -813,  -813,  -813,
     -20,   -15,   -10,    -8,    -6,    -3,     1,     3,    16,    17,
      23,    29,    31,    45,    46,    47,    48,    50,    55,    57,
     210,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,     0,  -813,  -813,    60,  -813,    26,   173,
    -813,    68,    70,     2,  -813,  -813,  -813,   127,  -813,    83,
      91,    93,    94,    97,    98,    99,   101,   104,   106,   108,
     121,   125,   132,   133,   135,   136,   140,   143,   145,   147,
     148,   151,   152,   154,   156,   157,   159,   165,   166,   167,
     168,   170,   171,   172,   174,  -813,   175,  -813,   176,   178,
     183,   187,   191,   193,   194,   200,   202,   203,   206,   207,
     209,   211,   213,   214,   216,   217,   219,   220,   222,   226,
      11,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,   119,   837,    13,   126,    72,   229,   231,
     232,   233,   236,   246,   248,   249,   250,   255,   266,   267,
      77,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,    85,   269,   272,    37,  -813,  -813,
    -813,  -813,   118,  -813,   117,  -813,   273,   281,   283,   287,
     289,   295,   296,     7,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,   122,   298,   299,   301,   303,   305,   306,   309,
     313,   314,   317,   318,   327,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,    56,    36,  -813,
     123,   237,   290,   224,  -813,    89,    92,   238,   343,   348,
     350,   360,   360,   430,   454,   390,   391,   457,   360,   394,
     396,   397,   399,   400,   402,   340,  -813,   774,   815,  -813,
     338,   339,    15,  -813,  -813,  -813,   345,   346,   354,   355,
      27,  -813,  -813,  -813,  -813,   456,   459,   361,  -813,  -813,
     362,   363,  -813,  -813,    21,  -813,  -813,  -813,   411,   360,
     429,   432,   360,   476,   477,   478,   501,   480,   504,   441,
     443,   446,   516,   495,   453,   519,   520,   521,   458,   360,
     460,   461,   522,   502,   465,   532,   535,   360,   537,   518,
     542,   543,   481,   482,   416,   485,   418,   360,   360,   487,
     360,   533,   534,   489,   493,   497,  -146,   -86,   498,   500,
     360,   360,   560,   360,   512,   513,   523,   524,   531,   436,
    -813,  -813,  -813,   448,   452,  -813,   462,   464,    28,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,   471,   469,   470,   472,
     473,   475,  -813,   483,   484,   488,   490,   491,   492,   496,
     499,   503,   507,   509,   511,   332,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,   515,  -813,   527,  -813,
      32,  -813,  -813,  -813,   474,  -813,   528,   529,   536,  -813,
      12,  -813,  -813,  -813,  -813,  -813,   565,   587,   589,   593,
     598,   600,   604,   606,   282,   608,   612,   570,   525,  -813,
    -813,   615,   624,   538,  -813,   698,   540,   544,   545,   547,
      35,  -813,  -813,  -813,  -813,   584,   586,   599,   641,   610,
     616,   360,   541,  -813,  -813,   643,   617,   651,   665,   666,
     667,   669,   671,   694,   681,   682,   577,  -813,   581,   573,
    -813,   579,    82,  -813,  -813,  -813,  -813,   583,   582,  -813,
     105,  -813,  -813,  -813,   588,   590,   597,  -813,   607,   609,
     611,   613,   618,   619,   221,   626,   627,   629,   631,   633,
     634,   635,   637,   640,   644,   645,   653,   654,   655,  -813,
     656,   605,   614,   638,   659,   662,   664,   672,   673,   674,
     675,   676,   677,   678,   294,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,   657,
     679,   683,   684,   686,   687,   690,   691,   695,   696,  -813,
     697,   699,   700,   701,   704,   707,   710,   711,   712,   335,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
     718,   720,   658,  -813,  -813,   360,   723,   724,   685,  -813,
     717,   721,  -813,   751,   767,   719,   727,  -813,   729,   731,
     736,   737,   739,   740,   741,   742,   743,   744,   746,   748,
     749,   752,   754,   756,   757,   758,   759,   760,   762,   764,
     768,   769,   770,   772,   773,   775,   776,   777,   778,   779,
     780,   782,   783,   786,   903,   789,   966,   790,   791,   792,
     793,   796,   797,   798,   799,   800,   801,   802,   803,   804,
     805,   806,   808,   809,    30,   812,   813,   816,   819,   820,
     821,   825,  -813,   747,   360,   652,   771,   832,   859,   827,
    -813,  -813,   734,   875,   934,   766,   893,   828,   894,   895,
     897,   898,   899,   902,   946,   969,   949,   950,   908,   958,
     853,  -813,   967,   858,   970,   863,  -813,  -813,   861,   973,
     974,   997,   868,  -813,   869,   876,   877,   879,   880,   882,
     883,   885,   886,   887,   888,   889,   891,   892,   896,   901,
     904,   913,  -813,   916,   921,  -813,   922,   890,   900,   923,
     924,   925,  -813,   926,   927,   928,   929,   936,   937,   939,
     940,   947,   955,   956,   959,   960,   961,  -813,   962,   963,
     964,   179,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  1002,  1005,
    1006,   953,  -813,   968,   977,   979,   980,   982,   984,   985,
    -813,   986,   987,   988,   989,   990,   991,   992,   993,   994,
     995,   996,  -813,  -813,  1010,   998,  1032,   999,  -813,  -813,
    1033,  1000,  1004,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,   360,   360,   360,   360,   360,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  1025,  1091,   360,  1099,  1106,
    1113,  1127,  1108,  1128,  1132,   360,   360,   560,  1007,  -813,
    -813,  1114,   -50,  1070,  1116,  1117,  1075,  1076,  1077,  1121,
    1011,  1123,  1124,  1125,  1126,  1149,  1129,  1130,  1085,  1131,
    1024,  -813,  1026,  1027,  -813,  1028,  1029,  1030,  -813,  -813,
    -813,  1031,  1034,   692,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -267,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -237,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,   560,   560,   560,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,    -1,  1035,  1036,    22,  1037,
    1038,  -813,  1039,  1040,  1041,  1042,  1043,  1156,  1044,  1045,
    1046,  1047,  1048,  1049,  1050,  1051,  1052,  1053,  1054,  1055,
    -813,  1056,  1135,  1057,  -813,   -82,  1058,  1059,  1093,   670,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  1133,  1168,  1169,  1134,  1136,  1060,  1137,
    1138,  1139,  1140,  1141,  1170,  1142,  1143,  1172,  1144,  1145,
    1146,  1173,  1147,  1063,  1148,  1175,  1150,  1084,  -813,  1086,
    1087,  1088,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  1089,   297,  1090,  -813,  1092,   280,  -813,  -813,  -813,
    -813,  -813,  -813,  1094,  1095,  1096,  1097,  1098,  1100,  1101,
    1102,  1103,  1104,  1105,  1107,  1109,  -813,  1110,  1111,  1112,
    1115,  1118,  1119,  1120,  1122,  1151,  1152,  1201,  1153,  1154,
    1155,  1157,  1158,  1159,  1160,  1161,  1162,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -217,  -813,  -813,   903,
    -813,   966,  -813,  -813,  -813,  -813,  -813,  -203,  -813,  -813,
    -813,  -813,  -813,  -188,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -182,  -813,   976,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -142,  -813,  -813,  -813,  -813,  -120,  -813,  -813,  -813,  1221,
     997,  1163,  1164,  1165,  1166,  1167,  1171,  1224,  1174,  1176,
    1177,  1178,  1179,  1180,  1181,  1182,  1183,  1184,  1185,  1186,
    1187,  1188,  1003,  1189,  1190,  1191,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,   -77,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,   -72,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,   -33,  -813,   227,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,   692,  -813,
    -813,  -813,    -1,  -813,    22,   976,  -813,  1156,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  1135,  -813,   -82,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,   -31,  -813,   750,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,   -28,  -813,  -813,  -813,  -813,  -813,   297,  -813,   280,
     227,  -813,  1201,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,   750,  -813,  1224,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  1003,  -813,
    -813,  -813,  -813,  -813,  -813,  -813
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -813,  -813,  -813,  -568,  -361,  -812,  -460,  -813,  -813,  1074,
    -813,  -813,  -813,  -813,  -813,  1008,  -813,  -813,  -813,  -813,
    -813,  1061,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  1304,  -813,  -813,  -813,  -813,
    -813,  1192,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,   505,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -183,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -169,
    -813,  -813,  -159,  -813,  -813,  -813,  -813,   735,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,   -81,  -813,   856,
    -813,  -813,  -813,    49,  -813,  -813,  -813,  -813,  -813,   905,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,   -60,
    -813,  -813,   -55,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,   831,  -813,  -813,
    -813,  -813,  -813,  -813,   807,  -813,  -813,  -813,  -813,  -813,
    -125,  -813,  -813,  -813,   794,  -813,  -813,  -813,  -813,  -126,
    -813,  -813,  -813,  -813,   716,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -124,  -813,  -813,
    -123,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,   -66,  -813,   881,  -813,
    -813,  -813,  -813,  -813,  1062,  -813,  -813,  -813,  -813,  1279,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,   -35,  -813,  1012,
    -813,  -813,  -813,  -813,  1214,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,   114,  -813,  -813,  -813,   120,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,   942,  -813,  -813,  -813,  -813,
    -813,   -37,  -813,  -813,  -813,  -813,  -813,   -34,  -813,  -813,
    1321,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,  -813,
    -813,  -813,  -813,  1193,  -813,  -813,  -813,  -813,  -813,  -813,
    -813
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint16 yytable[] =
{
     625,   626,   785,   130,  1343,  1298,    49,   632,   305,  1299,
      70,  1305,   138,   534,   525,    50,   379,    47,    48,   139,
     140,   141,   399,    55,   142,    70,   130,   379,   386,   471,
     131,   143,   472,   525,  1311,  1300,   566,   607,   294,  1301,
     144,   145,   146,    57,   147,  1123,  1124,  1125,   729,   148,
     149,   732,    71,   131,   306,  1447,   150,   598,   567,  1448,
     151,   776,   777,   152,   153,    72,   154,    71,   749,  1451,
     294,   307,   155,  1452,    62,   535,   757,    63,   267,    66,
      72,   387,   473,   598,  1453,   474,   767,   768,  1454,   770,
    1456,   156,   157,   308,  1457,   309,   158,   310,   311,   782,
     783,   132,   786,   159,    67,   536,   607,   160,   161,   162,
     122,   537,   163,   125,   380,   164,   165,   312,   566,   128,
     471,   778,   779,   472,   132,   380,   166,   534,   399,   129,
    1471,   137,   167,   168,  1472,   169,   170,   171,   172,    73,
     567,   475,   268,   269,   270,   271,   272,   273,   274,   275,
     173,   400,  1473,   263,    73,   264,  1474,   388,   476,   174,
     265,   175,   176,  1344,   177,   295,   608,   178,   179,   266,
     568,   180,   784,   473,   386,   538,   474,  1268,  1269,   526,
     856,   381,   181,   301,   857,   304,   599,   401,   350,   535,
     347,   276,   381,   389,   348,  1526,   296,   295,   526,  1527,
    1528,   569,   182,   183,  1529,   184,   858,   859,  1306,   185,
     527,    79,   599,   186,   187,   188,   189,   190,   402,   536,
     919,   191,   192,   860,    80,   537,   277,   387,   296,   527,
     193,  1312,   475,   609,   349,   608,   351,   861,  1533,  1531,
    1534,  1548,   862,  1532,  1567,  1549,   352,    81,  1568,   476,
      82,    83,   568,   600,   863,   355,    84,   400,    85,  1535,
     356,   864,   194,  1536,   195,   357,   865,   358,   866,   359,
     196,   528,   360,   197,   377,   397,   361,   198,   362,   600,
     582,   867,   199,   569,   469,   832,   477,   614,   712,   538,
     528,   363,   364,   401,   726,   640,   618,   353,   365,   619,
     718,   799,   609,   388,   366,   825,   367,   278,   911,   868,
     563,  1302,  1303,  1304,   601,   869,    86,    87,   641,   642,
     368,   369,   370,   371,   402,   372,    88,    89,   322,   643,
     373,   870,   374,   486,   378,  1537,   669,   871,   670,   389,
     601,   671,   279,   395,   545,   396,   672,    90,    91,   872,
     558,   873,   874,   487,  1015,   937,   875,   560,   408,   488,
     489,   673,   674,   624,    92,    93,   409,   675,   410,   411,
     323,   676,   412,   413,   414,    94,   415,   477,   942,   416,
     620,   417,  1398,   418,    95,  1248,  1249,  1250,  1251,  1252,
     490,   491,   565,   677,   584,   492,   419,   678,   679,  1381,
     420,   615,   953,   954,   955,   956,   957,   421,   422,   493,
     423,   424,   644,   645,   646,   425,   494,   647,   426,   876,
     427,   324,   428,   429,   648,   877,   430,   431,   680,   432,
     681,   433,   434,  1136,   435,   495,   878,   879,   649,   650,
     436,   437,   438,   439,   682,   440,   441,   442,   880,   443,
     445,   447,  1217,   448,   616,   651,   652,   325,   449,  1399,
     326,   327,   450,   496,   497,   683,   451,  1382,   452,   453,
      96,    97,   498,    98,    99,   454,  1383,   455,   456,  1538,
     653,   457,   458,   375,   459,   621,   460,  1384,   461,   462,
     499,   463,   464,  1400,   465,   466,   617,   467,   684,   500,
     501,   468,   624,   328,   546,   329,   547,   548,   549,  1401,
    1385,   550,   685,   842,   843,   844,   845,   846,   847,   848,
     330,   551,   686,   552,   553,   554,  1386,  1265,  1402,  1403,
     555,   138,   502,   503,  1404,  1405,  1406,  1407,   139,   140,
     141,   556,   557,   142,   561,  1387,  1388,   562,   575,  1408,
     143,  1389,  1390,  1391,  1392,   622,   576,   623,   577,   144,
     145,   146,   578,   147,   579,   331,  1393,   988,   148,   149,
     580,   581,   627,   585,   586,   150,   587,   322,   588,   151,
     589,   590,   152,   153,   591,   154,   305,   687,   592,   593,
     504,   155,   594,   595,   332,   333,   628,   629,   630,   631,
     596,   633,   688,   634,   635,   820,   636,   637,  1010,   638,
     156,   157,   639,   710,   711,   158,  1255,   714,   728,   323,
     720,   715,   159,   721,  1263,  1264,   160,   161,   162,   716,
     717,   163,   306,   722,   164,   165,   730,   723,   724,   731,
     733,   734,   735,   736,   737,   166,   738,   267,   739,   307,
     740,   167,   168,   741,   169,   170,   171,   172,   742,   743,
     744,   745,   746,   747,   752,   748,   753,   750,   751,   173,
     324,   308,   754,   309,   755,   310,   311,   756,   174,   758,
     175,   176,   759,   177,   760,   761,   178,   179,   762,   763,
     180,   764,   765,   766,   769,   312,   773,   771,   772,   856,
     774,   181,   784,   857,   775,   780,   325,   781,   792,   326,
     327,   268,   269,   270,   271,   272,   273,   274,   275,   787,
     788,   182,   183,   794,   184,   858,   859,   795,   185,   834,
     789,   790,   186,   187,   188,   189,   190,   797,   791,   798,
     191,   192,   860,   801,   802,   803,   827,   804,   805,   193,
     806,   835,   328,   836,   329,  1550,   861,   837,   808,   809,
     276,   862,   838,   810,   839,   811,   812,   813,   840,   330,
     841,   814,   849,   863,   815,   640,   850,   851,   816,   853,
     864,   194,   817,   195,   818,   865,   819,   866,   854,   196,
     822,   913,   197,   914,  1551,   277,   198,   852,   641,   642,
     867,   199,   824,   829,   830,   916,   915,   921,  1552,   643,
     855,   831,   907,   920,   331,   923,   669,   917,   670,   908,
     909,   671,   910,   918,   922,  1553,   672,    79,   868,   924,
     925,   926,  1554,   927,   869,   928,   929,  1555,   486,  1556,
      80,   673,   674,   332,   333,   930,   931,   675,   934,   932,
     870,   676,  1557,   933,   936,   939,   871,   940,   487,  1137,
     944,  1295,   945,    81,   488,   489,    82,    83,   872,   946,
     873,   874,    84,   677,    85,   875,   278,   678,   679,   947,
     975,   948,  1012,   949,  1013,   950,  1558,  1016,  1017,   976,
     951,   952,   644,   645,   646,   490,   491,   647,   960,   961,
     492,   962,  1559,   963,   648,   964,   965,   966,   680,   967,
     681,   279,   968,   977,   493,  1021,   969,   970,   649,   650,
    1560,   494,  1561,  1562,   682,   971,   972,   973,   974,   990,
    1014,  1022,    86,    87,   978,   651,   652,   979,   876,   980,
     495,  1142,    88,    89,   877,   683,  1350,   981,   982,   983,
     984,   985,   986,   987,   991,   878,   879,  1018,   992,   993,
     653,   994,   995,    90,    91,   996,   997,   880,   496,   497,
     998,   999,  1001,  1145,  1002,  1003,  1004,   498,   684,  1005,
      92,    93,  1006,     2,     3,  1007,  1008,  1009,     4,  1019,
    1563,    94,   685,  1020,  1023,   499,  1139,  1458,  1459,  1024,
      95,  1025,   686,  1026,   500,   501,     5,  1564,  1027,  1028,
       6,  1029,  1030,  1031,  1032,  1033,  1034,     7,  1035,  1565,
    1036,  1037,  1135,  1140,  1038,     8,  1039,  1460,  1040,  1041,
    1042,  1043,  1044,     9,  1045,  1461,  1046,   502,   503,  1143,
    1047,  1048,  1049,    10,  1050,  1051,  1138,  1052,  1053,  1054,
    1055,  1056,  1057,  1462,  1058,  1059,    11,    12,  1060,    13,
    1463,  1083,  1106,  1107,  1108,  1109,    14,   687,  1110,  1111,
    1112,  1113,  1114,  1115,  1116,  1117,  1118,  1119,  1120,  1464,
    1121,  1122,   688,    15,  1128,  1129,    96,    97,  1130,    98,
      99,  1131,  1132,  1133,    16,   504,    17,  1134,  1144,  1141,
    1146,  1148,  1149,  1147,  1150,  1151,  1152,  1465,  1466,  1153,
    1154,  1155,    18,  1156,  1157,  1158,  1467,  1061,  1062,  1063,
    1064,  1065,  1159,  1066,  1067,  1160,  1068,  1069,  1070,  1071,
      19,  1161,  1072,  1162,  1163,  1164,  1165,  1166,  1167,  1168,
    1171,  1172,  1073,  1074,  1075,  1076,  1077,  1078,  1173,  1174,
    1079,  1175,  1176,  1080,  1177,  1178,  1468,  1179,  1180,  1181,
    1182,  1183,    20,  1184,  1185,  1193,  1219,  1253,  1186,  1220,
    1221,    21,    22,  1187,  1241,  1194,  1188,  1469,    23,    24,
    1084,  1085,  1086,  1087,  1088,  1189,  1089,  1090,  1190,  1091,
    1092,  1093,  1094,  1191,  1192,  1095,  1243,  1245,  1195,  1196,
    1197,  1199,  1200,  1201,  1202,  1096,  1097,  1098,  1099,  1100,
    1101,  1203,  1204,  1102,  1205,  1206,  1103,  1501,  1502,  1503,
    1504,  1505,  1207,  1506,  1507,  1222,  1508,  1509,  1510,  1511,
    1208,  1209,  1512,  1254,  1210,  1211,  1212,  1214,  1215,  1216,
    1223,  1256,  1513,  1514,  1515,  1516,  1517,  1518,  1257,  1224,
    1519,  1225,  1226,  1520,  1227,  1258,  1228,  1229,  1230,  1231,
    1232,  1233,  1234,  1235,  1236,  1237,  1238,  1239,  1240,  1259,
    1261,  1244,  1260,  1242,  1262,  1246,  1247,  1270,  1267,  1266,
    1271,  1272,  1273,  1274,  1275,  1276,  1277,  1278,  1279,  1280,
    1281,  1282,  1285,  1283,  1284,  1286,  1287,  1322,  1288,  1289,
    1290,  1291,  1292,  1293,  1339,  1349,  1294,  1309,  1310,  1315,
    1316,  1317,  1318,  1319,  1320,  1321,  1326,  1327,  1328,  1329,
    1330,  1331,  1332,  1333,  1334,  1335,  1336,  1337,  1338,  1342,
    1347,  1348,  1353,  1354,  1363,  1357,  1366,  1370,  1372,  1374,
    1352,  1355,  1434,  1356,  1358,  1359,  1360,  1361,  1362,  1364,
    1365,  1367,  1368,  1369,  1371,  1373,  1376,  1375,  1377,  1378,
    1379,  1380,  1396,  1475,  1397,  1483,  1411,  1412,  1413,  1414,
    1415,   564,  1416,  1417,  1418,  1419,  1420,  1421,   354,  1422,
    1574,  1423,  1424,  1425,  1426,  1575,  1218,  1427,  1573,   989,
    1428,  1429,  1430,  1546,  1431,   597,   833,  1544,   719,  1476,
    1543,   912,  1569,  1570,   943,  1011,  1545,  1571,  1572,   938,
     821,   826,   398,  1540,   470,  1450,   727,  1542,  1541,  1449,
     800,   376,     0,  1432,  1433,  1438,  1439,  1440,     0,  1441,
    1442,  1443,  1444,  1445,  1446,  1477,  1478,  1479,  1480,  1481,
       0,     0,     0,  1482,   713,     0,  1487,     0,  1488,  1489,
    1490,  1491,  1492,  1493,  1494,  1495,  1496,  1497,  1498,  1499,
    1500,  1523,  1524,  1525,     0,     0,     0,     0,     0,     0,
       0,     0,   559,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   583
};

static const yytype_int16 yycheck[] =
{
     361,   362,   462,     1,    86,   272,   274,   368,     1,   276,
       1,    12,     1,     1,     1,   274,     1,   272,   273,     8,
       9,    10,     1,   274,    13,     1,     1,     1,     1,     1,
      28,    20,     4,     1,    12,   272,     1,     1,     1,   276,
      29,    30,    31,   274,    33,    15,    16,    17,   409,    38,
      39,   412,    43,    28,    47,   272,    45,     1,    23,   276,
      49,   207,   208,    52,    53,    56,    55,    43,   429,   272,
       1,    64,    61,   276,   274,    63,   437,   274,     1,   274,
      56,    54,    54,     1,   272,    57,   447,   448,   276,   450,
     272,    80,    81,    86,   276,    88,    85,    90,    91,   460,
     461,    99,   463,    92,   274,    93,     1,    96,    97,    98,
     164,    99,   101,   164,    99,   104,   105,   110,     1,   274,
       1,   207,   208,     4,    99,    99,   115,     1,     1,   274,
     272,   274,   121,   122,   276,   124,   125,   126,   127,   130,
      23,   113,    65,    66,    67,    68,    69,    70,    71,    72,
     139,   130,   272,   274,   130,   274,   276,   130,   130,   148,
     274,   150,   151,   245,   153,   128,   130,   156,   157,   274,
     135,   160,   142,    54,     1,   163,    57,   227,   228,   166,
       1,   166,   171,   164,     5,   274,   130,   166,   275,    63,
     274,   114,   166,   166,   274,   272,   159,   128,   166,   276,
     272,   166,   191,   192,   276,   194,    27,    28,   209,   198,
     197,     1,   130,   202,   203,   204,   205,   206,   197,    93,
     581,   210,   211,    44,    14,    99,   149,    54,   159,   197,
     219,   209,   113,   197,   272,   130,   275,    58,    11,   272,
      13,   272,    63,   276,   272,   276,   275,    37,   276,   130,
      40,    41,   135,   197,    75,   275,    46,   130,    48,    32,
     275,    82,   251,    36,   253,   275,    87,   275,    89,   275,
     259,   258,   275,   262,   274,   273,   275,   266,   275,   197,
     273,   102,   271,   166,   273,   273,   258,   164,   273,   163,
     258,   275,   275,   166,   273,     1,   207,   273,   275,   207,
     273,   273,   197,   130,   275,   273,   275,   230,   273,   130,
     273,  1123,  1124,  1125,   258,   136,   106,   107,    24,    25,
     275,   275,   275,   275,   197,   275,   116,   117,     1,    35,
     275,   152,   275,     1,   274,   108,     1,   158,     3,   166,
     258,     6,   265,   275,   272,   275,    11,   137,   138,   170,
     273,   172,   173,    21,   715,   273,   177,   272,   275,    27,
      28,    26,    27,   142,   154,   155,   275,    32,   275,   275,
      43,    36,   275,   275,   275,   165,   275,   258,   273,   275,
     142,   275,   102,   275,   174,   953,   954,   955,   956,   957,
      58,    59,   274,    58,   272,    63,   275,    62,    63,   102,
     275,   164,   181,   182,   183,   184,   185,   275,   275,    77,
     275,   275,   118,   119,   120,   275,    84,   123,   275,   240,
     275,    94,   275,   275,   130,   246,   275,   275,    93,   275,
      95,   275,   275,   794,   275,   103,   257,   258,   144,   145,
     275,   275,   275,   275,   109,   275,   275,   275,   269,   275,
     275,   275,   273,   275,   164,   161,   162,   130,   275,   179,
     133,   134,   275,   131,   132,   130,   275,   170,   275,   275,
     260,   261,   140,   263,   264,   275,   179,   275,   275,   252,
     186,   275,   275,   273,   275,   142,   275,   190,   275,   275,
     158,   275,   275,   213,   275,   275,   272,   275,   163,   167,
     168,   275,   142,   176,   275,   178,   275,   275,   275,   229,
     213,   275,   177,   231,   232,   233,   234,   235,   236,   237,
     193,   275,   187,   275,   275,   275,   229,   987,   248,   249,
     275,     1,   200,   201,   254,   255,   256,   257,     8,     9,
      10,   275,   275,    13,   275,   248,   249,   275,   275,   269,
      20,   254,   255,   256,   257,   207,   275,   207,   275,    29,
      30,    31,   275,    33,   275,   238,   269,   273,    38,    39,
     275,   275,   142,   275,   275,    45,   275,     1,   275,    49,
     275,   275,    52,    53,   275,    55,     1,   252,   275,   275,
     258,    61,   275,   275,   267,   268,   142,   207,   207,   142,
     273,   207,   267,   207,   207,   273,   207,   207,   273,   207,
      80,    81,   272,   275,   275,    85,   977,   272,   207,    43,
     164,   275,    92,   164,   985,   986,    96,    97,    98,   275,
     275,   101,    47,   272,   104,   105,   207,   275,   275,   207,
     164,   164,   164,   142,   164,   115,   142,     1,   207,    64,
     207,   121,   122,   207,   124,   125,   126,   127,   142,   164,
     207,   142,   142,   142,   142,   207,   164,   207,   207,   139,
      94,    86,   207,    88,   142,    90,    91,   142,   148,   142,
     150,   151,   164,   153,   142,   142,   156,   157,   207,   207,
     160,   275,   207,   275,   207,   110,   207,   164,   164,     1,
     207,   171,   142,     5,   207,   207,   130,   207,   272,   133,
     134,    65,    66,    67,    68,    69,    70,    71,    72,   207,
     207,   191,   192,   275,   194,    27,    28,   275,   198,   164,
     207,   207,   202,   203,   204,   205,   206,   275,   207,   275,
     210,   211,    44,   272,   275,   275,   272,   275,   275,   219,
     275,   164,   176,   164,   178,     5,    58,   164,   275,   275,
     114,    63,   164,   275,   164,   275,   275,   275,   164,   193,
     164,   275,   164,    75,   275,     1,   164,   207,   275,   164,
      82,   251,   275,   253,   275,    87,   275,    89,   164,   259,
     275,   207,   262,   207,    44,   149,   266,   272,    24,    25,
     102,   271,   275,   275,   275,   164,   207,   164,    58,    35,
     272,   275,   272,   272,   238,   164,     1,   207,     3,   275,
     275,     6,   275,   207,   207,    75,    11,     1,   130,   164,
     164,   164,    82,   164,   136,   164,   142,    87,     1,    89,
      14,    26,    27,   267,   268,   164,   164,    32,   275,   272,
     152,    36,   102,   272,   275,   272,   158,   275,    21,   207,
     272,   169,   272,    37,    27,    28,    40,    41,   170,   272,
     172,   173,    46,    58,    48,   177,   230,    62,    63,   272,
     275,   272,   164,   272,   164,   272,   136,   164,   164,   275,
     272,   272,   118,   119,   120,    58,    59,   123,   272,   272,
      63,   272,   152,   272,   130,   272,   272,   272,    93,   272,
      95,   265,   272,   275,    77,   164,   272,   272,   144,   145,
     170,    84,   172,   173,   109,   272,   272,   272,   272,   272,
     272,   164,   106,   107,   275,   161,   162,   275,   240,   275,
     103,   207,   116,   117,   246,   130,   276,   275,   275,   275,
     275,   275,   275,   275,   275,   257,   258,   272,   275,   275,
     186,   275,   275,   137,   138,   275,   275,   269,   131,   132,
     275,   275,   275,   207,   275,   275,   275,   140,   163,   275,
     154,   155,   275,     0,     1,   275,   275,   275,     5,   272,
     240,   165,   177,   272,   275,   158,   164,    21,    22,   272,
     174,   272,   187,   272,   167,   168,    23,   257,   272,   272,
      27,   272,   272,   272,   272,   272,   272,    34,   272,   269,
     272,   272,   275,   164,   272,    42,   272,    51,   272,   272,
     272,   272,   272,    50,   272,    59,   272,   200,   201,   164,
     272,   272,   272,    60,   272,   272,   275,   272,   272,   272,
     272,   272,   272,    77,   272,   272,    73,    74,   272,    76,
      84,   272,   272,   272,   272,   272,    83,   252,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   103,
     272,   272,   267,   100,   272,   272,   260,   261,   272,   263,
     264,   272,   272,   272,   111,   258,   113,   272,   164,   272,
     207,   207,   207,   275,   207,   207,   207,   131,   132,   207,
     164,   142,   129,   164,   164,   207,   140,   214,   215,   216,
     217,   218,   164,   220,   221,   272,   223,   224,   225,   226,
     147,   164,   229,   275,   164,   272,   275,   164,   164,   142,
     272,   272,   239,   240,   241,   242,   243,   244,   272,   272,
     247,   272,   272,   250,   272,   272,   180,   272,   272,   272,
     272,   272,   179,   272,   272,   275,   164,   142,   272,   164,
     164,   188,   189,   272,   164,   275,   272,   201,   195,   196,
     214,   215,   216,   217,   218,   272,   220,   221,   272,   223,
     224,   225,   226,   272,   272,   229,   164,   164,   275,   275,
     275,   275,   275,   275,   275,   239,   240,   241,   242,   243,
     244,   275,   275,   247,   275,   275,   250,   214,   215,   216,
     217,   218,   275,   220,   221,   272,   223,   224,   225,   226,
     275,   275,   229,   142,   275,   275,   275,   275,   275,   275,
     272,   142,   239,   240,   241,   242,   243,   244,   142,   272,
     247,   272,   272,   250,   272,   142,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   142,
     142,   272,   164,   275,   142,   275,   272,   207,   164,   272,
     164,   164,   207,   207,   207,   164,   275,   164,   164,   164,
     164,   142,   207,   164,   164,   164,   272,   141,   272,   272,
     272,   272,   272,   272,   169,   212,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   164,   164,   164,   275,   164,   164,   275,   164,
     207,   207,   141,   207,   207,   207,   207,   207,   207,   207,
     207,   207,   207,   207,   207,   207,   272,   207,   272,   272,
     272,   272,   272,   142,   272,   141,   272,   272,   272,   272,
     272,   297,   272,   272,   272,   272,   272,   272,    74,   272,
    1549,   272,   272,   272,   272,  1568,   881,   272,  1547,   654,
     272,   272,   272,  1474,   272,   334,   540,  1457,   390,  1350,
    1455,   570,  1527,  1529,   610,   689,  1472,  1530,  1532,   602,
     505,   530,   133,  1448,   200,  1301,   404,  1454,  1452,  1299,
     478,   100,    -1,   272,   272,   272,   272,   272,    -1,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
      -1,    -1,    -1,   272,   382,    -1,   272,    -1,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   280,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   313
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,   278,     0,     1,     5,    23,    27,    34,    42,    50,
      60,    73,    74,    76,    83,   100,   111,   113,   129,   147,
     179,   188,   189,   195,   196,   279,   284,   289,   296,   310,
     316,   331,   370,   389,   403,   431,   438,   448,   457,   488,
     498,   504,   509,   519,   589,   605,   628,   272,   273,   274,
     274,   371,   458,   499,   290,   274,   510,   274,   590,   404,
     489,   390,   274,   274,   332,   432,   274,   274,   439,   449,
       1,    43,    56,   130,   311,   312,   313,   314,   315,     1,
      14,    37,    40,    41,    46,    48,   106,   107,   116,   117,
     137,   138,   154,   155,   165,   174,   260,   261,   263,   264,
     606,   607,   608,   609,   610,   611,   612,   613,   614,   615,
     616,   617,   618,   619,   620,   621,   622,   623,   624,   625,
     626,   627,   164,   372,   376,   164,   459,   463,   274,   274,
       1,    28,    99,   505,   506,   507,   508,   274,     1,     8,
       9,    10,    13,    20,    29,    30,    31,    33,    38,    39,
      45,    49,    52,    53,    55,    61,    80,    81,    85,    92,
      96,    97,    98,   101,   104,   105,   115,   121,   122,   124,
     125,   126,   127,   139,   148,   150,   151,   153,   156,   157,
     160,   171,   191,   192,   194,   198,   202,   203,   204,   205,
     206,   210,   211,   219,   251,   253,   259,   262,   266,   271,
     520,   521,   522,   523,   524,   525,   526,   527,   528,   529,
     530,   531,   532,   533,   534,   535,   536,   537,   538,   539,
     540,   541,   542,   543,   544,   545,   546,   547,   548,   549,
     550,   551,   552,   553,   554,   555,   556,   557,   558,   559,
     560,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,   571,   572,   573,   574,   575,   576,   580,   584,   585,
     586,   587,   588,   274,   274,   274,   274,     1,    65,    66,
      67,    68,    69,    70,    71,    72,   114,   149,   230,   265,
     317,   318,   319,   320,   321,   322,   323,   324,   325,   326,
     327,   328,   329,   330,     1,   128,   159,   285,   286,   287,
     288,   164,   333,   337,   274,     1,    47,    64,    86,    88,
      90,    91,   110,   629,   630,   631,   632,   633,   634,   635,
     636,   637,     1,    43,    94,   130,   133,   134,   176,   178,
     193,   238,   267,   268,   297,   298,   299,   300,   301,   302,
     303,   304,   305,   306,   307,   308,   309,   274,   274,   272,
     275,   275,   275,   273,   312,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   273,   607,   274,   274,     1,
      99,   166,   500,   501,   502,   503,     1,    54,   130,   166,
     291,   292,   293,   294,   295,   275,   275,   273,   506,     1,
     130,   166,   197,   511,   515,   516,   517,   518,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   581,   275,   577,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   273,
     521,     1,     4,    54,    57,   113,   130,   258,   591,   592,
     593,   594,   595,   599,   600,   601,     1,    21,    27,    28,
      58,    59,    63,    77,    84,   103,   131,   132,   140,   158,
     167,   168,   200,   201,   258,   405,   406,   407,   408,   409,
     410,   411,   412,   413,   420,   421,   422,   423,   424,   425,
     426,   427,   428,   429,   430,     1,   166,   197,   258,   490,
     494,   495,   496,   497,     1,    63,    93,    99,   163,   391,
     395,   396,   397,   401,   402,   272,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   273,   318,
     272,   275,   275,   273,   286,   274,     1,    23,   135,   166,
     433,   434,   435,   436,   437,   275,   275,   275,   275,   275,
     275,   275,   273,   630,   272,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   273,   298,     1,   130,
     197,   258,   440,   441,   442,   443,   444,     1,   130,   197,
     450,   451,   452,   453,   164,   164,   164,   272,   207,   207,
     142,   142,   207,   207,   142,   281,   281,   142,   142,   207,
     207,   142,   281,   207,   207,   207,   207,   207,   207,   272,
       1,    24,    25,    35,   118,   119,   120,   123,   130,   144,
     145,   161,   162,   186,   373,   374,   375,   377,   378,   379,
     380,   381,   382,   383,   384,   385,   386,   387,   388,     1,
       3,     6,    11,    26,    27,    32,    36,    58,    62,    63,
      93,    95,   109,   130,   163,   177,   187,   252,   267,   460,
     461,   462,   464,   465,   466,   467,   468,   469,   470,   471,
     478,   479,   480,   481,   482,   483,   484,   485,   486,   487,
     275,   275,   273,   501,   272,   275,   275,   275,   273,   292,
     164,   164,   272,   275,   275,   512,   273,   516,   207,   281,
     207,   207,   281,   164,   164,   164,   142,   164,   142,   207,
     207,   207,   142,   164,   207,   142,   142,   142,   207,   281,
     207,   207,   142,   164,   207,   142,   142,   281,   142,   164,
     142,   142,   207,   207,   275,   207,   275,   281,   281,   207,
     281,   164,   164,   207,   207,   207,   207,   208,   207,   208,
     207,   207,   281,   281,   142,   283,   281,   207,   207,   207,
     207,   207,   272,   602,   275,   275,   596,   275,   275,   273,
     592,   272,   275,   275,   275,   275,   275,   414,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     273,   406,   275,   491,   275,   273,   495,   272,   392,   275,
     275,   275,   273,   396,   164,   164,   164,   164,   164,   164,
     164,   164,   231,   232,   233,   234,   235,   236,   237,   164,
     164,   207,   272,   164,   164,   272,     1,     5,    27,    28,
      44,    58,    63,    75,    82,    87,    89,   102,   130,   136,
     152,   158,   170,   172,   173,   177,   240,   246,   257,   258,
     269,   334,   335,   336,   338,   339,   340,   341,   342,   343,
     344,   348,   349,   350,   351,   352,   353,   354,   355,   356,
     357,   358,   359,   360,   361,   362,   363,   272,   275,   275,
     275,   273,   434,   207,   207,   207,   164,   207,   207,   281,
     272,   164,   207,   164,   164,   164,   164,   164,   164,   142,
     164,   164,   272,   272,   275,   445,   275,   273,   441,   272,
     275,   454,   273,   451,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   181,   182,   183,   184,   185,   280,   281,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   275,   275,   275,   275,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   273,   374,
     272,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     472,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     273,   461,   164,   164,   272,   281,   164,   164,   272,   272,
     272,   164,   164,   275,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   214,   215,   216,   217,   218,   220,   221,   223,   224,
     225,   226,   229,   239,   240,   241,   242,   243,   244,   247,
     250,   582,   583,   272,   214,   215,   216,   217,   218,   220,
     221,   223,   224,   225,   226,   229,   239,   240,   241,   242,
     243,   244,   247,   250,   578,   579,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,    15,    16,    17,   282,   283,   272,   272,
     272,   272,   272,   272,   272,   275,   281,   207,   275,   164,
     164,   272,   207,   164,   164,   207,   207,   275,   207,   207,
     207,   207,   207,   207,   164,   142,   164,   164,   207,   164,
     272,   164,   275,   164,   272,   275,   164,   164,   142,   399,
     400,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   275,   275,   275,   275,   275,   364,   275,
     275,   275,   275,   275,   275,   275,   275,   275,   275,   275,
     275,   275,   275,   345,   275,   275,   275,   273,   335,   164,
     164,   164,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   164,   275,   164,   272,   164,   275,   272,   280,   280,
     280,   280,   280,   142,   142,   281,   142,   142,   142,   142,
     164,   142,   142,   281,   281,   283,   272,   164,   227,   228,
     207,   164,   164,   207,   207,   207,   164,   275,   164,   164,
     164,   164,   142,   164,   164,   207,   164,   272,   272,   272,
     272,   272,   272,   272,   272,   169,   513,   514,   272,   276,
     272,   276,   282,   282,   282,    12,   209,   603,   604,   272,
     272,    12,   209,   597,   598,   272,   272,   272,   272,   272,
     272,   272,   141,   415,   416,   418,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   169,
     492,   493,   272,    86,   245,   393,   394,   272,   272,   212,
     276,   398,   207,   164,   164,   207,   207,   275,   207,   207,
     207,   207,   207,   164,   207,   207,   164,   207,   207,   207,
     164,   207,   275,   207,   164,   207,   272,   272,   272,   272,
     272,   102,   170,   179,   190,   213,   229,   248,   249,   254,
     255,   256,   257,   269,   446,   447,   272,   272,   102,   179,
     213,   229,   248,   249,   254,   255,   256,   257,   269,   455,
     456,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   141,   473,   474,   476,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   276,   583,
     579,   272,   276,   272,   276,   417,   272,   276,    21,    22,
      51,    59,    77,    84,   103,   131,   132,   140,   180,   201,
     419,   272,   276,   272,   276,   142,   400,   272,   272,   272,
     272,   272,   272,   141,   365,   366,   368,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   214,   215,   216,   217,   218,   220,   221,   223,   224,
     225,   226,   229,   239,   240,   241,   242,   243,   244,   247,
     250,   346,   347,   272,   272,   272,   272,   276,   272,   276,
     475,   272,   276,    11,    13,    32,    36,   108,   252,   477,
     514,   604,   598,   419,   416,   493,   394,   367,   272,   276,
       5,    44,    58,    75,    82,    87,    89,   102,   136,   152,
     170,   172,   173,   240,   257,   269,   369,   272,   276,   447,
     456,   477,   474,   369,   366,   347
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */


/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{


    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 27:

/* Line 1455 of yacc.c  */
#line 440 "ircd_parser.y"
    { (yyval.number) = 0; }
    break;

  case 29:

/* Line 1455 of yacc.c  */
#line 442 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (2)].number) + (yyvsp[(2) - (2)].number);
		}
    break;

  case 30:

/* Line 1455 of yacc.c  */
#line 446 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (3)].number) + (yyvsp[(3) - (3)].number);
		}
    break;

  case 31:

/* Line 1455 of yacc.c  */
#line 450 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (3)].number) * 60 + (yyvsp[(3) - (3)].number);
		}
    break;

  case 32:

/* Line 1455 of yacc.c  */
#line 454 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (3)].number) * 60 * 60 + (yyvsp[(3) - (3)].number);
		}
    break;

  case 33:

/* Line 1455 of yacc.c  */
#line 458 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (3)].number) * 60 * 60 * 24 + (yyvsp[(3) - (3)].number);
		}
    break;

  case 34:

/* Line 1455 of yacc.c  */
#line 462 "ircd_parser.y"
    {
			(yyval.number) = (yyvsp[(1) - (3)].number) * 60 * 60 * 24 * 7 + (yyvsp[(3) - (3)].number);
		}
    break;

  case 35:

/* Line 1455 of yacc.c  */
#line 467 "ircd_parser.y"
    { (yyval.number) = 0; }
    break;

  case 37:

/* Line 1455 of yacc.c  */
#line 468 "ircd_parser.y"
    { (yyval.number) = (yyvsp[(1) - (2)].number) + (yyvsp[(2) - (2)].number); }
    break;

  case 38:

/* Line 1455 of yacc.c  */
#line 469 "ircd_parser.y"
    { (yyval.number) = (yyvsp[(1) - (3)].number) + (yyvsp[(3) - (3)].number); }
    break;

  case 39:

/* Line 1455 of yacc.c  */
#line 470 "ircd_parser.y"
    { (yyval.number) = (yyvsp[(1) - (3)].number) * 1024 + (yyvsp[(3) - (3)].number); }
    break;

  case 40:

/* Line 1455 of yacc.c  */
#line 471 "ircd_parser.y"
    { (yyval.number) = (yyvsp[(1) - (3)].number) * 1024 * 1024 + (yyvsp[(3) - (3)].number); }
    break;

  case 47:

/* Line 1455 of yacc.c  */
#line 485 "ircd_parser.y"
    {
#ifndef STATIC_MODULES /* NOOP in the static case */
  if (ypass == 2)
  {
    char *m_bn;

    m_bn = basename(yylval.string);

    /* I suppose we should just ignore it if it is already loaded(since
     * otherwise we would flood the opers on rehash) -A1kmm.
     */
    add_conf_module(yylval.string);
  }
#endif
}
    break;

  case 48:

/* Line 1455 of yacc.c  */
#line 502 "ircd_parser.y"
    {
#ifndef STATIC_MODULES
  if (ypass == 2)
    mod_add_path(yylval.string);
#endif
}
    break;

  case 49:

/* Line 1455 of yacc.c  */
#line 514 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(DNSBL_TYPE);
    yy_dconf = map_to_conf(yy_conf);
  }
  else
  {
    MyFree(class_name);
    class_name = NULL;
  }
}
    break;

  case 50:

/* Line 1455 of yacc.c  */
#line 526 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_dconf->reason == NULL)
      delete_conf_item(yy_conf);
  }
}
    break;

  case 57:

/* Line 1455 of yacc.c  */
#line 539 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 58:

/* Line 1455 of yacc.c  */
#line 548 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_dconf->duration = (yyvsp[(3) - (4)].number);
}
    break;

  case 59:

/* Line 1455 of yacc.c  */
#line 554 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_dconf->reason);
    DupString(yy_dconf->reason, yylval.string);
  }
}
    break;

  case 75:

/* Line 1455 of yacc.c  */
#line 579 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 2 && ServerInfo.ctx) 
  {
    if (!ServerInfo.rsa_private_key_file)
    {
      yyerror("No rsa_private_key_file specified, SSL disabled");
      break;
    }

    if (SSL_CTX_use_certificate_file(ServerInfo.ctx,
      yylval.string, SSL_FILETYPE_PEM) <= 0)
    {
      yyerror(ERR_lib_error_string(ERR_get_error()));
      break;
    }

    if (SSL_CTX_use_PrivateKey_file(ServerInfo.ctx,
      ServerInfo.rsa_private_key_file, SSL_FILETYPE_PEM) <= 0)
    {
      yyerror(ERR_lib_error_string(ERR_get_error()));
      break;
    }

    if (!SSL_CTX_check_private_key(ServerInfo.ctx))
    {
      yyerror("RSA private key does not match the SSL certificate public key!");
      break;
    }
  }
#endif
}
    break;

  case 76:

/* Line 1455 of yacc.c  */
#line 613 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 1)
  {
    BIO *file;

    if (ServerInfo.rsa_private_key)
    {
      RSA_free(ServerInfo.rsa_private_key);
      ServerInfo.rsa_private_key = NULL;
    }

    if (ServerInfo.rsa_private_key_file)
    {
      MyFree(ServerInfo.rsa_private_key_file);
      ServerInfo.rsa_private_key_file = NULL;
    }

    DupString(ServerInfo.rsa_private_key_file, yylval.string);

    if ((file = BIO_new_file(yylval.string, "r")) == NULL)
    {
      yyerror("File open failed, ignoring");
      break;
    }

    ServerInfo.rsa_private_key = (RSA *)PEM_read_bio_RSAPrivateKey(file, NULL,
      0, NULL);

    (void)BIO_set_close(file, BIO_CLOSE);
    BIO_free(file);

    if (ServerInfo.rsa_private_key == NULL)
    {
      yyerror("Couldn't extract key, ignoring");
      break;
    }

    if (!RSA_check_key(ServerInfo.rsa_private_key))
    {
      RSA_free(ServerInfo.rsa_private_key);
      ServerInfo.rsa_private_key = NULL;

      yyerror("Invalid key, ignoring");
      break;
    }

    /* require 2048 bit (256 byte) key */
    if (RSA_size(ServerInfo.rsa_private_key) != 256)
    {
      RSA_free(ServerInfo.rsa_private_key);
      ServerInfo.rsa_private_key = NULL;

      yyerror("Not a 2048 bit key, ignoring");
    }
  }
#endif
}
    break;

  case 77:

/* Line 1455 of yacc.c  */
#line 673 "ircd_parser.y"
    {
  /* this isn't rehashable */
  if (ypass == 2)
  {
    if (ServerInfo.name == NULL)
    {
      /* the ircd will exit() in main() if we dont set one */
      if (strlen(yylval.string) <= HOSTLEN)
        DupString(ServerInfo.name, yylval.string);
    }
  }
}
    break;

  case 78:

/* Line 1455 of yacc.c  */
#line 687 "ircd_parser.y"
    {
  /* this isn't rehashable */
  if (ypass == 2 && !ServerInfo.sid)
  {
    if (valid_sid(yylval.string))
      DupString(ServerInfo.sid, yylval.string);
    else
    {
      ilog(L_ERROR, "Ignoring config file entry SID -- invalid SID. Aborting.");
      exit(0);
    }
  }
}
    break;

  case 79:

/* Line 1455 of yacc.c  */
#line 702 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ServerInfo.description);
    DupString(ServerInfo.description,yylval.string);
  }
}
    break;

  case 80:

/* Line 1455 of yacc.c  */
#line 711 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    char *p;

    if ((p = strchr(yylval.string, ' ')) != NULL)
      p = '\0';

    MyFree(ServerInfo.network_name);
    DupString(ServerInfo.network_name, yylval.string);
  }
}
    break;

  case 81:

/* Line 1455 of yacc.c  */
#line 725 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ServerInfo.network_desc);
    DupString(ServerInfo.network_desc, yylval.string);
  }
}
    break;

  case 82:

/* Line 1455 of yacc.c  */
#line 734 "ircd_parser.y"
    {
  if (ypass == 2 && *yylval.string != '*')
  {
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;

    if (irc_getaddrinfo(yylval.string, NULL, &hints, &res))
      ilog(L_ERROR, "Invalid netmask for server vhost(%s)", yylval.string);
    else
    {
      assert(res != NULL);

      memcpy(&ServerInfo.ip, res->ai_addr, res->ai_addrlen);
      ServerInfo.ip.ss.ss_family = res->ai_family;
      ServerInfo.ip.ss_len = res->ai_addrlen;
      irc_freeaddrinfo(res);

      ServerInfo.specific_ipv4_vhost = 1;
    }
  }
}
    break;

  case 83:

/* Line 1455 of yacc.c  */
#line 762 "ircd_parser.y"
    {
#ifdef IPV6
  if (ypass == 2 && *yylval.string != '*')
  {
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;

    if (irc_getaddrinfo(yylval.string, NULL, &hints, &res))
      ilog(L_ERROR, "Invalid netmask for server vhost6(%s)", yylval.string);
    else
    {
      assert(res != NULL);

      memcpy(&ServerInfo.ip6, res->ai_addr, res->ai_addrlen);
      ServerInfo.ip6.ss.ss_family = res->ai_family;
      ServerInfo.ip6.ss_len = res->ai_addrlen;
      irc_freeaddrinfo(res);

      ServerInfo.specific_ipv6_vhost = 1;
    }
  }
#endif
}
    break;

  case 84:

/* Line 1455 of yacc.c  */
#line 792 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    recalc_fdlimit(NULL);

    if ((yyvsp[(3) - (4)].number) < MAXCLIENTS_MIN)
    {
      char buf[IRCD_BUFSIZE];
      ircsprintf(buf, "MAXCLIENTS too low, setting to %d", MAXCLIENTS_MIN);
      yyerror(buf);
    }
    else if ((yyvsp[(3) - (4)].number) > MAXCLIENTS_MAX)
    {
      char buf[IRCD_BUFSIZE];
      ircsprintf(buf, "MAXCLIENTS too high, setting to %d", MAXCLIENTS_MAX);
      yyerror(buf);
    }
    else
      ServerInfo.max_clients = (yyvsp[(3) - (4)].number);
  }
}
    break;

  case 85:

/* Line 1455 of yacc.c  */
#line 815 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
    {
      /* Don't become a hub if we have a lazylink active. */
      if (!ServerInfo.hub && uplink && IsCapable(uplink, CAP_LL))
      {
        sendto_realops_flags(UMODE_ALL, L_ALL,
                             "Ignoring config file line hub=yes; "
                             "due to active LazyLink (%s)", uplink->name);
      }
      else
      {
        ServerInfo.hub = 1;
        uplink = NULL;
        delete_capability("HUB");
        add_capability("HUB", CAP_HUB, 1);
      }
    }
    else if (ServerInfo.hub)
    {
      dlink_node *ptr = NULL;

      ServerInfo.hub = 0;
      delete_capability("HUB");

      /* Don't become a leaf if we have a lazylink active. */
      DLINK_FOREACH(ptr, serv_list.head)
      {
        const struct Client *acptr = ptr->data;
        if (MyConnect(acptr) && IsCapable(acptr, CAP_LL))
        {
          sendto_realops_flags(UMODE_ALL, L_ALL,
                               "Ignoring config file line hub=no; "
                               "due to active LazyLink (%s)",
                               acptr->name);
          add_capability("HUB", CAP_HUB, 1);
          ServerInfo.hub = 1;
          break;
        }
      }
    }
  }
}
    break;

  case 93:

/* Line 1455 of yacc.c  */
#line 871 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(AdminInfo.name);
    DupString(AdminInfo.name, yylval.string);
  }
}
    break;

  case 94:

/* Line 1455 of yacc.c  */
#line 880 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(AdminInfo.email);
    DupString(AdminInfo.email, yylval.string);
  }
}
    break;

  case 95:

/* Line 1455 of yacc.c  */
#line 889 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(AdminInfo.description);
    DupString(AdminInfo.description, yylval.string);
  }
}
    break;

  case 112:

/* Line 1455 of yacc.c  */
#line 916 "ircd_parser.y"
    {
                        }
    break;

  case 113:

/* Line 1455 of yacc.c  */
#line 920 "ircd_parser.y"
    {
                        }
    break;

  case 114:

/* Line 1455 of yacc.c  */
#line 924 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.userlog, yylval.string,
            sizeof(ConfigLoggingEntry.userlog));
}
    break;

  case 115:

/* Line 1455 of yacc.c  */
#line 931 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.failed_operlog, yylval.string,
            sizeof(ConfigLoggingEntry.failed_operlog));
}
    break;

  case 116:

/* Line 1455 of yacc.c  */
#line 938 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.operlog, yylval.string,
            sizeof(ConfigLoggingEntry.operlog));
}
    break;

  case 117:

/* Line 1455 of yacc.c  */
#line 945 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.operspylog, yylval.string,
            sizeof(ConfigLoggingEntry.operspylog));
}
    break;

  case 118:

/* Line 1455 of yacc.c  */
#line 952 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.glinelog, yylval.string,
            sizeof(ConfigLoggingEntry.glinelog));
}
    break;

  case 119:

/* Line 1455 of yacc.c  */
#line 959 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.klinelog, yylval.string,
            sizeof(ConfigLoggingEntry.klinelog));
}
    break;

  case 120:

/* Line 1455 of yacc.c  */
#line 966 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.ioerrlog, yylval.string,
            sizeof(ConfigLoggingEntry.ioerrlog));
}
    break;

  case 121:

/* Line 1455 of yacc.c  */
#line 973 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(ConfigLoggingEntry.killlog, yylval.string,
            sizeof(ConfigLoggingEntry.killlog));
}
    break;

  case 122:

/* Line 1455 of yacc.c  */
#line 980 "ircd_parser.y"
    { 
  if (ypass == 2)
    set_log_level(L_CRIT);
}
    break;

  case 123:

/* Line 1455 of yacc.c  */
#line 984 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_ERROR);
}
    break;

  case 124:

/* Line 1455 of yacc.c  */
#line 988 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_WARN);
}
    break;

  case 125:

/* Line 1455 of yacc.c  */
#line 992 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_NOTICE);
}
    break;

  case 126:

/* Line 1455 of yacc.c  */
#line 996 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_TRACE);
}
    break;

  case 127:

/* Line 1455 of yacc.c  */
#line 1000 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_INFO);
}
    break;

  case 128:

/* Line 1455 of yacc.c  */
#line 1004 "ircd_parser.y"
    {
  if (ypass == 2)
    set_log_level(L_DEBUG);
}
    break;

  case 129:

/* Line 1455 of yacc.c  */
#line 1010 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigLoggingEntry.use_logging = yylval.number;
}
    break;

  case 130:

/* Line 1455 of yacc.c  */
#line 1019 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(OPER_TYPE);
    yy_aconf = map_to_conf(yy_conf);
    SetConfEncrypted(yy_aconf); /* Yes, the default is encrypted */
  }
  else
  {
    MyFree(class_name);
    class_name = NULL;
  }
}
    break;

  case 131:

/* Line 1455 of yacc.c  */
#line 1032 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp;
    dlink_node *ptr;
    dlink_node *next_ptr;

    if (yy_aconf->user && yy_aconf->host)
      conf_add_class_to_conf(yy_conf, class_name);
    else
      delete_conf_item(yy_conf);

    /* Now, make sure there is a copy of the "base" given oper
     * block in each of the collected copies
     */

    DLINK_FOREACH_SAFE(ptr, next_ptr, col_conf_list.head)
    {
      struct AccessItem *new_aconf;
      struct ConfItem *new_conf;
      yy_tmp = ptr->data;

      new_conf = make_conf_item(OPER_TYPE);
      new_aconf = (struct AccessItem *)map_to_conf(new_conf);

      new_aconf->flags = yy_aconf->flags;

      if (yy_conf->name != NULL)
        DupString(new_conf->name, yy_conf->name);
      if (yy_tmp->user != NULL)
	DupString(new_aconf->user, yy_tmp->user);
      else
	DupString(new_aconf->user, "*");
      if (yy_tmp->host != NULL)
	DupString(new_aconf->host, yy_tmp->host);
      else
	DupString(new_aconf->host, "*");
      conf_add_class_to_conf(new_conf, class_name);
      if (yy_aconf->passwd != NULL)
        DupString(new_aconf->passwd, yy_aconf->passwd);

      new_aconf->port = yy_aconf->port;
#ifdef HAVE_LIBCRYPTO
      if (yy_aconf->rsa_public_key_file != NULL)
      {
        BIO *file;

        DupString(new_aconf->rsa_public_key_file,
		  yy_aconf->rsa_public_key_file);

        file = BIO_new_file(yy_aconf->rsa_public_key_file, "r");
        new_aconf->rsa_public_key = (RSA *)PEM_read_bio_RSA_PUBKEY(file, 
							   NULL, 0, NULL);
        (void)BIO_set_close(file, BIO_CLOSE);
        BIO_free(file);
      }
      if (yy_aconf->certfp != NULL)
      {
        new_aconf->certfp = MyMalloc(SHA_DIGEST_LENGTH);
        memcpy(new_aconf->certfp, yy_aconf->certfp, SHA_DIGEST_LENGTH);
      }
#endif

#ifdef HAVE_LIBCRYPTO
      if (yy_tmp->name && (yy_tmp->passwd || yy_aconf->rsa_public_key)
	  && yy_tmp->host)
#else
      if (yy_tmp->name && yy_tmp->passwd && yy_tmp->host)
#endif
      {
        conf_add_class_to_conf(new_conf, class_name);
	if (yy_tmp->name != NULL)
	  DupString(new_conf->name, yy_tmp->name);
      }

      dlinkDelete(&yy_tmp->node, &col_conf_list);
      free_collect_item(yy_tmp);
    }

    yy_conf = NULL;
    yy_aconf = NULL;


    MyFree(class_name);
    class_name = NULL;
  }
}
    break;

  case 161:

/* Line 1455 of yacc.c  */
#line 1132 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (strlen(yylval.string) > OPERNICKLEN)
      yylval.string[OPERNICKLEN] = '\0';

    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 162:

/* Line 1455 of yacc.c  */
#line 1144 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (strlen(yylval.string) > OPERNICKLEN)
      yylval.string[OPERNICKLEN] = '\0';

    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 163:

/* Line 1455 of yacc.c  */
#line 1156 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct split_nuh_item nuh;

    nuh.nuhmask  = yylval.string;
    nuh.nickptr  = NULL;
    nuh.userptr  = userbuf;
    nuh.hostptr  = hostbuf;
    
    nuh.nicksize = 0;
    nuh.usersize = sizeof(userbuf);
    nuh.hostsize = sizeof(hostbuf);

    split_nuh(&nuh);

    if (yy_aconf->user == NULL)
    {
      DupString(yy_aconf->user, userbuf);
      DupString(yy_aconf->host, hostbuf);
    }
    else
    {
      struct CollectItem *yy_tmp = MyMalloc(sizeof(struct CollectItem));

      DupString(yy_tmp->user, userbuf);
      DupString(yy_tmp->host, hostbuf);

      dlinkAdd(yy_tmp, &yy_tmp->node, &col_conf_list);
    }
  }
}
    break;

  case 164:

/* Line 1455 of yacc.c  */
#line 1190 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    char tmp[SHA_DIGEST_LENGTH];
    
    if(yy_aconf->certfp != NULL)
      MyFree(yy_aconf->certfp);

    if(base16_decode(tmp, SHA_DIGEST_LENGTH, yylval.string, strlen(yylval.string)) != 0)
    {
      yyerror("Invalid client certificate fingerprint provided. Ignoring");
      break;
    }
    yy_aconf->certfp = MyMalloc(SHA_DIGEST_LENGTH);
    memcpy(yy_aconf->certfp, tmp, SHA_DIGEST_LENGTH);
  }
}
    break;

  case 165:

/* Line 1455 of yacc.c  */
#line 1209 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_aconf->passwd != NULL)
      memset(yy_aconf->passwd, 0, strlen(yy_aconf->passwd));

    MyFree(yy_aconf->passwd);
    DupString(yy_aconf->passwd, yylval.string);
  }
}
    break;

  case 166:

/* Line 1455 of yacc.c  */
#line 1221 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      SetConfEncrypted(yy_aconf);
    else
      ClearConfEncrypted(yy_aconf);
  }
}
    break;

  case 167:

/* Line 1455 of yacc.c  */
#line 1232 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 2)
  {
    BIO *file;

    if (yy_aconf->rsa_public_key != NULL)
    {
      RSA_free(yy_aconf->rsa_public_key);
      yy_aconf->rsa_public_key = NULL;
    }

    if (yy_aconf->rsa_public_key_file != NULL)
    {
      MyFree(yy_aconf->rsa_public_key_file);
      yy_aconf->rsa_public_key_file = NULL;
    }

    DupString(yy_aconf->rsa_public_key_file, yylval.string);
    file = BIO_new_file(yylval.string, "r");

    if (file == NULL)
    {
      yyerror("Ignoring rsa_public_key_file -- file doesn't exist");
      break;
    }

    yy_aconf->rsa_public_key = (RSA *)PEM_read_bio_RSA_PUBKEY(file, NULL, 0, NULL);

    if (yy_aconf->rsa_public_key == NULL)
    {
      yyerror("Ignoring rsa_public_key_file -- Key invalid; check key syntax.");
      break;
    }

    (void)BIO_set_close(file, BIO_CLOSE);
    BIO_free(file);
  }
#endif /* HAVE_LIBCRYPTO */
}
    break;

  case 168:

/* Line 1455 of yacc.c  */
#line 1274 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(class_name);
    DupString(class_name, yylval.string);
  }
}
    break;

  case 169:

/* Line 1455 of yacc.c  */
#line 1283 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes = 0;
}
    break;

  case 173:

/* Line 1455 of yacc.c  */
#line 1290 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_BOTS;
}
    break;

  case 174:

/* Line 1455 of yacc.c  */
#line 1294 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_CCONN;
}
    break;

  case 175:

/* Line 1455 of yacc.c  */
#line 1298 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_CCONN_FULL;
}
    break;

  case 176:

/* Line 1455 of yacc.c  */
#line 1302 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_DEAF;
}
    break;

  case 177:

/* Line 1455 of yacc.c  */
#line 1306 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_DEBUG;
}
    break;

  case 178:

/* Line 1455 of yacc.c  */
#line 1310 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_FULL;
}
    break;

  case 179:

/* Line 1455 of yacc.c  */
#line 1314 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_SKILL;
}
    break;

  case 180:

/* Line 1455 of yacc.c  */
#line 1318 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_NCHANGE;
}
    break;

  case 181:

/* Line 1455 of yacc.c  */
#line 1322 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_REJ;
}
    break;

  case 182:

/* Line 1455 of yacc.c  */
#line 1326 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_UNAUTH;
}
    break;

  case 183:

/* Line 1455 of yacc.c  */
#line 1330 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_SPY;
}
    break;

  case 184:

/* Line 1455 of yacc.c  */
#line 1334 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_EXTERNAL;
}
    break;

  case 185:

/* Line 1455 of yacc.c  */
#line 1338 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_OPERWALL;
}
    break;

  case 186:

/* Line 1455 of yacc.c  */
#line 1342 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_SERVNOTICE;
}
    break;

  case 187:

/* Line 1455 of yacc.c  */
#line 1346 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_INVISIBLE;
}
    break;

  case 188:

/* Line 1455 of yacc.c  */
#line 1350 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_WALLOP;
}
    break;

  case 189:

/* Line 1455 of yacc.c  */
#line 1354 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_SOFTCALLERID;
}
    break;

  case 190:

/* Line 1455 of yacc.c  */
#line 1358 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_CALLERID;
}
    break;

  case 191:

/* Line 1455 of yacc.c  */
#line 1362 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_LOCOPS;
}
    break;

  case 192:

/* Line 1455 of yacc.c  */
#line 1366 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->modes |= UMODE_HIDECHANNELS;
}
    break;

  case 193:

/* Line 1455 of yacc.c  */
#line 1372 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_GLOBAL_KILL;
    else
      yy_aconf->port &= ~OPER_FLAG_GLOBAL_KILL;
  }
}
    break;

  case 194:

/* Line 1455 of yacc.c  */
#line 1383 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_REMOTE;
    else
      yy_aconf->port &= ~OPER_FLAG_REMOTE; 
  }
}
    break;

  case 195:

/* Line 1455 of yacc.c  */
#line 1394 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_REMOTEBAN;
    else
      yy_aconf->port &= ~OPER_FLAG_REMOTEBAN;
  }
}
    break;

  case 196:

/* Line 1455 of yacc.c  */
#line 1405 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_K;
    else
      yy_aconf->port &= ~OPER_FLAG_K;
  }
}
    break;

  case 197:

/* Line 1455 of yacc.c  */
#line 1416 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_X;
    else
      yy_aconf->port &= ~OPER_FLAG_X;
  }
}
    break;

  case 198:

/* Line 1455 of yacc.c  */
#line 1427 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_UNKLINE;
    else
      yy_aconf->port &= ~OPER_FLAG_UNKLINE; 
  }
}
    break;

  case 199:

/* Line 1455 of yacc.c  */
#line 1438 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_GLINE;
    else
      yy_aconf->port &= ~OPER_FLAG_GLINE;
  }
}
    break;

  case 200:

/* Line 1455 of yacc.c  */
#line 1449 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_N;
    else
      yy_aconf->port &= ~OPER_FLAG_N;
  }
}
    break;

  case 201:

/* Line 1455 of yacc.c  */
#line 1460 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_DIE;
    else
      yy_aconf->port &= ~OPER_FLAG_DIE;
  }
}
    break;

  case 202:

/* Line 1455 of yacc.c  */
#line 1471 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_REHASH;
    else
      yy_aconf->port &= ~OPER_FLAG_REHASH;
  }
}
    break;

  case 203:

/* Line 1455 of yacc.c  */
#line 1482 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_ADMIN;
    else
      yy_aconf->port &= ~OPER_FLAG_ADMIN;
  }
}
    break;

  case 204:

/* Line 1455 of yacc.c  */
#line 1493 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_HIDDEN_ADMIN;
    else
      yy_aconf->port &= ~OPER_FLAG_HIDDEN_ADMIN;
  }
}
    break;

  case 205:

/* Line 1455 of yacc.c  */
#line 1504 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_HIDDEN_OPER;
    else
      yy_aconf->port &= ~OPER_FLAG_HIDDEN_OPER;
  }
}
    break;

  case 206:

/* Line 1455 of yacc.c  */
#line 1515 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_OPER_SPY;
    else
      yy_aconf->port &= ~OPER_FLAG_OPER_SPY;
  }
}
    break;

  case 207:

/* Line 1455 of yacc.c  */
#line 1526 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->port |= OPER_FLAG_OPERWALL;
    else
      yy_aconf->port &= ~OPER_FLAG_OPERWALL;
  }
}
    break;

  case 208:

/* Line 1455 of yacc.c  */
#line 1537 "ircd_parser.y"
    {
}
    break;

  case 212:

/* Line 1455 of yacc.c  */
#line 1541 "ircd_parser.y"
    { not_atom = 1; }
    break;

  case 214:

/* Line 1455 of yacc.c  */
#line 1542 "ircd_parser.y"
    { not_atom = 0; }
    break;

  case 216:

/* Line 1455 of yacc.c  */
#line 1545 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)yy_aconf->port &= ~OPER_FLAG_GLOBAL_KILL;
    else yy_aconf->port |= OPER_FLAG_GLOBAL_KILL;
  }
}
    break;

  case 217:

/* Line 1455 of yacc.c  */
#line 1552 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_REMOTE;
    else yy_aconf->port |= OPER_FLAG_REMOTE;
  }
}
    break;

  case 218:

/* Line 1455 of yacc.c  */
#line 1559 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_K;
    else yy_aconf->port |= OPER_FLAG_K;
  }
}
    break;

  case 219:

/* Line 1455 of yacc.c  */
#line 1566 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_UNKLINE;
    else yy_aconf->port |= OPER_FLAG_UNKLINE;
  } 
}
    break;

  case 220:

/* Line 1455 of yacc.c  */
#line 1573 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_X;
    else yy_aconf->port |= OPER_FLAG_X;
  }
}
    break;

  case 221:

/* Line 1455 of yacc.c  */
#line 1580 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_GLINE;
    else yy_aconf->port |= OPER_FLAG_GLINE;
  }
}
    break;

  case 222:

/* Line 1455 of yacc.c  */
#line 1587 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_DIE;
    else yy_aconf->port |= OPER_FLAG_DIE;
  }
}
    break;

  case 223:

/* Line 1455 of yacc.c  */
#line 1594 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_REHASH;
    else yy_aconf->port |= OPER_FLAG_REHASH;
  }
}
    break;

  case 224:

/* Line 1455 of yacc.c  */
#line 1601 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_ADMIN;
    else yy_aconf->port |= OPER_FLAG_ADMIN;
  }
}
    break;

  case 225:

/* Line 1455 of yacc.c  */
#line 1608 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_HIDDEN_ADMIN;
    else yy_aconf->port |= OPER_FLAG_HIDDEN_ADMIN;
  }
}
    break;

  case 226:

/* Line 1455 of yacc.c  */
#line 1615 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_N;
    else yy_aconf->port |= OPER_FLAG_N;
  }
}
    break;

  case 227:

/* Line 1455 of yacc.c  */
#line 1622 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_OPERWALL;
    else yy_aconf->port |= OPER_FLAG_OPERWALL;
  }
}
    break;

  case 228:

/* Line 1455 of yacc.c  */
#line 1629 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_OPER_SPY;
    else yy_aconf->port |= OPER_FLAG_OPER_SPY;
  }
}
    break;

  case 229:

/* Line 1455 of yacc.c  */
#line 1636 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_HIDDEN_OPER;
    else yy_aconf->port |= OPER_FLAG_HIDDEN_OPER;
  }
}
    break;

  case 230:

/* Line 1455 of yacc.c  */
#line 1643 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->port &= ~OPER_FLAG_REMOTEBAN;
    else yy_aconf->port |= OPER_FLAG_REMOTEBAN;
  }
}
    break;

  case 231:

/* Line 1455 of yacc.c  */
#line 1650 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) ClearConfEncrypted(yy_aconf);
    else SetConfEncrypted(yy_aconf);
  }
}
    break;

  case 232:

/* Line 1455 of yacc.c  */
#line 1663 "ircd_parser.y"
    {
  if (ypass == 1)
  {
    yy_conf = make_conf_item(CLASS_TYPE);
    yy_class = map_to_conf(yy_conf);
  }
}
    break;

  case 233:

/* Line 1455 of yacc.c  */
#line 1670 "ircd_parser.y"
    {
  if (ypass == 1)
  {
    struct ConfItem *cconf = NULL;
    struct ClassItem *class = NULL;

    if (yy_class_name == NULL)
      delete_conf_item(yy_conf);
    else
    {
      cconf = find_exact_name_conf(CLASS_TYPE, yy_class_name, NULL, NULL, NULL);

      if (cconf != NULL)		/* The class existed already */
      {
        int user_count = 0;

        rebuild_cidr_class(cconf, yy_class);

        class = map_to_conf(cconf);

        user_count = class->curr_user_count;
        memcpy(class, yy_class, sizeof(*class));
        class->curr_user_count = user_count;
        class->active = 1;

        delete_conf_item(yy_conf);

        MyFree(cconf->name);            /* Allows case change of class name */
        cconf->name = yy_class_name;
      }
      else	/* Brand new class */
      {
        MyFree(yy_conf->name);          /* just in case it was allocated */
        yy_conf->name = yy_class_name;
	yy_class->active = 1;
      }
    }
    yy_class_name = NULL;
  }
}
    break;

  case 252:

/* Line 1455 of yacc.c  */
#line 1729 "ircd_parser.y"
    {
  if (ypass == 1)
  {
    MyFree(yy_class_name);
    DupString(yy_class_name, yylval.string);
  }
}
    break;

  case 253:

/* Line 1455 of yacc.c  */
#line 1738 "ircd_parser.y"
    {
  if (ypass == 1)
  {
    MyFree(yy_class_name);
    DupString(yy_class_name, yylval.string);
  }
}
    break;

  case 254:

/* Line 1455 of yacc.c  */
#line 1747 "ircd_parser.y"
    {
  if (ypass == 1)
    PingFreq(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 255:

/* Line 1455 of yacc.c  */
#line 1753 "ircd_parser.y"
    {
  if (ypass == 1)
    PingWarning(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 256:

/* Line 1455 of yacc.c  */
#line 1759 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxPerIp(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 257:

/* Line 1455 of yacc.c  */
#line 1765 "ircd_parser.y"
    {
  if (ypass == 1)
    ConFreq(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 258:

/* Line 1455 of yacc.c  */
#line 1771 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxTotal(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 259:

/* Line 1455 of yacc.c  */
#line 1777 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxGlobal(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 260:

/* Line 1455 of yacc.c  */
#line 1783 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxLocal(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 261:

/* Line 1455 of yacc.c  */
#line 1789 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxIdent(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 262:

/* Line 1455 of yacc.c  */
#line 1795 "ircd_parser.y"
    {
  if (ypass == 1)
    MaxSendq(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 263:

/* Line 1455 of yacc.c  */
#line 1801 "ircd_parser.y"
    {
  if (ypass == 1)
    CidrBitlenIPV4(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 264:

/* Line 1455 of yacc.c  */
#line 1807 "ircd_parser.y"
    {
  if (ypass == 1)
    CidrBitlenIPV6(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 265:

/* Line 1455 of yacc.c  */
#line 1813 "ircd_parser.y"
    {
  if (ypass == 1)
    NumberPerCidr(yy_class) = (yyvsp[(3) - (4)].number);
}
    break;

  case 266:

/* Line 1455 of yacc.c  */
#line 1822 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    listener_address = NULL;
    listener_flags = 0;
  }
}
    break;

  case 267:

/* Line 1455 of yacc.c  */
#line 1829 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(listener_address);
    listener_address = NULL;
  }
}
    break;

  case 268:

/* Line 1455 of yacc.c  */
#line 1838 "ircd_parser.y"
    {
  listener_flags = 0;
}
    break;

  case 272:

/* Line 1455 of yacc.c  */
#line 1844 "ircd_parser.y"
    {
  if (ypass == 2)
    listener_flags |= LISTENER_SSL;
}
    break;

  case 273:

/* Line 1455 of yacc.c  */
#line 1848 "ircd_parser.y"
    {
  if (ypass == 2)
    listener_flags |= LISTENER_HIDDEN;
}
    break;

  case 281:

/* Line 1455 of yacc.c  */
#line 1856 "ircd_parser.y"
    { listener_flags = 0; }
    break;

  case 285:

/* Line 1455 of yacc.c  */
#line 1861 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if ((listener_flags & LISTENER_SSL))
#ifdef HAVE_LIBCRYPTO
      if (!ServerInfo.ctx)
#endif
      {
        yyerror("SSL not available - port closed");
	break;
      }
    add_listener((yyvsp[(1) - (1)].number), listener_address, listener_flags);
  }
}
    break;

  case 286:

/* Line 1455 of yacc.c  */
#line 1875 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    int i;

    if ((listener_flags & LISTENER_SSL))
#ifdef HAVE_LIBCRYPTO
      if (!ServerInfo.ctx)
#endif
      {
        yyerror("SSL not available - port closed");
	break;
      }

    for (i = (yyvsp[(1) - (3)].number); i <= (yyvsp[(3) - (3)].number); ++i)
      add_listener(i, listener_address, listener_flags);
  }
}
    break;

  case 287:

/* Line 1455 of yacc.c  */
#line 1895 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(listener_address);
    DupString(listener_address, yylval.string);
  }
}
    break;

  case 288:

/* Line 1455 of yacc.c  */
#line 1904 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(listener_address);
    DupString(listener_address, yylval.string);
  }
}
    break;

  case 289:

/* Line 1455 of yacc.c  */
#line 1916 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(CLIENT_TYPE);
    yy_aconf = map_to_conf(yy_conf);
  }
  else
  {
    MyFree(class_name);
    class_name = NULL;
  }
}
    break;

  case 290:

/* Line 1455 of yacc.c  */
#line 1928 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp = NULL;
    dlink_node *ptr = NULL, *next_ptr = NULL;

    if (yy_aconf->user && yy_aconf->host)
    {
      conf_add_class_to_conf(yy_conf, class_name);
      add_conf_by_address(CONF_CLIENT, yy_aconf);
    }
    else
      delete_conf_item(yy_conf);

    /* copy over settings from first struct */
    DLINK_FOREACH_SAFE(ptr, next_ptr, col_conf_list.head)
    {
      struct AccessItem *new_aconf;
      struct ConfItem *new_conf;

      new_conf = make_conf_item(CLIENT_TYPE);
      new_aconf = map_to_conf(new_conf);

      yy_tmp = ptr->data;

      assert(yy_tmp->user && yy_tmp->host);

      if (yy_aconf->passwd != NULL)
        DupString(new_aconf->passwd, yy_aconf->passwd);
      if (yy_conf->name != NULL)
        DupString(new_conf->name, yy_conf->name);
      if (yy_aconf->passwd != NULL)
        DupString(new_aconf->passwd, yy_aconf->passwd);

      new_aconf->flags = yy_aconf->flags;
      new_aconf->port  = yy_aconf->port;

      DupString(new_aconf->user, yy_tmp->user);
      collapse(new_aconf->user);

      DupString(new_aconf->host, yy_tmp->host);
      collapse(new_aconf->host);

      if (yy_aconf->certfp != NULL)
      {
        new_aconf->certfp = MyMalloc(SHA_DIGEST_LENGTH);
        memcpy(new_aconf->certfp, yy_aconf->certfp, SHA_DIGEST_LENGTH);
      }

      conf_add_class_to_conf(new_conf, class_name);
      add_conf_by_address(CONF_CLIENT, new_aconf);
      dlinkDelete(&yy_tmp->node, &col_conf_list);
      free_collect_item(yy_tmp);
    }

    MyFree(class_name);
    class_name = NULL;
    yy_conf = NULL;
    yy_aconf = NULL;
  }
}
    break;

  case 312:

/* Line 1455 of yacc.c  */
#line 1999 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp = NULL;
    struct split_nuh_item nuh;

    nuh.nuhmask  = yylval.string;
    nuh.nickptr  = NULL;
    nuh.userptr  = userbuf;
    nuh.hostptr  = hostbuf;

    nuh.nicksize = 0;
    nuh.usersize = sizeof(userbuf);
    nuh.hostsize = sizeof(hostbuf);

    split_nuh(&nuh);

    if (yy_aconf->user == NULL)
    {
      DupString(yy_aconf->user, userbuf);
      DupString(yy_aconf->host, hostbuf);
    }
    else
    {
      yy_tmp = MyMalloc(sizeof(struct CollectItem));

      DupString(yy_tmp->user, userbuf);
      DupString(yy_tmp->host, hostbuf);

      dlinkAdd(yy_tmp, &yy_tmp->node, &col_conf_list);
    }
  }
}
    break;

  case 313:

/* Line 1455 of yacc.c  */
#line 2036 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    /* be paranoid */
    if (yy_aconf->passwd != NULL)
      memset(yy_aconf->passwd, 0, strlen(yy_aconf->passwd));

    MyFree(yy_aconf->passwd);
    DupString(yy_aconf->passwd, yylval.string);
  }
}
    break;

  case 314:

/* Line 1455 of yacc.c  */
#line 2049 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    char tmp[SHA_DIGEST_LENGTH];

    if(yy_aconf->certfp != NULL)
      MyFree(yy_aconf->certfp);

    if(base16_decode(tmp, SHA_DIGEST_LENGTH, yylval.string, strlen(yylval.string)) != 0)
    {
      yyerror("Invalid client certificate fingerprint provided. Ignoring");
      break;
    }
    yy_aconf->certfp = MyMalloc(SHA_DIGEST_LENGTH);
    memcpy(yy_aconf->certfp, tmp, SHA_DIGEST_LENGTH);
  }
}
    break;

  case 315:

/* Line 1455 of yacc.c  */
#line 2068 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_SPOOF_NOTICE;
    else
      yy_aconf->flags &= ~CONF_FLAGS_SPOOF_NOTICE;
  }
}
    break;

  case 316:

/* Line 1455 of yacc.c  */
#line 2079 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(class_name);
    DupString(class_name, yylval.string);
  }
}
    break;

  case 317:

/* Line 1455 of yacc.c  */
#line 2088 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      SetConfEncrypted(yy_aconf);
    else
      ClearConfEncrypted(yy_aconf);
  }
}
    break;

  case 318:

/* Line 1455 of yacc.c  */
#line 2099 "ircd_parser.y"
    {
}
    break;

  case 322:

/* Line 1455 of yacc.c  */
#line 2103 "ircd_parser.y"
    { not_atom = 1; }
    break;

  case 324:

/* Line 1455 of yacc.c  */
#line 2104 "ircd_parser.y"
    { not_atom = 0; }
    break;

  case 326:

/* Line 1455 of yacc.c  */
#line 2107 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_SPOOF_NOTICE;
    else yy_aconf->flags |= CONF_FLAGS_SPOOF_NOTICE;
  }

}
    break;

  case 327:

/* Line 1455 of yacc.c  */
#line 2115 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_NOLIMIT;
    else yy_aconf->flags |= CONF_FLAGS_NOLIMIT;
  }
}
    break;

  case 328:

/* Line 1455 of yacc.c  */
#line 2122 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_EXEMPTKLINE;
    else yy_aconf->flags |= CONF_FLAGS_EXEMPTKLINE;
  } 
}
    break;

  case 329:

/* Line 1455 of yacc.c  */
#line 2129 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_NEED_IDENTD;
    else yy_aconf->flags |= CONF_FLAGS_NEED_IDENTD;
  }
}
    break;

  case 330:

/* Line 1455 of yacc.c  */
#line 2136 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_CAN_FLOOD;
    else yy_aconf->flags |= CONF_FLAGS_CAN_FLOOD;
  }
}
    break;

  case 331:

/* Line 1455 of yacc.c  */
#line 2143 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_IDLE_LINED;
    else yy_aconf->flags |= CONF_FLAGS_IDLE_LINED;
  }
}
    break;

  case 332:

/* Line 1455 of yacc.c  */
#line 2150 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_NO_TILDE;
    else yy_aconf->flags |= CONF_FLAGS_NO_TILDE;
  } 
}
    break;

  case 333:

/* Line 1455 of yacc.c  */
#line 2157 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_EXEMPTGLINE;
    else yy_aconf->flags |= CONF_FLAGS_EXEMPTGLINE;
  } 
}
    break;

  case 334:

/* Line 1455 of yacc.c  */
#line 2164 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_EXEMPTRESV;
    else yy_aconf->flags |= CONF_FLAGS_EXEMPTRESV;
  }
}
    break;

  case 335:

/* Line 1455 of yacc.c  */
#line 2171 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_EXEMPTDNSBL;
    else yy_aconf->flags |= CONF_FLAGS_EXEMPTDNSBL;
  }
}
    break;

  case 336:

/* Line 1455 of yacc.c  */
#line 2178 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_WEBIRC;
    else yy_aconf->flags |= CONF_FLAGS_WEBIRC;
  }
}
    break;

  case 337:

/* Line 1455 of yacc.c  */
#line 2185 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom) yy_aconf->flags &= ~CONF_FLAGS_NEED_PASSWORD;
    else yy_aconf->flags |= CONF_FLAGS_NEED_PASSWORD;
  }
}
    break;

  case 338:

/* Line 1455 of yacc.c  */
#line 2194 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_EXEMPTKLINE;
    else
      yy_aconf->flags &= ~CONF_FLAGS_EXEMPTKLINE;
  }
}
    break;

  case 339:

/* Line 1455 of yacc.c  */
#line 2205 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_NEED_IDENTD;
    else
      yy_aconf->flags &= ~CONF_FLAGS_NEED_IDENTD;
  }
}
    break;

  case 340:

/* Line 1455 of yacc.c  */
#line 2216 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_NOLIMIT;
    else
      yy_aconf->flags &= ~CONF_FLAGS_NOLIMIT;
  }
}
    break;

  case 341:

/* Line 1455 of yacc.c  */
#line 2227 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_CAN_FLOOD;
    else
      yy_aconf->flags &= ~CONF_FLAGS_CAN_FLOOD;
  }
}
    break;

  case 342:

/* Line 1455 of yacc.c  */
#line 2238 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_NO_TILDE;
    else
      yy_aconf->flags &= ~CONF_FLAGS_NO_TILDE;
  }
}
    break;

  case 343:

/* Line 1455 of yacc.c  */
#line 2249 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_EXEMPTGLINE;
    else
      yy_aconf->flags &= ~CONF_FLAGS_EXEMPTGLINE;
  }
}
    break;

  case 344:

/* Line 1455 of yacc.c  */
#line 2261 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_conf->name);

    if (strlen(yylval.string) < HOSTLEN)
    {    
      DupString(yy_conf->name, yylval.string);
      yy_aconf->flags |= CONF_FLAGS_SPOOF_IP;
    }
    else
    {
      ilog(L_ERROR, "Spoofs must be less than %d..ignoring it", HOSTLEN);
      yy_conf->name = NULL;
    }
  }
}
    break;

  case 345:

/* Line 1455 of yacc.c  */
#line 2280 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_aconf->flags |= CONF_FLAGS_REDIR;
    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 346:

/* Line 1455 of yacc.c  */
#line 2290 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_aconf->flags |= CONF_FLAGS_REDIR;
    yy_aconf->port = (yyvsp[(3) - (4)].number);
  }
}
    break;

  case 347:

/* Line 1455 of yacc.c  */
#line 2299 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_WEBIRC;
    else
      yy_aconf->flags &= ~CONF_FLAGS_WEBIRC;
  }
}
    break;

  case 348:

/* Line 1455 of yacc.c  */
#line 2310 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_NEED_PASSWORD;
    else
      yy_aconf->flags &= ~CONF_FLAGS_NEED_PASSWORD;
  }
}
    break;

  case 349:

/* Line 1455 of yacc.c  */
#line 2325 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(resv_reason);
    resv_reason = NULL;
  }
}
    break;

  case 350:

/* Line 1455 of yacc.c  */
#line 2332 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(resv_reason);
    resv_reason = NULL;
  }
}
    break;

  case 357:

/* Line 1455 of yacc.c  */
#line 2344 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(resv_reason);
    DupString(resv_reason, yylval.string);
  }
}
    break;

  case 358:

/* Line 1455 of yacc.c  */
#line 2353 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (IsChanPrefix(*yylval.string))
    {
      char def_reason[] = "No reason";

      create_channel_resv(yylval.string, resv_reason != NULL ? resv_reason : def_reason, 1);
    }
  }
  /* ignore it for now.. but we really should make a warning if
   * its an erroneous name --fl_ */
}
    break;

  case 359:

/* Line 1455 of yacc.c  */
#line 2368 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    char def_reason[] = "No reason";

    create_nick_resv(yylval.string, resv_reason != NULL ? resv_reason : def_reason, 1);
  }
}
    break;

  case 360:

/* Line 1455 of yacc.c  */
#line 2381 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(ULINE_TYPE);
    yy_match_item = map_to_conf(yy_conf);
    yy_match_item->action = SHARED_ALL;
  }
}
    break;

  case 361:

/* Line 1455 of yacc.c  */
#line 2389 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = NULL;
  }
}
    break;

  case 368:

/* Line 1455 of yacc.c  */
#line 2400 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 369:

/* Line 1455 of yacc.c  */
#line 2409 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct split_nuh_item nuh;

    nuh.nuhmask  = yylval.string;
    nuh.nickptr  = NULL;
    nuh.userptr  = userbuf;
    nuh.hostptr  = hostbuf;

    nuh.nicksize = 0;
    nuh.usersize = sizeof(userbuf);
    nuh.hostsize = sizeof(hostbuf);

    split_nuh(&nuh);

    DupString(yy_match_item->user, userbuf);
    DupString(yy_match_item->host, hostbuf);
  }
}
    break;

  case 370:

/* Line 1455 of yacc.c  */
#line 2431 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action = 0;
}
    break;

  case 374:

/* Line 1455 of yacc.c  */
#line 2438 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_KLINE;
}
    break;

  case 375:

/* Line 1455 of yacc.c  */
#line 2442 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_TKLINE;
}
    break;

  case 376:

/* Line 1455 of yacc.c  */
#line 2446 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_UNKLINE;
}
    break;

  case 377:

/* Line 1455 of yacc.c  */
#line 2450 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_XLINE;
}
    break;

  case 378:

/* Line 1455 of yacc.c  */
#line 2454 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_TXLINE;
}
    break;

  case 379:

/* Line 1455 of yacc.c  */
#line 2458 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_UNXLINE;
}
    break;

  case 380:

/* Line 1455 of yacc.c  */
#line 2462 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_RESV;
}
    break;

  case 381:

/* Line 1455 of yacc.c  */
#line 2466 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_TRESV;
}
    break;

  case 382:

/* Line 1455 of yacc.c  */
#line 2470 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_UNRESV;
}
    break;

  case 383:

/* Line 1455 of yacc.c  */
#line 2474 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_LOCOPS;
}
    break;

  case 384:

/* Line 1455 of yacc.c  */
#line 2478 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_SERVICES;
}
    break;

  case 385:

/* Line 1455 of yacc.c  */
#line 2482 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action |= SHARED_REHASH;
}
    break;

  case 386:

/* Line 1455 of yacc.c  */
#line 2486 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_match_item->action = SHARED_ALL;
}
    break;

  case 387:

/* Line 1455 of yacc.c  */
#line 2495 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(CLUSTER_TYPE);
    yy_conf->flags = SHARED_ALL;
  }
}
    break;

  case 388:

/* Line 1455 of yacc.c  */
#line 2502 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_conf->name == NULL)
      DupString(yy_conf->name, "*");
    yy_conf = NULL;
  }
}
    break;

  case 394:

/* Line 1455 of yacc.c  */
#line 2515 "ircd_parser.y"
    {
  if (ypass == 2)
    DupString(yy_conf->name, yylval.string);
}
    break;

  case 395:

/* Line 1455 of yacc.c  */
#line 2521 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags = 0;
}
    break;

  case 399:

/* Line 1455 of yacc.c  */
#line 2528 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_KLINE;
}
    break;

  case 400:

/* Line 1455 of yacc.c  */
#line 2532 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_TKLINE;
}
    break;

  case 401:

/* Line 1455 of yacc.c  */
#line 2536 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_UNKLINE;
}
    break;

  case 402:

/* Line 1455 of yacc.c  */
#line 2540 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_XLINE;
}
    break;

  case 403:

/* Line 1455 of yacc.c  */
#line 2544 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_TXLINE;
}
    break;

  case 404:

/* Line 1455 of yacc.c  */
#line 2548 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_UNXLINE;
}
    break;

  case 405:

/* Line 1455 of yacc.c  */
#line 2552 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_RESV;
}
    break;

  case 406:

/* Line 1455 of yacc.c  */
#line 2556 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_TRESV;
}
    break;

  case 407:

/* Line 1455 of yacc.c  */
#line 2560 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_UNRESV;
}
    break;

  case 408:

/* Line 1455 of yacc.c  */
#line 2564 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags |= SHARED_LOCOPS;
}
    break;

  case 409:

/* Line 1455 of yacc.c  */
#line 2568 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_conf->flags = SHARED_ALL;
}
    break;

  case 410:

/* Line 1455 of yacc.c  */
#line 2577 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(SERVER_TYPE);
    yy_aconf = (struct AccessItem *)map_to_conf(yy_conf);
    yy_aconf->passwd = NULL;
    /* defaults */
    yy_aconf->port = PORTNUM;

    if (ConfigFileEntry.burst_away)
      yy_aconf->flags = CONF_FLAGS_BURST_AWAY;
  }
  else
  {
    MyFree(class_name);
    class_name = NULL;
  }
}
    break;

  case 411:

/* Line 1455 of yacc.c  */
#line 2595 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_hconf=NULL;
    struct CollectItem *yy_lconf=NULL;
    dlink_node *ptr;
    dlink_node *next_ptr;
#ifdef HAVE_LIBCRYPTO
    if (yy_aconf->host &&
	((yy_aconf->passwd && yy_aconf->spasswd) ||
	 (yy_aconf->rsa_public_key && IsConfCryptLink(yy_aconf))))
#else /* !HAVE_LIBCRYPTO */
      if (yy_aconf->host && !IsConfCryptLink(yy_aconf) && 
	  yy_aconf->passwd && yy_aconf->spasswd)
#endif /* !HAVE_LIBCRYPTO */
	{
	  if (conf_add_server(yy_conf, class_name) == -1)
	  {
	    delete_conf_item(yy_conf);
	    yy_conf = NULL;
	    yy_aconf = NULL;
	  }
	}
	else
	{
	  /* Even if yy_conf ->name is NULL
	   * should still unhook any hub/leaf confs still pending
	   */
	  unhook_hub_leaf_confs();

	  if (yy_conf->name != NULL)
	  {
#ifndef HAVE_LIBCRYPTO
	    if (IsConfCryptLink(yy_aconf))
	      yyerror("Ignoring connect block -- no OpenSSL support");
#else
	    if (IsConfCryptLink(yy_aconf) && !yy_aconf->rsa_public_key)
	      yyerror("Ignoring connect block -- missing key");
#endif
	    if (yy_aconf->host == NULL)
	      yyerror("Ignoring connect block -- missing host");
	    else if (!IsConfCryptLink(yy_aconf) && 
		    (!yy_aconf->passwd || !yy_aconf->spasswd))
              yyerror("Ignoring connect block -- missing password");
	  }


          /* XXX
           * This fixes a try_connections() core (caused by invalid class_ptr
           * pointers) reported by metalrock. That's an ugly fix, but there
           * is currently no better way. The entire config subsystem needs an
           * rewrite ASAP. make_conf_item() shouldn't really add things onto
           * a doubly linked list immediately without any sanity checks!  -Michael
           */
          delete_conf_item(yy_conf);

          yy_aconf = NULL;
	  yy_conf = NULL;
	}

      /*
       * yy_conf is still pointing at the server that is having
       * a connect block built for it. This means, y_aconf->name 
       * points to the actual irc name this server will be known as.
       * Now this new server has a set or even just one hub_mask (or leaf_mask)
       * given in the link list at yy_hconf. Fill in the HUB confs
       * from this link list now.
       */        
      DLINK_FOREACH_SAFE(ptr, next_ptr, hub_conf_list.head)
      {
	struct ConfItem *new_hub_conf;
	struct MatchItem *match_item;

	yy_hconf = ptr->data;

	/* yy_conf == NULL is a fatal error for this connect block! */
	if ((yy_conf != NULL) && (yy_conf->name != NULL))
	{
	  new_hub_conf = make_conf_item(HUB_TYPE);
	  match_item = (struct MatchItem *)map_to_conf(new_hub_conf);
	  DupString(new_hub_conf->name, yy_conf->name);
	  if (yy_hconf->user != NULL)
	    DupString(match_item->user, yy_hconf->user);
	  else
	    DupString(match_item->user, "*");
	  if (yy_hconf->host != NULL)
	    DupString(match_item->host, yy_hconf->host);
	  else
	    DupString(match_item->host, "*");
	}
	dlinkDelete(&yy_hconf->node, &hub_conf_list);
	free_collect_item(yy_hconf);
      }

      /* Ditto for the LEAF confs */

      DLINK_FOREACH_SAFE(ptr, next_ptr, leaf_conf_list.head)
      {
	struct ConfItem *new_leaf_conf;
	struct MatchItem *match_item;

	yy_lconf = ptr->data;

	if ((yy_conf != NULL) && (yy_conf->name != NULL))
	{
	  new_leaf_conf = make_conf_item(LEAF_TYPE);
	  match_item = (struct MatchItem *)map_to_conf(new_leaf_conf);
	  DupString(new_leaf_conf->name, yy_conf->name);
	  if (yy_lconf->user != NULL)
	    DupString(match_item->user, yy_lconf->user);
	  else
	    DupString(match_item->user, "*");
	  if (yy_lconf->host != NULL)
	    DupString(match_item->host, yy_lconf->host);
	  else
	    DupString(match_item->host, "*");
	}
	dlinkDelete(&yy_lconf->node, &leaf_conf_list);
	free_collect_item(yy_lconf);
      }
      MyFree(class_name);
      class_name = NULL;
      yy_conf = NULL;
      yy_aconf = NULL;
  }
}
    break;

  case 436:

/* Line 1455 of yacc.c  */
#line 2734 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_conf->name != NULL)
      yyerror("Multiple connect name entry");

    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 437:

/* Line 1455 of yacc.c  */
#line 2746 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_conf->name != NULL)
      yyerror("Multiple connect name entry");

    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 438:

/* Line 1455 of yacc.c  */
#line 2758 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_aconf->host);
    DupString(yy_aconf->host, yylval.string);
  }
}
    break;

  case 439:

/* Line 1455 of yacc.c  */
#line 2767 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;

    if (irc_getaddrinfo(yylval.string, NULL, &hints, &res))
      ilog(L_ERROR, "Invalid netmask for server vhost(%s)", yylval.string);
    else
    {
      assert(res != NULL);

      memcpy(&yy_aconf->my_ipnum, res->ai_addr, res->ai_addrlen);
      yy_aconf->my_ipnum.ss.ss_family = res->ai_family;
      yy_aconf->my_ipnum.ss_len = res->ai_addrlen;
      irc_freeaddrinfo(res);
    }
  }
}
    break;

  case 440:

/* Line 1455 of yacc.c  */
#line 2793 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if ((yyvsp[(3) - (4)].string)[0] == ':')
      yyerror("Server passwords cannot begin with a colon");
    else if (strchr((yyvsp[(3) - (4)].string), ' ') != NULL)
      yyerror("Server passwords cannot contain spaces");
    else {
      if (yy_aconf->spasswd != NULL)
        memset(yy_aconf->spasswd, 0, strlen(yy_aconf->spasswd));

      MyFree(yy_aconf->spasswd);
      DupString(yy_aconf->spasswd, yylval.string);
    }
  }
}
    break;

  case 441:

/* Line 1455 of yacc.c  */
#line 2811 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if ((yyvsp[(3) - (4)].string)[0] == ':')
      yyerror("Server passwords cannot begin with a colon");
    else if (strchr((yyvsp[(3) - (4)].string), ' ') != NULL)
      yyerror("Server passwords cannot contain spaces");
    else {
      if (yy_aconf->passwd != NULL)
        memset(yy_aconf->passwd, 0, strlen(yy_aconf->passwd));

      MyFree(yy_aconf->passwd);
      DupString(yy_aconf->passwd, yylval.string);
    }
  }
}
    break;

  case 442:

/* Line 1455 of yacc.c  */
#line 2829 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->port = (yyvsp[(3) - (4)].number);
}
    break;

  case 443:

/* Line 1455 of yacc.c  */
#line 2835 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->aftype = AF_INET;
}
    break;

  case 444:

/* Line 1455 of yacc.c  */
#line 2839 "ircd_parser.y"
    {
#ifdef IPV6
  if (ypass == 2)
    yy_aconf->aftype = AF_INET6;
#endif
}
    break;

  case 445:

/* Line 1455 of yacc.c  */
#line 2847 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_aconf->fakename);
    DupString(yy_aconf->fakename, yylval.string);
  }
}
    break;

  case 446:

/* Line 1455 of yacc.c  */
#line 2856 "ircd_parser.y"
    {
}
    break;

  case 450:

/* Line 1455 of yacc.c  */
#line 2860 "ircd_parser.y"
    { not_atom = 1; }
    break;

  case 452:

/* Line 1455 of yacc.c  */
#line 2861 "ircd_parser.y"
    { not_atom = 0; }
    break;

  case 454:

/* Line 1455 of yacc.c  */
#line 2864 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)ClearConfLazyLink(yy_aconf);
    else SetConfLazyLink(yy_aconf);
  }
}
    break;

  case 455:

/* Line 1455 of yacc.c  */
#line 2871 "ircd_parser.y"
    {
  if (ypass == 2)
#ifndef HAVE_LIBZ
    yyerror("Ignoring flags = compressed; -- no zlib support");
#else
 {
   if (not_atom)ClearConfCompressed(yy_aconf);
   else SetConfCompressed(yy_aconf);
 }
#endif
}
    break;

  case 456:

/* Line 1455 of yacc.c  */
#line 2882 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)ClearConfCryptLink(yy_aconf);
    else SetConfCryptLink(yy_aconf);
  }
}
    break;

  case 457:

/* Line 1455 of yacc.c  */
#line 2889 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)ClearConfAllowAutoConn(yy_aconf);
    else SetConfAllowAutoConn(yy_aconf);
  }
}
    break;

  case 458:

/* Line 1455 of yacc.c  */
#line 2896 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)ClearConfAwayBurst(yy_aconf);
    else SetConfAwayBurst(yy_aconf);
  }
}
    break;

  case 459:

/* Line 1455 of yacc.c  */
#line 2903 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (not_atom)ClearConfTopicBurst(yy_aconf);
    else SetConfTopicBurst(yy_aconf);
  }
}
    break;

  case 460:

/* Line 1455 of yacc.c  */
#line 2913 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 2)
  {
    BIO *file;

    if (yy_aconf->rsa_public_key != NULL)
    {
      RSA_free(yy_aconf->rsa_public_key);
      yy_aconf->rsa_public_key = NULL;
    }

    if (yy_aconf->rsa_public_key_file != NULL)
    {
      MyFree(yy_aconf->rsa_public_key_file);
      yy_aconf->rsa_public_key_file = NULL;
    }

    DupString(yy_aconf->rsa_public_key_file, yylval.string);

    if ((file = BIO_new_file(yylval.string, "r")) == NULL)
    {
      yyerror("Ignoring rsa_public_key_file -- file doesn't exist");
      break;
    }

    yy_aconf->rsa_public_key = (RSA *)PEM_read_bio_RSA_PUBKEY(file, NULL, 0, NULL);

    if (yy_aconf->rsa_public_key == NULL)
    {
      yyerror("Ignoring rsa_public_key_file -- Key invalid; check key syntax.");
      break;
    }

    (void)BIO_set_close(file, BIO_CLOSE);
    BIO_free(file);
  }
#endif /* HAVE_LIBCRYPTO */
}
    break;

  case 461:

/* Line 1455 of yacc.c  */
#line 2954 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_ENCRYPTED;
    else
      yy_aconf->flags &= ~CONF_FLAGS_ENCRYPTED;
  }
}
    break;

  case 462:

/* Line 1455 of yacc.c  */
#line 2965 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_CRYPTLINK;
    else
      yy_aconf->flags &= ~CONF_FLAGS_CRYPTLINK;
  }
}
    break;

  case 463:

/* Line 1455 of yacc.c  */
#line 2976 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
#ifndef HAVE_LIBZ
      yyerror("Ignoring compressed=yes; -- no zlib support");
#else
      yy_aconf->flags |= CONF_FLAGS_COMPRESSED;
#endif
    else
      yy_aconf->flags &= ~CONF_FLAGS_COMPRESSED;
  }
}
    break;

  case 464:

/* Line 1455 of yacc.c  */
#line 2991 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      yy_aconf->flags |= CONF_FLAGS_ALLOW_AUTO_CONN;
    else
      yy_aconf->flags &= ~CONF_FLAGS_ALLOW_AUTO_CONN;
  }
}
    break;

  case 465:

/* Line 1455 of yacc.c  */
#line 3002 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.number)
      SetConfTopicBurst(yy_aconf);
    else
      ClearConfTopicBurst(yy_aconf);
  }
}
    break;

  case 466:

/* Line 1455 of yacc.c  */
#line 3013 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp;

    yy_tmp = (struct CollectItem *)MyMalloc(sizeof(struct CollectItem));
    DupString(yy_tmp->host, yylval.string);
    DupString(yy_tmp->user, "*");
    dlinkAdd(yy_tmp, &yy_tmp->node, &hub_conf_list);
  }
}
    break;

  case 467:

/* Line 1455 of yacc.c  */
#line 3026 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp;

    yy_tmp = (struct CollectItem *)MyMalloc(sizeof(struct CollectItem));
    DupString(yy_tmp->host, yylval.string);
    DupString(yy_tmp->user, "*");
    dlinkAdd(yy_tmp, &yy_tmp->node, &leaf_conf_list);
  }
}
    break;

  case 468:

/* Line 1455 of yacc.c  */
#line 3039 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(class_name);
    DupString(class_name, yylval.string);
  }
}
    break;

  case 469:

/* Line 1455 of yacc.c  */
#line 3048 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 2)
  {
    struct EncCapability *ecap;
    const char *cipher_name;
    int found = 0;

    yy_aconf->cipher_preference = NULL;
    cipher_name = yylval.string;

    for (ecap = CipherTable; ecap->name; ecap++)
    {
      if ((irccmp(ecap->name, cipher_name) == 0) &&
          (ecap->cap & CAP_ENC_MASK))
      {
        yy_aconf->cipher_preference = ecap;
        found = 1;
        break;
      }
    }

    if (!found)
      yyerror("Invalid cipher");
  }
#else
  if (ypass == 2)
    yyerror("Ignoring cipher_preference -- no OpenSSL support");
#endif
}
    break;

  case 470:

/* Line 1455 of yacc.c  */
#line 3083 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    userbuf[0] = hostbuf[0] = reasonbuf[0] = '\0';
    regex_ban = 0;
  }
}
    break;

  case 471:

/* Line 1455 of yacc.c  */
#line 3090 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (userbuf[0] && hostbuf[0])
    {
      if (regex_ban)
      {
        pcre *exp_user = NULL;
        pcre *exp_host = NULL;
        const char *errptr = NULL;

        if (!(exp_user = ircd_pcre_compile(userbuf, &errptr)) ||
            !(exp_host = ircd_pcre_compile(hostbuf, &errptr)))
        {
          ilog(L_ERROR, "Failed to add regular expression based K-Line: %s", errptr);
          break;
        }

        yy_conf = make_conf_item(RKLINE_TYPE);
	yy_aconf = map_to_conf(yy_conf);

        yy_aconf->regexuser = exp_user;
        yy_aconf->regexhost = exp_host;

        DupString(yy_aconf->user, userbuf);
        DupString(yy_aconf->host, hostbuf);

        if (reasonbuf[0])
          DupString(yy_aconf->reason, reasonbuf);
        else
          DupString(yy_aconf->reason, "No reason");
      }
      else
      {
        yy_conf = make_conf_item(KLINE_TYPE);
        yy_aconf = map_to_conf(yy_conf);

        DupString(yy_aconf->user, userbuf);
        DupString(yy_aconf->host, hostbuf);

        if (reasonbuf[0])
          DupString(yy_aconf->reason, reasonbuf);
        else
          DupString(yy_aconf->reason, "No reason");
        add_conf_by_address(CONF_KILL, yy_aconf);
      }
    }
    else
      delete_conf_item(yy_conf);

    yy_conf = NULL;
    yy_aconf = NULL;
  }
}
    break;

  case 472:

/* Line 1455 of yacc.c  */
#line 3146 "ircd_parser.y"
    {
}
    break;

  case 476:

/* Line 1455 of yacc.c  */
#line 3151 "ircd_parser.y"
    {
  if (ypass == 2)
    regex_ban = 1;
}
    break;

  case 483:

/* Line 1455 of yacc.c  */
#line 3160 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct split_nuh_item nuh;

    nuh.nuhmask  = yylval.string;
    nuh.nickptr  = NULL;
    nuh.userptr  = userbuf;
    nuh.hostptr  = hostbuf;

    nuh.nicksize = 0;
    nuh.usersize = sizeof(userbuf);
    nuh.hostsize = sizeof(hostbuf);

    split_nuh(&nuh);
  }
}
    break;

  case 484:

/* Line 1455 of yacc.c  */
#line 3179 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(reasonbuf, yylval.string, sizeof(reasonbuf));
}
    break;

  case 485:

/* Line 1455 of yacc.c  */
#line 3188 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(DLINE_TYPE);
    yy_aconf = map_to_conf(yy_conf);
    /* default reason */
    DupString(yy_aconf->reason, "No reason");
  }
}
    break;

  case 486:

/* Line 1455 of yacc.c  */
#line 3197 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yy_aconf->host && parse_netmask(yy_aconf->host, NULL, NULL) != HM_HOST)
      add_conf_by_address(CONF_DLINE, yy_aconf);
    else
      delete_conf_item(yy_conf);
    yy_conf = NULL;
    yy_aconf = NULL;
  }
}
    break;

  case 492:

/* Line 1455 of yacc.c  */
#line 3213 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_aconf->host);
    DupString(yy_aconf->host, yylval.string);
  }
}
    break;

  case 493:

/* Line 1455 of yacc.c  */
#line 3222 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(yy_aconf->reason);
    DupString(yy_aconf->reason, yylval.string);
  }
}
    break;

  case 500:

/* Line 1455 of yacc.c  */
#line 3239 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (yylval.string[0] && parse_netmask(yylval.string, NULL, NULL) != HM_HOST)
    {
      yy_conf = make_conf_item(EXEMPTDLINE_TYPE);
      yy_aconf = map_to_conf(yy_conf);
      DupString(yy_aconf->host, yylval.string);

      add_conf_by_address(CONF_EXEMPTDLINE, yy_aconf);

      yy_conf = NULL;
      yy_aconf = NULL;
    }
  }
}
    break;

  case 501:

/* Line 1455 of yacc.c  */
#line 3257 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    char tmp[SHA_DIGEST_LENGTH];

    yy_conf = make_conf_item(EXEMPTDLINE_TYPE);
    yy_aconf = map_to_conf(yy_conf);
  
    if(base16_decode(tmp, SHA_DIGEST_LENGTH, yylval.string, strlen(yylval.string)) != 0)
    {
      yyerror("Invalid client certificate fingerprint provided. Ignoring");
      break;
    }
 
    yy_aconf->certfp = MyMalloc(SHA_DIGEST_LENGTH);
    yy_aconf->host = MyMalloc(SHA_DIGEST_LENGTH);
    memcpy(yy_aconf->certfp, tmp, SHA_DIGEST_LENGTH);
    memcpy(yy_aconf->host, tmp, SHA_DIGEST_LENGTH);
 
    add_conf_by_address(CONF_EXEMPTDLINE, yy_aconf);

    yy_conf = NULL;
    yy_aconf = NULL;

 }
}
    break;

  case 502:

/* Line 1455 of yacc.c  */
#line 3289 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    regex_ban = 0;
    reasonbuf[0] = gecos_name[0] = '\0';
  }
}
    break;

  case 503:

/* Line 1455 of yacc.c  */
#line 3296 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (gecos_name[0])
    {
      if (regex_ban)
      {
        pcre *exp_p = NULL;
        const char *errptr = NULL;

        if (!(exp_p = ircd_pcre_compile(gecos_name, &errptr)))
        {
          ilog(L_ERROR, "Failed to add regular expression based X-Line: %s", errptr);
          break;
        }

        yy_conf = make_conf_item(RXLINE_TYPE);
        yy_conf->regexpname = exp_p;
      }
      else
        yy_conf = make_conf_item(XLINE_TYPE);

      yy_match_item = map_to_conf(yy_conf);
      DupString(yy_conf->name, gecos_name);

      if (reasonbuf[0])
        DupString(yy_match_item->reason, reasonbuf);
      else
        DupString(yy_match_item->reason, "No reason");
    }
  }
}
    break;

  case 504:

/* Line 1455 of yacc.c  */
#line 3330 "ircd_parser.y"
    {
}
    break;

  case 508:

/* Line 1455 of yacc.c  */
#line 3335 "ircd_parser.y"
    {
  if (ypass == 2)
    regex_ban = 1;
}
    break;

  case 515:

/* Line 1455 of yacc.c  */
#line 3344 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(gecos_name, yylval.string, sizeof(gecos_name));
}
    break;

  case 516:

/* Line 1455 of yacc.c  */
#line 3350 "ircd_parser.y"
    {
  if (ypass == 2)
    strlcpy(reasonbuf, yylval.string, sizeof(reasonbuf));
}
    break;

  case 582:

/* Line 1455 of yacc.c  */
#line 3398 "ircd_parser.y"
    {
  ConfigFileEntry.gline_min_cidr = (yyvsp[(3) - (4)].number);
}
    break;

  case 583:

/* Line 1455 of yacc.c  */
#line 3403 "ircd_parser.y"
    {
  ConfigFileEntry.gline_min_cidr6 = (yyvsp[(3) - (4)].number);
}
    break;

  case 584:

/* Line 1455 of yacc.c  */
#line 3408 "ircd_parser.y"
    {
  ConfigFileEntry.burst_away = yylval.number;
}
    break;

  case 585:

/* Line 1455 of yacc.c  */
#line 3413 "ircd_parser.y"
    {
  ConfigFileEntry.use_whois_actually = yylval.number;
}
    break;

  case 586:

/* Line 1455 of yacc.c  */
#line 3418 "ircd_parser.y"
    {
  GlobalSetOptions.rejecttime = yylval.number;
}
    break;

  case 587:

/* Line 1455 of yacc.c  */
#line 3423 "ircd_parser.y"
    {
  ConfigFileEntry.tkline_expire_notices = yylval.number;
}
    break;

  case 588:

/* Line 1455 of yacc.c  */
#line 3428 "ircd_parser.y"
    {
  ConfigFileEntry.kill_chase_time_limit = (yyvsp[(3) - (4)].number);
}
    break;

  case 589:

/* Line 1455 of yacc.c  */
#line 3433 "ircd_parser.y"
    {
  ConfigFileEntry.hide_spoof_ips = yylval.number;
}
    break;

  case 590:

/* Line 1455 of yacc.c  */
#line 3438 "ircd_parser.y"
    {
  ConfigFileEntry.ignore_bogus_ts = yylval.number;
}
    break;

  case 591:

/* Line 1455 of yacc.c  */
#line 3443 "ircd_parser.y"
    {
  ConfigFileEntry.disable_remote = yylval.number;
}
    break;

  case 592:

/* Line 1455 of yacc.c  */
#line 3448 "ircd_parser.y"
    {
  ConfigFileEntry.failed_oper_notice = yylval.number;
}
    break;

  case 593:

/* Line 1455 of yacc.c  */
#line 3453 "ircd_parser.y"
    {
  ConfigFileEntry.anti_nick_flood = yylval.number;
}
    break;

  case 594:

/* Line 1455 of yacc.c  */
#line 3458 "ircd_parser.y"
    {
  ConfigFileEntry.max_nick_time = (yyvsp[(3) - (4)].number); 
}
    break;

  case 595:

/* Line 1455 of yacc.c  */
#line 3463 "ircd_parser.y"
    {
  ConfigFileEntry.max_nick_changes = (yyvsp[(3) - (4)].number);
}
    break;

  case 596:

/* Line 1455 of yacc.c  */
#line 3468 "ircd_parser.y"
    {
  ConfigFileEntry.max_accept = (yyvsp[(3) - (4)].number);
}
    break;

  case 597:

/* Line 1455 of yacc.c  */
#line 3473 "ircd_parser.y"
    {
  ConfigFileEntry.anti_spam_exit_message_time = (yyvsp[(3) - (4)].number);
}
    break;

  case 598:

/* Line 1455 of yacc.c  */
#line 3478 "ircd_parser.y"
    {
  ConfigFileEntry.anti_spam_connect_numeric = yylval.number;
}
    break;

  case 599:

/* Line 1455 of yacc.c  */
#line 3483 "ircd_parser.y"
    {
  ConfigFileEntry.ts_warn_delta = (yyvsp[(3) - (4)].number);
}
    break;

  case 600:

/* Line 1455 of yacc.c  */
#line 3488 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.ts_max_delta = (yyvsp[(3) - (4)].number);
}
    break;

  case 601:

/* Line 1455 of yacc.c  */
#line 3494 "ircd_parser.y"
    {
  if (((yyvsp[(3) - (4)].number) > 0) && ypass == 1)
  {
    ilog(L_CRIT, "You haven't read your config file properly.");
    ilog(L_CRIT, "There is a line in the example conf that will kill your server if not removed.");
    ilog(L_CRIT, "Consider actually reading/editing the conf file, and removing this line.");
    exit(0);
  }
}
    break;

  case 602:

/* Line 1455 of yacc.c  */
#line 3505 "ircd_parser.y"
    {
  ConfigFileEntry.kline_with_reason = yylval.number;
}
    break;

  case 603:

/* Line 1455 of yacc.c  */
#line 3510 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.kline_reason);
    DupString(ConfigFileEntry.kline_reason, yylval.string);
  }
}
    break;

  case 604:

/* Line 1455 of yacc.c  */
#line 3519 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.cloak_key1);
    DupString(ConfigFileEntry.cloak_key1, yylval.string);
  }
}
    break;

  case 605:

/* Line 1455 of yacc.c  */
#line 3528 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.cloak_key2);
    DupString(ConfigFileEntry.cloak_key2, yylval.string);
  }
}
    break;

  case 606:

/* Line 1455 of yacc.c  */
#line 3537 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.cloak_key3);
    DupString(ConfigFileEntry.cloak_key3, yylval.string);
  }
}
    break;

  case 607:

/* Line 1455 of yacc.c  */
#line 3546 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.services_name);
    DupString(ConfigFileEntry.services_name, yylval.string);
  }
}
    break;

  case 608:

/* Line 1455 of yacc.c  */
#line 3555 "ircd_parser.y"
    {
  ConfigFileEntry.invisible_on_connect = yylval.number;
}
    break;

  case 609:

/* Line 1455 of yacc.c  */
#line 3560 "ircd_parser.y"
    {
  ConfigFileEntry.warn_no_nline = yylval.number;
}
    break;

  case 610:

/* Line 1455 of yacc.c  */
#line 3565 "ircd_parser.y"
    {
  ConfigFileEntry.stats_e_disabled = yylval.number;
}
    break;

  case 611:

/* Line 1455 of yacc.c  */
#line 3570 "ircd_parser.y"
    {
  ConfigFileEntry.stats_o_oper_only = yylval.number;
}
    break;

  case 612:

/* Line 1455 of yacc.c  */
#line 3575 "ircd_parser.y"
    {
  ConfigFileEntry.stats_P_oper_only = yylval.number;
}
    break;

  case 613:

/* Line 1455 of yacc.c  */
#line 3580 "ircd_parser.y"
    {
  ConfigFileEntry.hide_killer = yylval.number;
}
    break;

  case 614:

/* Line 1455 of yacc.c  */
#line 3585 "ircd_parser.y"
    {
  ConfigFileEntry.stats_k_oper_only = 2 * yylval.number;
}
    break;

  case 615:

/* Line 1455 of yacc.c  */
#line 3588 "ircd_parser.y"
    {
  ConfigFileEntry.stats_k_oper_only = 1;
}
    break;

  case 616:

/* Line 1455 of yacc.c  */
#line 3593 "ircd_parser.y"
    {
  ConfigFileEntry.stats_i_oper_only = 2 * yylval.number;
}
    break;

  case 617:

/* Line 1455 of yacc.c  */
#line 3596 "ircd_parser.y"
    {
  ConfigFileEntry.stats_i_oper_only = 1;
}
    break;

  case 618:

/* Line 1455 of yacc.c  */
#line 3601 "ircd_parser.y"
    {
  ConfigFileEntry.pace_wait = (yyvsp[(3) - (4)].number);
}
    break;

  case 619:

/* Line 1455 of yacc.c  */
#line 3606 "ircd_parser.y"
    {
  ConfigFileEntry.caller_id_wait = (yyvsp[(3) - (4)].number);
}
    break;

  case 620:

/* Line 1455 of yacc.c  */
#line 3611 "ircd_parser.y"
    {
  ConfigFileEntry.opers_bypass_callerid = yylval.number;
}
    break;

  case 621:

/* Line 1455 of yacc.c  */
#line 3616 "ircd_parser.y"
    {
  ConfigFileEntry.pace_wait_simple = (yyvsp[(3) - (4)].number);
}
    break;

  case 622:

/* Line 1455 of yacc.c  */
#line 3621 "ircd_parser.y"
    {
  ConfigFileEntry.short_motd = yylval.number;
}
    break;

  case 623:

/* Line 1455 of yacc.c  */
#line 3626 "ircd_parser.y"
    {
  ConfigFileEntry.no_oper_flood = yylval.number;
}
    break;

  case 624:

/* Line 1455 of yacc.c  */
#line 3631 "ircd_parser.y"
    {
  ConfigFileEntry.true_no_oper_flood = yylval.number;
}
    break;

  case 625:

/* Line 1455 of yacc.c  */
#line 3636 "ircd_parser.y"
    {
  ConfigFileEntry.oper_pass_resv = yylval.number;
}
    break;

  case 626:

/* Line 1455 of yacc.c  */
#line 3641 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (strlen(yylval.string) > LOCALE_LENGTH-2)
      yylval.string[LOCALE_LENGTH-1] = '\0';

    set_locale(yylval.string);
  }
}
    break;

  case 627:

/* Line 1455 of yacc.c  */
#line 3652 "ircd_parser.y"
    {
  ConfigFileEntry.idletime = (yyvsp[(3) - (4)].number);
}
    break;

  case 628:

/* Line 1455 of yacc.c  */
#line 3657 "ircd_parser.y"
    {
  ConfigFileEntry.dots_in_ident = (yyvsp[(3) - (4)].number);
}
    break;

  case 629:

/* Line 1455 of yacc.c  */
#line 3662 "ircd_parser.y"
    {
  ConfigFileEntry.max_targets = (yyvsp[(3) - (4)].number);
}
    break;

  case 630:

/* Line 1455 of yacc.c  */
#line 3667 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.servlink_path);
    DupString(ConfigFileEntry.servlink_path, yylval.string);
  }
}
    break;

  case 631:

/* Line 1455 of yacc.c  */
#line 3676 "ircd_parser.y"
    {
#ifdef HAVE_LIBCRYPTO
  if (ypass == 2)
  {
    struct EncCapability *ecap;
    const char *cipher_name;
    int found = 0;

    ConfigFileEntry.default_cipher_preference = NULL;
    cipher_name = yylval.string;

    for (ecap = CipherTable; ecap->name; ecap++)
    {
      if ((irccmp(ecap->name, cipher_name) == 0) &&
          (ecap->cap & CAP_ENC_MASK))
      {
        ConfigFileEntry.default_cipher_preference = ecap;
        found = 1;
        break;
      }
    }

    if (!found)
      yyerror("Invalid cipher");
  }
#else
  if (ypass == 2)
    yyerror("Ignoring default_cipher_preference -- no OpenSSL support");
#endif
}
    break;

  case 632:

/* Line 1455 of yacc.c  */
#line 3708 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    ConfigFileEntry.compression_level = (yyvsp[(3) - (4)].number);
#ifndef HAVE_LIBZ
    yyerror("Ignoring compression_level -- no zlib support");
#else
    if ((ConfigFileEntry.compression_level < 1) ||
        (ConfigFileEntry.compression_level > 9))
    {
      yyerror("Ignoring invalid compression_level, using default");
      ConfigFileEntry.compression_level = 0;
    }
#endif
  }
}
    break;

  case 633:

/* Line 1455 of yacc.c  */
#line 3726 "ircd_parser.y"
    {
  ConfigFileEntry.use_egd = yylval.number;
}
    break;

  case 634:

/* Line 1455 of yacc.c  */
#line 3731 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigFileEntry.egdpool_path);
    DupString(ConfigFileEntry.egdpool_path, yylval.string);
  }
}
    break;

  case 635:

/* Line 1455 of yacc.c  */
#line 3740 "ircd_parser.y"
    {
  ConfigFileEntry.ping_cookie = yylval.number;
}
    break;

  case 636:

/* Line 1455 of yacc.c  */
#line 3745 "ircd_parser.y"
    {
  ConfigFileEntry.disable_auth = yylval.number;
}
    break;

  case 637:

/* Line 1455 of yacc.c  */
#line 3750 "ircd_parser.y"
    {
  ConfigFileEntry.throttle_time = yylval.number;
}
    break;

  case 638:

/* Line 1455 of yacc.c  */
#line 3755 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes = 0;
}
    break;

  case 642:

/* Line 1455 of yacc.c  */
#line 3761 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_BOTS;
}
    break;

  case 643:

/* Line 1455 of yacc.c  */
#line 3764 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_CCONN;
}
    break;

  case 644:

/* Line 1455 of yacc.c  */
#line 3767 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_CCONN_FULL;
}
    break;

  case 645:

/* Line 1455 of yacc.c  */
#line 3770 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_DEAF;
}
    break;

  case 646:

/* Line 1455 of yacc.c  */
#line 3773 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_DEBUG;
}
    break;

  case 647:

/* Line 1455 of yacc.c  */
#line 3776 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_FULL;
}
    break;

  case 648:

/* Line 1455 of yacc.c  */
#line 3779 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_SKILL;
}
    break;

  case 649:

/* Line 1455 of yacc.c  */
#line 3782 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_NCHANGE;
}
    break;

  case 650:

/* Line 1455 of yacc.c  */
#line 3785 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_REJ;
}
    break;

  case 651:

/* Line 1455 of yacc.c  */
#line 3788 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_UNAUTH;
}
    break;

  case 652:

/* Line 1455 of yacc.c  */
#line 3791 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_SPY;
}
    break;

  case 653:

/* Line 1455 of yacc.c  */
#line 3794 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_EXTERNAL;
}
    break;

  case 654:

/* Line 1455 of yacc.c  */
#line 3797 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_OPERWALL;
}
    break;

  case 655:

/* Line 1455 of yacc.c  */
#line 3800 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_SERVNOTICE;
}
    break;

  case 656:

/* Line 1455 of yacc.c  */
#line 3803 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_INVISIBLE;
}
    break;

  case 657:

/* Line 1455 of yacc.c  */
#line 3806 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_WALLOP;
}
    break;

  case 658:

/* Line 1455 of yacc.c  */
#line 3809 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_SOFTCALLERID;
}
    break;

  case 659:

/* Line 1455 of yacc.c  */
#line 3812 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_CALLERID;
}
    break;

  case 660:

/* Line 1455 of yacc.c  */
#line 3815 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_LOCOPS;
}
    break;

  case 661:

/* Line 1455 of yacc.c  */
#line 3818 "ircd_parser.y"
    {
  ConfigFileEntry.oper_umodes |= UMODE_HIDECHANNELS;
}
    break;

  case 662:

/* Line 1455 of yacc.c  */
#line 3823 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes = 0;
}
    break;

  case 666:

/* Line 1455 of yacc.c  */
#line 3829 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_BOTS;
}
    break;

  case 667:

/* Line 1455 of yacc.c  */
#line 3832 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_CCONN;
}
    break;

  case 668:

/* Line 1455 of yacc.c  */
#line 3835 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_CCONN_FULL;
}
    break;

  case 669:

/* Line 1455 of yacc.c  */
#line 3838 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_DEAF;
}
    break;

  case 670:

/* Line 1455 of yacc.c  */
#line 3841 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_DEBUG;
}
    break;

  case 671:

/* Line 1455 of yacc.c  */
#line 3844 "ircd_parser.y"
    { 
  ConfigFileEntry.oper_only_umodes |= UMODE_FULL;
}
    break;

  case 672:

/* Line 1455 of yacc.c  */
#line 3847 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_SKILL;
}
    break;

  case 673:

/* Line 1455 of yacc.c  */
#line 3850 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_NCHANGE;
}
    break;

  case 674:

/* Line 1455 of yacc.c  */
#line 3853 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_REJ;
}
    break;

  case 675:

/* Line 1455 of yacc.c  */
#line 3856 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_UNAUTH;
}
    break;

  case 676:

/* Line 1455 of yacc.c  */
#line 3859 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_SPY;
}
    break;

  case 677:

/* Line 1455 of yacc.c  */
#line 3862 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_EXTERNAL;
}
    break;

  case 678:

/* Line 1455 of yacc.c  */
#line 3865 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_OPERWALL;
}
    break;

  case 679:

/* Line 1455 of yacc.c  */
#line 3868 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_SERVNOTICE;
}
    break;

  case 680:

/* Line 1455 of yacc.c  */
#line 3871 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_INVISIBLE;
}
    break;

  case 681:

/* Line 1455 of yacc.c  */
#line 3874 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_WALLOP;
}
    break;

  case 682:

/* Line 1455 of yacc.c  */
#line 3877 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_SOFTCALLERID;
}
    break;

  case 683:

/* Line 1455 of yacc.c  */
#line 3880 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_CALLERID;
}
    break;

  case 684:

/* Line 1455 of yacc.c  */
#line 3883 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_LOCOPS;
}
    break;

  case 685:

/* Line 1455 of yacc.c  */
#line 3886 "ircd_parser.y"
    {
  ConfigFileEntry.oper_only_umodes |= UMODE_HIDECHANNELS;
}
    break;

  case 686:

/* Line 1455 of yacc.c  */
#line 3891 "ircd_parser.y"
    {
  ConfigFileEntry.min_nonwildcard = (yyvsp[(3) - (4)].number);
}
    break;

  case 687:

/* Line 1455 of yacc.c  */
#line 3896 "ircd_parser.y"
    {
  ConfigFileEntry.min_nonwildcard_simple = (yyvsp[(3) - (4)].number);
}
    break;

  case 688:

/* Line 1455 of yacc.c  */
#line 3901 "ircd_parser.y"
    {
  ConfigFileEntry.default_floodcount = (yyvsp[(3) - (4)].number);
}
    break;

  case 689:

/* Line 1455 of yacc.c  */
#line 3906 "ircd_parser.y"
    {
  ConfigFileEntry.client_flood = (yyvsp[(3) - (4)].number);
}
    break;

  case 690:

/* Line 1455 of yacc.c  */
#line 3911 "ircd_parser.y"
    {
  ConfigFileEntry.dot_in_ip6_addr = yylval.number;
}
    break;

  case 691:

/* Line 1455 of yacc.c  */
#line 3919 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    yy_conf = make_conf_item(GDENY_TYPE);
    yy_aconf = map_to_conf(yy_conf);
  }
}
    break;

  case 692:

/* Line 1455 of yacc.c  */
#line 3926 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    /*
     * since we re-allocate yy_conf/yy_aconf after the end of action=, at the
     * end we will have one extra, so we should free it.
     */
    if (yy_conf->name == NULL || yy_aconf->user == NULL)
    {
      delete_conf_item(yy_conf);
      yy_conf = NULL;
      yy_aconf = NULL;
    }
  }
}
    break;

  case 702:

/* Line 1455 of yacc.c  */
#line 3952 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.glines = yylval.number;
}
    break;

  case 703:

/* Line 1455 of yacc.c  */
#line 3958 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.gline_time = (yyvsp[(3) - (4)].number);
}
    break;

  case 704:

/* Line 1455 of yacc.c  */
#line 3964 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.gline_logging = 0;
}
    break;

  case 708:

/* Line 1455 of yacc.c  */
#line 3970 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.gline_logging |= GDENY_REJECT;
}
    break;

  case 709:

/* Line 1455 of yacc.c  */
#line 3974 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigFileEntry.gline_logging |= GDENY_BLOCK;
}
    break;

  case 710:

/* Line 1455 of yacc.c  */
#line 3980 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct split_nuh_item nuh;

    nuh.nuhmask  = yylval.string;
    nuh.nickptr  = NULL;
    nuh.userptr  = userbuf;
    nuh.hostptr  = hostbuf;

    nuh.nicksize = 0;
    nuh.usersize = sizeof(userbuf);
    nuh.hostsize = sizeof(hostbuf);

    split_nuh(&nuh);

    if (yy_aconf->user == NULL)
    {
      DupString(yy_aconf->user, userbuf);
      DupString(yy_aconf->host, hostbuf);
    }
    else
    {
      struct CollectItem *yy_tmp = MyMalloc(sizeof(struct CollectItem));

      DupString(yy_tmp->user, userbuf);
      DupString(yy_tmp->host, hostbuf);

      dlinkAdd(yy_tmp, &yy_tmp->node, &col_conf_list);
    }
  }
}
    break;

  case 711:

/* Line 1455 of yacc.c  */
#line 4014 "ircd_parser.y"
    {
  if (ypass == 2)  
  {
    MyFree(yy_conf->name);
    DupString(yy_conf->name, yylval.string);
  }
}
    break;

  case 712:

/* Line 1455 of yacc.c  */
#line 4023 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->flags = 0;
}
    break;

  case 713:

/* Line 1455 of yacc.c  */
#line 4027 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    struct CollectItem *yy_tmp = NULL;
    dlink_node *ptr, *next_ptr;

    DLINK_FOREACH_SAFE(ptr, next_ptr, col_conf_list.head)
    {
      struct AccessItem *new_aconf;
      struct ConfItem *new_conf;

      yy_tmp = ptr->data;
      new_conf = make_conf_item(GDENY_TYPE);
      new_aconf = map_to_conf(new_conf);

      new_aconf->flags = yy_aconf->flags;

      if (yy_conf->name != NULL)
        DupString(new_conf->name, yy_conf->name);
      else
        DupString(new_conf->name, "*");
      if (yy_aconf->user != NULL)
         DupString(new_aconf->user, yy_tmp->user);
      else   
        DupString(new_aconf->user, "*");
      if (yy_aconf->host != NULL)
        DupString(new_aconf->host, yy_tmp->host);
      else
        DupString(new_aconf->host, "*");

      dlinkDelete(&yy_tmp->node, &col_conf_list);
    }

    /*
     * In case someone has fed us with more than one action= after user/name
     * which would leak memory  -Michael
     */
    if (yy_conf->name == NULL || yy_aconf->user == NULL)
      delete_conf_item(yy_conf);

    yy_conf = make_conf_item(GDENY_TYPE);
    yy_aconf = map_to_conf(yy_conf);
  }
}
    break;

  case 716:

/* Line 1455 of yacc.c  */
#line 4074 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->flags |= GDENY_REJECT;
}
    break;

  case 717:

/* Line 1455 of yacc.c  */
#line 4078 "ircd_parser.y"
    {
  if (ypass == 2)
    yy_aconf->flags |= GDENY_BLOCK;
}
    break;

  case 742:

/* Line 1455 of yacc.c  */
#line 4103 "ircd_parser.y"
    {
  ConfigChannel.cycle_on_hostchange = yylval.number;
}
    break;

  case 743:

/* Line 1455 of yacc.c  */
#line 4108 "ircd_parser.y"
    {
  ConfigChannel.disable_fake_channels = yylval.number;
}
    break;

  case 744:

/* Line 1455 of yacc.c  */
#line 4113 "ircd_parser.y"
    {
  ConfigChannel.restrict_channels = yylval.number;
}
    break;

  case 745:

/* Line 1455 of yacc.c  */
#line 4118 "ircd_parser.y"
    {
  ConfigChannel.disable_local_channels = yylval.number;
}
    break;

  case 746:

/* Line 1455 of yacc.c  */
#line 4123 "ircd_parser.y"
    {
  ConfigChannel.use_except = yylval.number;
}
    break;

  case 747:

/* Line 1455 of yacc.c  */
#line 4128 "ircd_parser.y"
    {
  ConfigChannel.use_invex = yylval.number;
}
    break;

  case 748:

/* Line 1455 of yacc.c  */
#line 4133 "ircd_parser.y"
    {
  ConfigChannel.regex_bans = yylval.number;
}
    break;

  case 749:

/* Line 1455 of yacc.c  */
#line 4138 "ircd_parser.y"
    {
  ConfigChannel.use_knock = yylval.number;
}
    break;

  case 750:

/* Line 1455 of yacc.c  */
#line 4143 "ircd_parser.y"
    {
  ConfigChannel.knock_delay = (yyvsp[(3) - (4)].number);
}
    break;

  case 751:

/* Line 1455 of yacc.c  */
#line 4148 "ircd_parser.y"
    {
  ConfigChannel.knock_delay_channel = (yyvsp[(3) - (4)].number);
}
    break;

  case 752:

/* Line 1455 of yacc.c  */
#line 4153 "ircd_parser.y"
    {
  ConfigChannel.max_chans_per_user = (yyvsp[(3) - (4)].number);
}
    break;

  case 753:

/* Line 1455 of yacc.c  */
#line 4158 "ircd_parser.y"
    {
  ConfigChannel.quiet_on_ban = yylval.number;
}
    break;

  case 754:

/* Line 1455 of yacc.c  */
#line 4163 "ircd_parser.y"
    {
  ConfigChannel.max_bans = (yyvsp[(3) - (4)].number);
}
    break;

  case 755:

/* Line 1455 of yacc.c  */
#line 4168 "ircd_parser.y"
    {
  ConfigChannel.default_split_user_count = (yyvsp[(3) - (4)].number);
}
    break;

  case 756:

/* Line 1455 of yacc.c  */
#line 4173 "ircd_parser.y"
    {
  ConfigChannel.default_split_server_count = (yyvsp[(3) - (4)].number);
}
    break;

  case 757:

/* Line 1455 of yacc.c  */
#line 4178 "ircd_parser.y"
    {
  ConfigChannel.no_create_on_split = yylval.number;
}
    break;

  case 758:

/* Line 1455 of yacc.c  */
#line 4183 "ircd_parser.y"
    {
  ConfigChannel.no_join_on_split = yylval.number;
}
    break;

  case 759:

/* Line 1455 of yacc.c  */
#line 4188 "ircd_parser.y"
    {
  ConfigChannel.burst_topicwho = yylval.number;
}
    break;

  case 760:

/* Line 1455 of yacc.c  */
#line 4193 "ircd_parser.y"
    {
  GlobalSetOptions.joinfloodcount = yylval.number;
}
    break;

  case 761:

/* Line 1455 of yacc.c  */
#line 4198 "ircd_parser.y"
    {
  GlobalSetOptions.joinfloodtime = yylval.number;
}
    break;

  case 773:

/* Line 1455 of yacc.c  */
#line 4217 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigServerHide.flatten_links = yylval.number;
}
    break;

  case 774:

/* Line 1455 of yacc.c  */
#line 4223 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigServerHide.hide_servers = yylval.number;
}
    break;

  case 775:

/* Line 1455 of yacc.c  */
#line 4229 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    MyFree(ConfigServerHide.hidden_name);
    DupString(ConfigServerHide.hidden_name, yylval.string);
  }
}
    break;

  case 776:

/* Line 1455 of yacc.c  */
#line 4238 "ircd_parser.y"
    {
  if (ypass == 2)
  {
    if (((yyvsp[(3) - (4)].number) > 0) && ConfigServerHide.links_disabled == 1)
    {
      eventAddIsh("write_links_file", write_links_file, NULL, (yyvsp[(3) - (4)].number));
      ConfigServerHide.links_disabled = 0;
    }

    ConfigServerHide.links_delay = (yyvsp[(3) - (4)].number);
  }
}
    break;

  case 777:

/* Line 1455 of yacc.c  */
#line 4252 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigServerHide.hidden = yylval.number;
}
    break;

  case 778:

/* Line 1455 of yacc.c  */
#line 4258 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigServerHide.disable_hidden = yylval.number;
}
    break;

  case 779:

/* Line 1455 of yacc.c  */
#line 4264 "ircd_parser.y"
    {
  if (ypass == 2)
    ConfigServerHide.hide_server_ips = yylval.number;
}
    break;



/* Line 1455 of yacc.c  */
#line 9043 "y.tab.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



