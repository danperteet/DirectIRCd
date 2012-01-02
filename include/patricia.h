/*
 * $Id: patricia.h 22407 2006-05-07 15:39:43Z androsyn $
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors. 
 *
 * This file had been called "radix.h" in the MRT sources.
 *
 * I renamed it to "patricia.h" since it's not an implementation of a general
 * radix trie.  Also, pulled in various requirements from "mrt.h" and added
 * some other things it could be used as a standalone API.
 */

#ifndef _PATRICIA_H
#define _PATRICIA_H
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#ifndef TESTING
#include "class.h"
#include "client.h"
#include "common.h"
#include "irc_string.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "memory.h"
#include "config.h"
#endif


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE !(FALSE)
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* typedef unsigned int uint; */
typedef void (*void_fn_t) ();
#define prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)
#define MAXLINE 1024
#define BIT_TEST(f, b)  ((f) & (b))

#include <netinet/in.h>
#include <sys/socket.h>

typedef struct _prefix_t
{
	u_short family;		/* AF_INET | AF_INET6 */
	u_short bitlen;		/* same as mask? */
	int ref_count;		/* reference count */
	union
	{
		struct in_addr sin;
#ifdef IPV6
		struct in6_addr sin6;
#endif				/* IPV6 */
	}
	add;
}
prefix_t;


typedef struct _patricia_node_t
{
	unsigned int bit;		/* flag if this node used */
	prefix_t *prefix;	/* who we are in patricia tree */
	struct _patricia_node_t *l, *r;	/* left and right children */
	struct _patricia_node_t *parent;	/* may be used */
	void *data;
}
patricia_node_t;

typedef struct _patricia_tree_t
{
	patricia_node_t *head;
	unsigned int maxbits;		/* for IP, 32 bit addresses */
	int num_active_node;	/* for debug purpose */
}
patricia_tree_t;


patricia_node_t *match_ip(patricia_tree_t * tree, struct sockaddr  *ip);
patricia_node_t *match_string(patricia_tree_t * tree, const char *string);
patricia_node_t *match_exact_string(patricia_tree_t * tree, const char *string);
patricia_node_t *patricia_search_exact(patricia_tree_t * patricia, prefix_t * prefix);
patricia_node_t *patricia_search_best(patricia_tree_t * patricia, prefix_t * prefix);
patricia_node_t *patricia_search_best2(patricia_tree_t * patricia,
				       prefix_t * prefix, int inclusive);
patricia_node_t *patricia_lookup(patricia_tree_t * patricia, prefix_t * prefix);

void patricia_remove(patricia_tree_t * patricia, patricia_node_t * node);
patricia_tree_t *New_Patricia(int maxbits);
void Clear_Patricia(patricia_tree_t * patricia, void_fn_t func);
void Destroy_Patricia(patricia_tree_t * patricia, void_fn_t func);
void patricia_process(patricia_tree_t * patricia, void_fn_t func);
void init_patricia(void);


#if 0
prefix_t *ascii2prefix(int family, char *string);
#endif
patricia_node_t *make_and_lookup(patricia_tree_t * tree, const char *string);
patricia_node_t *make_and_lookup_ip(patricia_tree_t * tree, struct sockaddr *, int bitlen);


#define PATRICIA_MAXBITS 128
#define PATRICIA_NBIT(x)        (0x80 >> ((x) & 0x7f))
#define PATRICIA_NBYTE(x)       ((x) >> 3)

#define PATRICIA_DATA_GET(node, type) (type *)((node)->data)
#define PATRICIA_DATA_SET(node, value) ((node)->data = (void *)(value))

#define PATRICIA_WALK(Xhead, Xnode) \
    do { \
        patricia_node_t *Xstack[PATRICIA_MAXBITS+1]; \
        patricia_node_t **Xsp = Xstack; \
        patricia_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
            if (Xnode->prefix)

#define PATRICIA_WALK_ALL(Xhead, Xnode) \
do { \
        patricia_node_t *Xstack[PATRICIA_MAXBITS+1]; \
        patricia_node_t **Xsp = Xstack; \
        patricia_node_t *Xrn = (Xhead); \
        while ((Xnode = Xrn)) { \
	    if (1)

#define PATRICIA_WALK_BREAK { \
	    if (Xsp != Xstack) { \
		Xrn = *(--Xsp); \
	     } else { \
		Xrn = (patricia_node_t *) 0; \
	    } \
	    continue; }

#define PATRICIA_WALK_END \
            if (Xrn->l) { \
                if (Xrn->r) { \
                    *Xsp++ = Xrn->r; \
                } \
                Xrn = Xrn->l; \
            } else if (Xrn->r) { \
                Xrn = Xrn->r; \
            } else if (Xsp != Xstack) { \
                Xrn = *(--Xsp); \
            } else { \
                Xrn = (patricia_node_t *) 0; \
            } \
        } \
    } while (0)

#endif /* _PATRICIA_H */
