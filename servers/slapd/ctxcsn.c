/* $OpenLDAP$ */
/*
 * Context CSN Management Routines
 */
/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <db.h>

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"
#include "lutil_ldap.h"

#ifdef LDAP_SYNC

struct berval *
commit_csn( Operation *op )
{
	struct berval *max_committed_csn = NULL;
	struct slap_csn_entry *csne = NULL, *committed_csne = NULL;
	int i = 0;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		csne->state = SLAP_CSN_COMMIT;
	}

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->state == SLAP_CSN_COMMIT )
			committed_csne = csne;
		if ( csne->state == SLAP_CSN_PENDING )
			break;
	}

	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );

	if ( committed_csne ) {
		max_committed_csn = ber_dupbv( NULL, committed_csne->csn );
	}

	return max_committed_csn;
}

void
rewind_commit_csn( Operation *op )
{
	struct slap_csn_entry *csne = NULL;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		csne->state = SLAP_CSN_PENDING;
	}
	
	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );
}

void
graduate_commit_csn( Operation *op )
{
	struct slap_csn_entry *csne = NULL;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		LDAP_TAILQ_REMOVE( &op->o_bd->be_pending_csn_list, csne, csn_link );
		ch_free( csne->csn->bv_val );
		ch_free( csne->csn );
		ch_free( csne );
	}

	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );

	return;
}

Entry *
create_context_csn_entry(
	Backend *be,
	struct berval *context_csn
)
{
	Modifications *ml;
	Modifications *mlnext;
	Modifications *mod;
	Modifications *modlist;
	Modifications **modtail = &modlist;

	struct berval* ocbva = NULL;
	struct berval* socbva = NULL;
	struct berval* cnbva = NULL;
	struct berval* ssbva = NULL;
	struct berval* scbva = NULL;

	char substr[64];
	char rdnstr[67];
	const char	*text;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;

	Entry* e;
	int rc;

	struct berval sub_bv = { 0, NULL };
	struct berval psubrdn = { 0, NULL };
	
	slap_callback cb;
	SlapReply	rs = {REP_RESULT};

	struct berval rdn = { 0, NULL };
	int match = 0;
	char *def_filter_str = NULL;

	ocbva = ( struct berval * ) ch_calloc( 4, sizeof( struct berval ));
	socbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
	cnbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
	ssbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));
	scbva = ( struct berval * ) ch_calloc( 2, sizeof( struct berval ));

	ber_str2bv( "top", strlen("top"), 1, &ocbva[0] );
	ber_str2bv( "subentry", strlen("subentry"), 1, &ocbva[1] );
	ber_str2bv( "syncProviderSubentry",
			strlen("syncProviderSubentry"), 1, &ocbva[2] );
	ocbva[3].bv_len = 0;
	ocbva[3].bv_val = NULL;

	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "objectClass", strlen("objectClass"), 1, &mod->sml_type );
	mod->sml_bvalues = ocbva;
	mod->sml_nvalues = ocbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	ber_str2bv( "syncProviderSubentry",
			strlen("syncProviderSubentry"), 1, &socbva[0] );
	socbva[1].bv_len = 0;
	socbva[1].bv_val = NULL;

	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "structuralObjectClass", strlen("structuralObjectClass"), 1, &mod->sml_type );
	mod->sml_bvalues = socbva;
	mod->sml_nvalues = socbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	sprintf( substr, "ldapsync" );
	sprintf( rdnstr, "cn=%s", substr );
	ber_str2bv( substr, strlen( substr ), 1, &cnbva[0] );
	ber_str2bv( rdnstr, strlen( rdnstr ), 1, &psubrdn );
	cnbva[1].bv_len = 0;
	cnbva[1].bv_val = NULL;
	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "cn", strlen("cn"), 1, &mod->sml_type );
	mod->sml_bvalues = cnbva;
	mod->sml_nvalues = cnbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	if ( context_csn ) {
		ber_dupbv( &scbva[0], context_csn );
		scbva[1].bv_len = 0;
		scbva[1].bv_val = NULL;
		mod = (Modifications *) ch_malloc( sizeof( Modifications ));
		mod->sml_op = LDAP_MOD_REPLACE;
		mod->sml_next = NULL;
		mod->sml_desc = NULL;
		ber_str2bv( "contextCSN", strlen("contextCSN"), 1, &mod->sml_type );
		mod->sml_bvalues = scbva;
		mod->sml_nvalues = scbva;
		*modtail = mod;
		modtail = &mod->sml_next;
	}

	ber_str2bv( "{}", strlen("{}"), 1, &ssbva[0] );
	ssbva[1].bv_len = 0;
	ssbva[1].bv_val = NULL;
	mod = (Modifications *) ch_malloc( sizeof( Modifications ));
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_next = NULL;
	mod->sml_desc = NULL;
	ber_str2bv( "subtreeSpecification",
			strlen("subtreeSpecification"), 1, &mod->sml_type );
	mod->sml_bvalues = ssbva;
	mod->sml_nvalues = ssbva;
	*modtail = mod;
	modtail = &mod->sml_next;

	rc = slap_mods_check( modlist, 1, &text, txtbuf, textlen, NULL );

	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"create_context_csn_entry: mods check (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "create_context_csn_entry: mods check (%s)\n",
			 text, 0, 0 );
#endif
	}

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));

	build_new_dn( &sub_bv, &be->be_nsuffix[0], &psubrdn );
	dnPrettyNormal( NULL, &sub_bv, &e->e_name, &e->e_nname, NULL );
	ch_free( sub_bv.bv_val );
	ch_free( psubrdn.bv_val );

	e->e_attrs = NULL;

	rc = slap_mods2entry( modlist, &e, 1, 1, &text, txtbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
				"create_context_csn_entry: mods2entry (%s)\n", text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "create_context_csn_entry: mods2entry (%s)\n",
			 text, 0, 0 );
#endif
	}

	return e;
}

static int
contextcsn_callback(
	Operation* op,
	SlapReply* rs
)
{
	if ( rs->sr_type != REP_SEARCH ) {
		*((int*)op->o_callback->sc_private) = 0;
	} else {
		*((int*)op->o_callback->sc_private) = 1;
	}
	return LDAP_SUCCESS;
}
#endif
