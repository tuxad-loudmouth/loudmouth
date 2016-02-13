/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2003-2006 Imendio AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses>
 */

#include "lm-debug.h"
#include "lm-ssl-base.h"
#include "lm-ssl-internals.h"

void
_lm_ssl_base_init (LmSSLBase      *base,
                   const gchar    *expected_fingerprint,
                   LmSSLFunction   ssl_function,
                   gpointer        user_data,
                   GDestroyNotify  notify)
{
    base->ref_count      = 1;
    base->func           = ssl_function;
    base->func_data      = user_data;
    base->data_notify    = notify;
    base->fingerprint[0] = '\0';
    base->cipher_list    = NULL;

    if (expected_fingerprint) {
        if (!g_str_has_prefix(expected_fingerprint, LM_FINGERPRINT_PREFIX)) {
          /* let's set a bogus hash because the user tries to use a hash
             we don't support now */
          expected_fingerprint = "wrong_hash_format";
          g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "Wrong hash format, use "
                 LM_FINGERPRINT_PREFIX"$hash");
        }
        base->expected_fingerprint = g_strndup(expected_fingerprint,
                                               LM_FINGERPRINT_LENGTH);
    } else {
        base->expected_fingerprint = NULL;
    }

    if (!base->func) {
        /* If user didn't provide an SSL func the default will be used
         * this function will always tell the connection to continue.
         */
        base->func = _lm_ssl_func_always_continue;
    }
}

void
_lm_ssl_base_set_cipher_list (LmSSLBase   *base,
                              const gchar *cipher_list)
{
    if (base->cipher_list)
        g_free (base->cipher_list);
    base->cipher_list = g_strdup (cipher_list);
}

void
_lm_ssl_base_set_ca_path (LmSSLBase   *base,
                          const gchar *ca_path)
{
    if (base->ca_path)
        g_free (base->ca_path);
    base->ca_path = g_strdup (ca_path);
}

void
_lm_ssl_base_set_fingerprint (LmSSLBase    *base,
                              const guchar *digest,
                              unsigned int  digest_len)
{
    gchar hex[LM_FINGERPRINT_LENGTH];
    gchar *p;
    int i;

    g_assert(LM_FINGERPRINT_PREFIX != NULL);
    g_assert(digest != NULL);
    g_assert(digest_len > 0);
    g_assert(LM_FINGERPRINT_LENGTH >=
             (sizeof(LM_FINGERPRINT_PREFIX) + digest_len*2));

    for (p = hex, i = 0; i < digest_len ; i++, p+=2) {
        g_snprintf(p, 3, "%02x", digest[i]);
    }
    g_snprintf(base->fingerprint, LM_FINGERPRINT_LENGTH,
               "%s%s",
               LM_FINGERPRINT_PREFIX,
               hex);
}

int _lm_ssl_base_check_fingerprint( LmSSLBase *base)
{
    if (base->expected_fingerprint == NULL) {
        return 0;
    }
    return g_ascii_strcasecmp(base->expected_fingerprint, base->fingerprint);
}

void
_lm_ssl_base_free_fields (LmSSLBase *base)
{
    g_free (base->expected_fingerprint);
    g_free (base->cipher_list);
    g_free (base->ca_path);
}

