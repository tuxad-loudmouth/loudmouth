/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Imendio AB
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
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>

#include "lm-marshal.h"
#include "lm-feature-ping.h"

#define GET_PRIV(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), LM_TYPE_FEATURE_PING, LmFeaturePingPriv))

typedef struct LmFeaturePingPriv LmFeaturePingPriv;
struct LmFeaturePingPriv {
	gint my_prop;
};

static void     feature_ping_finalize            (GObject           *object);
static void     feature_ping_get_property        (GObject           *object,
					   guint              param_id,
					   GValue            *value,
					   GParamSpec        *pspec);
static void     feature_ping_set_property        (GObject           *object,
					   guint              param_id,
					   const GValue      *value,
					   GParamSpec        *pspec);

G_DEFINE_TYPE (LmFeaturePing, lm_feature_ping, G_TYPE_OBJECT)

enum {
	PROP_0,
	PROP_MY_PROP
};

enum {
	SIGNAL_NAME,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
lm_feature_ping_class_init (LmFeaturePingClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->finalize     = feature_ping_finalize;
	object_class->get_property = feature_ping_get_property;
	object_class->set_property = feature_ping_set_property;

	g_object_class_install_property (object_class,
					 PROP_MY_PROP,
					 g_param_spec_string ("my-prop",
							      "My Prop",
							      "My Property",
							      NULL,
							      G_PARAM_READWRITE));
	
	signals[SIGNAL_NAME] = 
		g_signal_new ("signal-name",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      lm_marshal_VOID__INT,
			      G_TYPE_NONE, 
			      1, G_TYPE_INT);
	
	g_type_class_add_private (object_class, sizeof (LmFeaturePingPriv));
}

static void
lm_feature_ping_init (LmFeaturePing *feature_ping)
{
	LmFeaturePingPriv *priv;

	priv = GET_PRIV (feature_ping);

}

static void
feature_ping_finalize (GObject *object)
{
	LmFeaturePingPriv *priv;

	priv = GET_PRIV (object);

	(G_OBJECT_CLASS (lm_feature_ping_parent_class)->finalize) (object);
}

static void
feature_ping_get_property (GObject    *object,
		   guint       param_id,
		   GValue     *value,
		   GParamSpec *pspec)
{
	LmFeaturePingPriv *priv;

	priv = GET_PRIV (object);

	switch (param_id) {
	case PROP_MY_PROP:
		g_value_set_int (value, priv->my_prop);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
		break;
	};
}

static void
feature_ping_set_property (GObject      *object,
		   guint         param_id,
		   const GValue *value,
		   GParamSpec   *pspec)
{
	LmFeaturePingPriv *priv;

	priv = GET_PRIV (object);

	switch (param_id) {
	case PROP_MY_PROP:
		priv->my_prop = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
		break;
	};
}

