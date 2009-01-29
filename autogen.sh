#!/bin/sh
# Run this to generate all the initial makefiles, etc.

: ${AUTORECONF=autoreconf}
: ${GTKDOCIZE=gtkdocize}

$GTKDOCIZE || exit 1
$AUTORECONF --install || exit 1
