// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#pragma once

enum {
  RX_OK,
  RX_REDIRECT,
  RX_DROP,
  RX_RECIRCULATE,
  RX_ERROR,
};

struct type_value {
  u64 type:8;
  u64 value:56;
};
struct metadata {
  // An array of type/value pairs for the module to do with as it pleases. The
  // array is initialized to zero when the event first enters the module chain.
  // The values are preserved across modules.
  struct type_value data[8];

  // A field reserved for use by the wrapper and helper functions.
  u32 flags;

  // The length of the packet currently being processed. Read-only.
  u32 pktlen;

  // The module id currently processing the packet.
  int module_id;

  // The interface on which a packet was received. Numbering is local to the
  // module.
  int in_ifc;

  // If the module intends to forward the packet, it must call pkt_redirect to
  // set this field to determine the next-hop.
  int redir_ifc;

  int clone_ifc;
};

// iomodule must implement this function to attach to the networking stack
static int handle_rx(void *pkt, struct metadata *md);

static int pkt_redirect(void *pkt, struct metadata *md, int ifc);
static int pkt_mirror(void *pkt, struct metadata *md, int ifc);
static int pkt_drop(void *pkt, struct metadata *md);
