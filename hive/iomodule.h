// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#pragma once

enum {
  RX_OK,
  RX_REDIRECT,
  RX_DROP,
  //RX_RECIRCULATE,
  RX_ERROR,
};

struct metadata {
  u64 data[8];
  u32 flags;
  int module_id;
  int in_ifc;
  int redir_ifc;
  int clone_ifc;
};

// iomodule must implement this function to attach to the networking stack
static int handle_rx(void *pkt, struct metadata *md);

static int pkt_redirect(void *pkt, struct metadata *md, int ifc);
static int pkt_mirror(void *pkt, struct metadata *md, int ifc);
static int pkt_drop(void *pkt, struct metadata *md);
