// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

#include "iomodule.h"

BPF_TABLE("array", int, struct metadata, metadata, 8);
BPF_TABLE("prog", int, int, modules, 1);

int handle_rx_wrapper(struct __sk_buff *skb) {
  int md_id = skb->cb[0];
  struct metadata *md = metadata.lookup(&md_id);
  if (!md)
    return TC_ACT_SHOT;
  // copy to stack to avoid verifier confusion
  //struct metadata local_md = *md;
  //local_md.flags = 0;
  //local_md.redir_ifc = 0;
  //local_md.clone_ifc = 0;
  md->flags = 0;
  md->redir_ifc = 0;
  md->clone_ifc = 0;

  int rc = handle_rx(skb, md);
  switch (rc) {
    case RX_OK:
      break;
    case RX_REDIRECT:
      break;
    case RX_DROP:
      return TC_ACT_SHOT;
  }
  //metadata.update(&md_id, &local_md);
  return TC_ACT_SHOT;
}

static int pkt_redirect(void *pkt, struct metadata *md, int ifc) {
  md->redir_ifc = ifc;
  return TC_ACT_OK;
}

static int pkt_mirror(void *pkt, struct metadata *md, int ifc) {
  md->clone_ifc = ifc;
  return TC_ACT_OK;
}
