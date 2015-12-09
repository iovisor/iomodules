// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>
#include <uapi/linux/pkt_cls.h>

#include "iomodule.h"

BPF_TABLE("array", int, struct metadata, metadata, 8);

BPF_TABLE("prog", int, int, modules, 1024);

struct link_key {
  int module_id;
  int ifc;
};

struct link {
  int module_id;
  int ifc;
  u64 packets;
  u64 bytes;
};

BPF_TABLE("hash", struct link_key, struct link, links, 1024);

// Invoke the next module in the chain.
// When next module is a bpf function and is successfully invoked, this
// function never returns.
static int invoke_module(struct __sk_buff *skb, struct metadata *md, struct link *link) {
  if (link->module_id != 0) {
    md->in_ifc = link->ifc;
    md->module_id = link->module_id;
    modules.call(skb, md->module_id);
  } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    bpf_redirect(link->ifc, 0);
    return TC_ACT_REDIRECT;
#else
    bpf_clone_redirect(skb, link->ifc, 0);
    return TC_ACT_SHOT;
#endif
  }
  return TC_ACT_SHOT;
}

int recv_netdev(struct __sk_buff *skb) {
  int md_id = bpf_get_smp_processor_id();
  struct metadata *md = metadata.lookup(&md_id);
  if (!md)
    return TC_ACT_SHOT;

  skb->cb[0] = md_id;

  struct link_key lkey = {
    .module_id = 0,
    .ifc = skb->ifindex,
  };
  struct link *link = links.lookup(&lkey);
  if (!link)
    return TC_ACT_SHOT;

  *md = (struct metadata){};
  return invoke_module(skb, md, link);
}

int recv_tailcall(struct __sk_buff *skb) {
  int md_id = skb->cb[0];
  struct metadata *md = metadata.lookup(&md_id);
  if (!md)
    return TC_ACT_SHOT;

  struct link_key lkey = {
    .module_id = md->module_id,
    .ifc = md->redir_ifc,
  };
  struct link *link = links.lookup(&lkey);
  if (!link)
    return TC_ACT_SHOT;

  return invoke_module(skb, md, link);
}
