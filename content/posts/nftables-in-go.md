---
title: "Using nftables in Go"
date: "2025-11-22"
description: "Benefits and how to use nftables in native go via netlink"
tags: ["netlink", "golang", "nftables", "firewall"]
categories: ["networking", "golang"]
ShowToc: true
TocOpen: true
comments: true
draft: true
weight: 1
---

I've been recently working with the Go package [google/nftables](https://github.com/google/nftables)
written by [Michael Stapelberg](https://michael.stapelberg.ch) and wanted to
share some insights on why and how to use it as an alternative to invoking the
`nft` CLI tool via shell commands.

## Introduction

If you are familiar with [iptables](https://ipset.netfilter.org/iptables.man.html),
you probably know that it has been deprecated in favor of [nft](https://www.netfilter.org/projects/nftables/manpage.html) as the default Linux firewalling tool. Many systems still use the 
`iptables` frontend via [iptables-nft](https://www.redhat.com/en/blog/using-iptables-nft-hybrid-linux-firewall)
which bridges iptables commands to the [nftables](https://wiki.nftables.org/wiki-nftables/index.php/What_is_nftables%3F) backend. 

Those CLI tools are great for manual configuration but when it comes to 
programmatic access, using [libnftnl](https://www.netfilter.org/projects/libnftnl/index.html)
(the C library for nftables [netlink](https://linux.die.net/man/7/netlink)
communication) is a better option.

However, my goal has been to get something working in pure Go since I find it 
much easier and enjoyable to work with.

Here is where the package `google/nftables` comes into play. It provides a
native Go implementation of the netlink communication with `nftables` and allows
you to manage firewall rules directly from your Go code. For the netlink 
communication, [mdlayher/netlink](https://github.com/mdlayher/netlink) is used
under the hood.

## Why use programmatic access to nftables?

In my opinion, there are several reasons why you might want to use programmatic 
access to `nftables` instead of invoking the `nft` CLI via shell commands:
1. **Portable code**: Using a Go package allows you to write code that is 
portable across different systems without relying on the presence of the `nft`
binary.
2. **Better error handling**: Although, that may not always be the case, using a
Go package allows you to handle errors in a more structured way compared to
parsing CLI output.
3. **Optimistic concurrency control**: When using a programmatic approach, you
can query the current state of the firewall and apply changes based on that
state without worrying about concurrent modifications of the same resources by
other processes.

## What's the catch?

Of course, those benefits come with a few drawbacks:
1. **Learning curve**: Using `google/nftables` is much more complex than using 
the `nft` CLI as it is a low-level interface to the netlink protocol.
2. **Limited documentation**: The package is mostly documented in Godoc
comments, which can be sufficient but may not cover all use cases or provide
comprehensive examples.
3. **Kernel version compatibility**: Since `nftables` is a kernel feature, you
need to ensure that the target system's kernel version supports the features you
want to use. Additionally, there could be kernel changes, edge cases or bugs
that could have you [go down a rabbit hole](https://github.com/google/nftables/issues/329).

## Examples

Since using `google/nftables` can be challenging, especially for those who are
not familiar with netlink or the internal workings of `nftables`, I wanted to 
provide some practical examples to help you get started with some of the more
tricky but common use cases. 

Below are some code snippets that demonstrate how to achieve various tasks
using the package.

**Note**: 
  - To run the examples, you need to have sufficient privileges (usually root)
  or the capability `CAP_NET_ADMIN` to modify `nftables` rules.
  - Those examples are based on the latest git version of `google/nftables` in 
  the main branch. At the time of writing, the latest released version is
  `v0.0.3` does not include all the features used below.

### Basic example: Creating a table and a chain
Here is a simple example of how to create a new table and a chain in `nftables`
using the `google/nftables` package:

```go
package main
import (
    "log"
    "github.com/google/nftables"
    "github.com/google/nftables/binaryutil"
    "github.com/google/nftables/expr"
    "golang.org/x/sys/unix"
)

func main() {
    c, err := nftables.New()
    if err != nil {
        log.Fatalf("Failed to create nftables connection: %v", err)
    }

    // Create a new table
    table := &nftables.Table{
        Name:   "filter",
        Family: nftables.TableFamilyIPv4,
    }
    c.AddTable(table)

    // Create a new chain
    chain := &nftables.Chain{
        Name:     "input",
        Table:    table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookInput,
        Priority: nftables.ChainPriorityFilter,
    }
    c.AddChain(chain)

    // Commit the changes
    if err := c.Flush(); err != nil {
        log.Fatalf("Failed to flush nftables changes: %v", err)
    }
}
```

This is the equivalent of loading the following file via `nft -f`:

```
table ip filter {
    chain input {
        type filter hook input priority 0;
    }
}
```

What happens under the hood is that the package maintains a batch of netlink
messages to create the table and chain. When `Flush()` is called, the batch
is to the kernel in one go and is applied atomically in a single transaction.

### Adding a rule to drop incoming TCP traffic on port 80
Continuing from the previous example, here is how to add a rule that drops
incoming TCP traffic on port 80:

```go
rule := nftables.Rule{
    Table: table,
    Chain: chain,
    Exprs: []expr.Any{
        // Load the L4 protocol into register 1
        &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
        // Compare the value of register 1 with TCP
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
        // Load the destination port from the transport header into register 1
        &expr.Payload{
            DestRegister: 1,
            Base:         expr.PayloadBaseTransportHeader,
            // Offset for destination port
            Offset:       2,
            Len:          2,
        },
        // Compare the value of register 1 with port 80 in big-endian
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x50}},
        // Drop the packet
        &expr.Verdict{Kind: expr.VerdictDrop},
    },
}
c.AddRule(&rule)
```

### Adding a rule to compare source IP address to a CIDR
Here is an example of how to add a rule that matches packets from a specific
source IP address range (CIDR):

```go
rule := nftables.Rule{
    Table: table,
    Chain: chain,
    Exprs: []expr.Any{
        // Load the source IP address into register 1
        &expr.Payload{
            DestRegister: 1,
            Base:         expr.PayloadBaseNetworkHeader,
            // Offset for source IP in IPv4 header
            Offset:       12,
            Len:          4,
        },
        // Add a mask to match the CIDR range
        &expr.Bitwise{
            SourceRegister: 1,
            DestRegister:   1,
            Len:            4,
            // Mask for /24
            Mask:           []byte{255, 255, 255, 0},
            Xor:            []byte{0, 0, 0, 0},
        },
        // Compare the value of register 1 with the CIDR (e.g., 10.0.0.0/24)
        &expr.Cmp{
            Op:       expr.CmpOpEq,
            Register: 1,
            Data:     []byte{10, 0, 0, 0}, // Base IP of CIDR
        },
        // Accept the packet
        &expr.Verdict{Kind: expr.VerdictAccept},
    },
}
c.AddRule(&rule)
```

### Adding a rule to accept packets with state ESTABLISHED or RELATED
Here is an example of how to add a rule that accepts packets with connection
state `established` or `related`:

```go
rule := nftables.Rule{
    Table: table,
    Chain: chain,
    Exprs: []expr.Any{
        // Load the connection state into register 1
        &expr.Ct{
            Register: 1,
            Key:      expr.CtKeySTATE,
        },
        &expr.Bitwise{
            SourceRegister: 1,
            DestRegister:   1,
            Len:            4,
            // bitmask for ESTABLISHED | RELATED
            Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
            // uint32 0 for XOR
            Xor:            make([]byte, 4),
        },
        &expr.Cmp{
            Op:       expr.CmpOpNeq,
            Register: 1,
            // uint32 0 for comparison
            Data:     make([]byte, 4),
        },
        &expr.Verdict{
            Kind: expr.VerdictAccept,
        },
    },
}
c.AddRule(&rule)
```

### Adding a rule with optimistic concurrency control

Assume that you want to add a single rule to an existing chain only if the rule
does not already exist. However, since other processes may be modifying the same
chain concurrently, you want to ensure that your addition is based on the latest
state of the chain. You can achieve this by using the generation ID provided by
`nftables`. Here is an example of how to do this:

```go
// Get the current generation of the nftables configuration
gen, err := c.GetGen()
if err != nil {
    log.Fatalf("Failed to get nftables generation: %v", err)
}

// Check the current state of the chain
rules, err := c.GetRules(table, chain)
if err != nil {
    log.Fatalf("Failed to get existing rules: %v", err)
}

if len(rules) == 1 {
    log.Printf("Chain %s already has rules, skipping addition", chain.Name)
    return
}

rule := nftables.Rule{
    Table: table,
    Chain: chain,
    Exprs: []expr.Any{
        &expr.Verdict{Kind: expr.VerdictDrop},
    },
}
c.AddRule(&rule)

// Flush changes with the generation ID to ensure no concurrent modifications
if err := c.FlushWithGenID(gen.ID); err != nil {
    if (errors.Is(err, unix.ERESTART)) {
        log.Printf("Conflict detected, retrying...")
        // Retry logic here
    } else {
        log.Fatalf("Failed to flush nftables changes: %v", err)
    }
}
```

### Adding a set of CIDR ranges and using it in a rule
You can also create a set of CIDR ranges and use it in a rule for more efficient
matching:

```go
set := &nftables.Set{
    Table:    table,
    Name:     "allowed_cidrs",
    KeyType:  nftables.TypeIPAddr,
    Interval: true,
}
elements := []nftables.SetElement{
    // first IP in 10.0.0.0/24
    {Key: []byte{10, 0, 0, 0}},
    // (last IP in 10.0.0.0/24) + 1
    {Key: []byte{10, 0, 1, 0}, IntervalEnd: true},
}
c.AddSet(set, elements)

rule := nftables.Rule{
    Table: table,
    Chain: chain,
    Exprs: []expr.Any{
        // Load the source IP address into register 1
        &expr.Payload{
            DestRegister: 1,
            Base:         expr.PayloadBaseNetworkHeader,
            // Offset for source IP in IPv4 header
            Offset:       12,
            Len:          4,
        },
        // Lookup the source IP in the set
        &expr.Lookup{
            SourceRegister: 1,
            SetName:        "allowed_cidrs",
            SetID:          set.ID,
        },
        // Accept the packet if found in the set
        &expr.Verdict{Kind: expr.VerdictAccept},
    },
}
c.AddRule(&rule)
```

Notice how the CIDR range is represented as two separate entries in the set:
  1. The first IP address of the range
  2. The last IP address of the range + 1 with the `IntervalEnd` flag set.

This is not something that you would have to think about when using the `nft` 
CLI where you can simply do the following instead:

```
table ip filter {
    set allowed_cidrs {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.0/24 }
    }
}
```

To make matters even more complicated, if the CIDR range goes all the way to the
end of the address space (e.g., `128.0.0.0/1`), you need to do something like
this instead:

```go
elements := []nftables.SetElement{
    // There is no upper bound
    {Key: []byte{128, 0, 0, 0}, IntervalOpen: true},
}
```

### Finding more examples

Since the documentation of `google/nftables` is limited, I would recommend
looking at the integration [tests](https://github.com/google/nftables/blob/main/nftables_test.go) to find more examples like the ones above.

## Summary

As seen above, programmatic access to `nftables` can be challenging but it also
comes with great benefits as long as you are aware of the potential pitfalls.

Having proper testing and error handling in place can give you confidence that
your code will work as expected in production environments. I would recommend
running your tests against the latest stable kernel version to make sure that
there are no compatibility issues and if you can, test against multiple kernel
versions to ensure broader compatibility.

I may publish a follow-up post that goes into the debugging process when things
don't work as expected. If you have any questions about the examples or want to
share your own  experiences with `nftables` in Go, feel free to reach out to me
via email.