# Bomfather Agent

Bomfather Agent is an eBPF-based agent that runs in the kernel space to block actions based on a policy.

We built this agent to solve the problems we had with existing solutions.

1. They were too complex to set up and use.
2. They were too slow and inefficient.
3. And even if they were simple to set up, they were not secure and/or flexible enough to work for a variety of use cases.

These points are our North Star for this entire project. All features and developments are meant to fulfill these points.

*Note that we try to avoid using AI generated code in this repo and won't be accepting AI generated PRs.*

## Features

* Simple to use: All you need is an LSM enabled kernel. You install the agent, create a 5 to 10 line policy file, launch the agent, and you’re good to go.
* Default deny all policy: When a restriction is applied (e.g., a process is allowed to read a file), it is applied to all processes, and only whitelisted processes are allowed to bypass the restriction.
* Executable based policy enforcement: Almost all of the policy is based on an executable and what resources (e.g. files, gpu’s, network, etc.) it can access.
* Fast and efficient: The agent runs in kernel space and uses eBPF and LSM hooks to enforce the policy, which is vastly more efficient than userspace tools like strace.

## Prerequisites

(Here is a guide on how to enable LSM on your system: https://docs.bomfather.dev/prerequisites)

* Linux kernel 5.18 or higher
* LSM enabled on the system

## Installation

### With Source

To build from source, you need to have the following tools installed:

```
go 1.26 or higher
make
clang
llvm
llvm-14
protobuf-compiler
git
```

On Debian/Ubuntu, you can install the non-Go build dependencies with:

```
apt-get update \
  && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    llvm-14 \
    protobuf-compiler \
  && rm -rf /var/lib/apt/lists/*
```

Then build the agent with:

```
make
```

## Quickstart

For a quick start, you can use the following command to run the agent with a default policy:

```
sudo ./agent run --config config.yaml
```

This will run the agent with whatever policy is defined in the config file.

You can then optionally use the following command to see the status of the agent:

```
sudo ./agent status --help
```

The status command is primarily for reading Prometheus metrics from the agent.

## How to create a policy

A policy is a YAML file that defines the rules the agent enforces.

The config is mainly made up of two sections, `policies` and `attributes`. The `policies` section defines who is allowed to access a protected resource. The policies section defines what executables are allowed to access protected directories or IPs. `attributes` define the boundaries of an executable, so an attribute can make an executable connect only to a single IP and block it from connecting to any other IP. 

There are many ways to create a policy, so for each feature, we have a dedicated section in the documentation that explains how to create a policy for that feature: https://docs.bomfather.dev/configuration-guide.

But for a quick-start use case, you can use the following policy file:

```
policies:
  - executable: "filepath = [absolute-path]/app/signer"
    can_access_dirs:
      - "[absolute-path]/secrets/keys : read"
    is_allowed_to_access_ip:
      - "kms.us-east-1.amazonaws.com:443"

attributes:
  - path: "type = executable | filepath = [absolute-path]/app/signer"
    can_only_access_ips:
      - "kms.us-east-1.amazonaws.com:443"
```

This policy allows us to sandbox the signer and ensure it is the only process on the system that can access the data.

In the policies section, we define that the executable signer is the only process allowed to access the /secrets/keys directory and the IP’s associated with the AWS KMS endpoint.

In the attributes section, we define that the executable signer is only allowed to access the AWS KMS endpoint, and no other IPs.

In this relatively simple config, we have been able to significantly harden our signer process (which in the real world could be part of a larger system) in a config that is only 10 lines long.

There are a couple of more real-world examples in the documentation https://docs.bomfather.dev/examples/gpu.

## API keys

Optionally, if you want to export the violations the agent detects, you can include an API key and the agent will send the violations to the Bomfather servers.

But most importantly, THIS IS NOT MANDATORY, the agent will still function the same way without it. No features are disabled if you don’t include an API key, and if no API key is included, no data of any kind is sent to the Bomfather servers.

If you do want to use Bomfather servers, please contact us at founders@bomfather.dev.
