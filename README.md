# Straw - The simple tool to suck the config out of your Slurm beverage!

Straw is a simple cli tool meant to fetch the slurm config from a Slurm server running the slurmctld.

## Why Straw?

In order to create tools and clients that interact with a Slurm cluster, you need at least the following:
* The Slurm config file(s).
* The authentication tokens.

Most of the time, this involves:
* Either maintaining a copy of your slurm config file(s), or running slurmd in configless mode.
* The munged daemon configured with a munge key for authentication

When containerising tools or clients that interact with the Slurm cluster, it is undesirable having to run
these extra services.

Straw is a one-shot cli tool that fetches the slurm config files, removing the burden of setting up some of these extra services
and greatly simplifying containerisation of slurm tools.

## Usage

Running this tool requires python 3. If you're using munge to authenticate, you must run this tool as either
the slurm user or root.

```
python straw.py [--auth=<auth_method>] <slurmctld.domain.com> <slurm version>
Where auth_method is either munge or jwt. The default auth method is munge.
```

Both the hostname of the slurmctld and the slurm version are mandatory. The slurm version should match that of
the slurmctld server, as this will determine the Slurm protocol version that straw will use.
