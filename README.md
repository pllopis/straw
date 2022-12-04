# 🥤 Straw for your Slurm beverage!

Straw is a simple and minimalistic one-shot cli tool that fetches the slurm config files from a Slurm server running the slurmctld.
It can greatly simplify the deployment of (containerised) environments that interact as clients with Slurm clusters by removing the need
for maintaining munge keys, slurm config files, as well as slurmd, and munge daemons.

## Why Straw?

In order to create tools and clients that interact with a Slurm cluster, an environment/container usually needs at least the following:
* The Slurm config file(s).
* The Munge authentication tokens.

Most of the time, this involves:
* Either maintaining a copy of your slurm config file(s), or running slurmd with configless mode.
* The munged daemon configured with a munge key for authentication

When containerising tools or clients that interact with the Slurm cluster, it is undesirable having to run
and setup these extra services on each container, and managing the munge.key that is shared in the cluster requires utmost care.

In fact, when building Slurm client environments (such as containers), due to how Slurm tools have been designed,
you must choose between either a *configless* setup, or a munge *secretless* setup.

*Configless setup* refers to an environment which is agnostic to slurm config files (no need update and put these files in your environment).

*Secretless setup* refers to not needing to share the secret munge key with your environment.

One way to go munge-secretless is to rely on JWT tokens (which arguably are a secret, but where the risk implications are much lower than the munge key).
However, Slurm tools can not use JWT tokens and configless mode simultaneously.
And while it is possible to use JWT in combination with a minimalistic slurm.conf with just the `SlurmctldHost` and `Clustername`,
some commands such as srun refuse to run without more information in the slurm.conf, limiting the usefulness of this approach.

Straw is a one-shot cli tool that aims to greatly simplify these use cases, and provide increased security for these environments.

Straw fetches the slurm config files, optionally using JWT authentication, removing the burden of setting up and running both slurmd and munged,
and allowing *configless* and *munge-secretless* environments to interact with Slurm clusters.

## How does it work?

Straw talks just enough of the Slurm protocol to be able to retrieve the config files, and perform either munge or jwt authentication,
in a way that regular Slurm tools don't.

Therefore you can create containers that do not contain neither the slurm.conf files, nor munge secrets, nor run additional daemons (such as munge or slurmd).
Just add straw to your container and call it early on during initialisation, ensuring your environment starts after having fetched all slurm config files.

## Requirements

Running this tool requires python 3, and a few libraries listed in the requirements.txt.

If you're using munge to authenticate, you must run this tool as either
the Slurm user, or root. The slurmctld needs to have [configless mode](https://slurm.schedmd.com/configless_slurm.html) enabled as well.  
Optionally, for JWT authentication you'll need to enable [JWT support](https://slurm.schedmd.com/jwt.html) in your slurmctld.

## Usage

```
python straw.py [--auth=<munge|jwt>] <slurmctld.domain.com> <slurm version>
```

Where auth\_method is either`munge` or `jwt`. The default auth method is munge.  
When using jwt authentication, the token will be grabbed from the `SLURM_JWT` environment variable.

The slurm version should include the major release (first two parts), e.g. `22.05`.

Both the hostname of the slurmctld and the slurm version are mandatory. The slurm version should match that of
the slurmctld server, as this will determine the Slurm protocol version that straw will use to communicate with the slurmctld.
