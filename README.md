# 🥤 Straw for your Slurm beverage!

Straw is a simple and minimalistic one-shot cli tool that fetches the Slurm config files from a Slurm server running the slurmctld.
It can greatly simplify the deployment of (containerised) environments that interact as clients with Slurm clusters by removing the need
for maintaining munge keys, Slurm config files, as well as slurmd, and munge daemons.

## Why Straw?

In order to create tools and clients that interact with a Slurm cluster, an environment/container usually needs at least the following:
* The Slurm config file(s).
* The Munge authentication tokens.

Most of the time, this involves:
* Either maintaining a copy of your Slurm config file(s), or running slurmd with configless mode.
* The munged daemon configured with a munge key for authentication

When containerising tools or clients that interact with the Slurm cluster, it is undesirable having to run
and setup these extra services on each container, and managing the munge.key that is shared in the cluster requires utmost care.

In fact, when building Slurm client environments (such as containers), due to how Slurm tools have been designed,
you must choose between either a *configless* setup, or a munge *secretless* setup.

*Configless setup* refers to an environment which is agnostic to Slurm config files (no need update and put these files in your environment).

*Secretless setup* refers to not needing to share the secret munge key with your environment.

For instance, you may want to connect some notebook service that is exposed to the internet to your Slurm cluster. In this situation, you might prefer not to keep the Slurm munge key in the public notebook service that's exposed to the wider Internet.

```
   D M Z       firewall
                  │
┌────────────┐    │    ┌───────────┐
│            │    │    │           │
│  Public    │    │    │  Private  │
│  notebook  │    │    │  Slurm    │
│  service   │    │    │  cluster  │
│            │    │    │           │
└────────────┘    │    └───────────┘
```

One way to go munge-secretless is to rely on JWT tokens (which arguably are a secret, but where the risk implications are much lower than the munge key).
However, Slurm tools can not use JWT tokens and configless mode simultaneously.
And while it is possible to use JWT in combination with a minimalistic slurm.conf with just the `SlurmctldHost` and `Clustername`,
some commands such as srun refuse to run without more information in the slurm.conf, limiting the usefulness of this approach.

Straw is a one-shot cli tool that aims to greatly simplify these use cases, and provide increased security for these environments.

Straw fetches the Slurm config files, optionally using JWT authentication, removing the burden of setting up and running both slurmd and munged,
and allowing *configless* and *munge-secretless* environments to interact with Slurm clusters.

## How does it work?

Straw talks just enough of the Slurm protocol to be able to retrieve the config files, and perform either munge or jwt authentication,
in a way that regular Slurm tools don't.

Therefore you can create containers that do not contain neither the slurm.conf files, nor munge secrets, nor run additional daemons (such as munge or slurmd).
Just add straw to your container and call it early on during initialisation, ensuring your environment starts after having fetched all Slurm config files.

## Requirements

Running this tool requires python 3.

If you're using munge to authenticate, you must run this tool as either
the Slurm user, or root. The slurmctld needs to have [configless mode](https://slurm.schedmd.com/configless_slurm.html) enabled as well.  
Optionally, for JWT authentication you'll need to enable [JWT support](https://slurm.schedmd.com/jwt.html) in your slurmctld.

## Building

With munge support
```
pip install "straw[munge] @ git+https://github.com/pllopis/straw"
```

Without munge support
```
pip install "straw @ git+https://github.com/pllopis/straw"
```

## Usage

```
usage: straw.py [-h] [--auth {munge,jwt}] [-o OUTPUT_DIR] [-v] [-V] [-l] server [server ...] version

positional arguments:
  server                slurmctld server in server[:port] notation
  version               Slurm major version that corresponds to that of the slurmctld server (e.g. 22.05)

options:
  -h, --help            show this help message and exit
  --auth {munge,jwt}    Authentication method (default: jwt)
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Existing output directory where config files will be saved (default: ./)
  -v, --verbose         Increase output verbosity. Rrepetitions allowed. (default: None)
  -V, --version         show program's version number and exit
  -l, --list            List available protocol versions (default: False)
```

Where auth\_method is either `munge` or `jwt`. The `pymunge` import is conditional on using munge as authentication method, so if yo do not need munge, the library requirement is also not needed.
When using jwt authentication, the token will be grabbed from the `SLURM_JWT` environment variable.

The Slurm version should include the major release (first two parts), e.g. `22.05`.
It should also match that of the slurmctld server, as this will determine the Slurm protocol version that straw will use to communicate with the slurmctld.
