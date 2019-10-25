# Embedded Nimrod

## Base Installation
In the `deploy` folder, you'll see several files:

* `install.yml` - The installation playbook.
* `inventory.yml` - The installation inventory. Edit this to your needs.
* `nimexec.j2` - The template for the `nimexec` program.
* `nimrod-embedded.j2` - The template for the "Modules" environment module.
* `nimrod-embedded.lua.j2` - The template for the LMOD environment module. 

To define a new host to install to, add the following to the `all` hosts section in `inventory.yml`
followed by the hostname in the `nimrod_hosts` group. Edit any fields to your liking.

```yaml
myhpc:
  # SSH Address of the HPC
  ansible_ssh_host: myhpc.ssh.login.address

  # The root installation directory, i.e. /opt/embedded-nimrod-1.1.4
  root_dir: /opt/embedded-nimrod-{{ nimrod_version }}

  # The $MODULEPATH for "Modules". An appropriate subdirectory will be created.
  # Omit this field if not required.
  # Note that at least one of the module_path_* fields is required.
  module_path_modules: /etc/modulefiles

  # The $MODULEPATH for LMOD. An appropriate subdirectory will be created.
  # Omit this field if not required.
  # Note that at least one of the module_path_* fields is required.
  module_path_lmod: /etc/modulefiles

  # The name/type of the cluster. This maps directly to $NIMRUN_CLUSTER.
  # Omit this field to autodetect.
  # Valid values are generic_{pbs,slurm,lsf}
  cluster_name: generic_pbs
```

## Steps

* Add your HPC to `inventory.yml`
* Compile `nimrun` (see instructions below)
* Put the path to the compiled `nimrun` binary in the `nimrun_binary` variable in `inventory.yml`

To install:
```bash
ansible-playbook -i inventory.yml install.yml
```

## Building nimrun

The `nimrun` executable needs to be compiled for your environment.
Example build scripts are provided in `build-rcc.sh` and `build-static.sh`.

At a minimum, at least GCC 7.2.0 (with C++17 support) is required.
