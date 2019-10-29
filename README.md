# Embedded Nimrod

## Background

The Nimrod portal is a well established tool for high throughput computing providing a mechanism to process many jobs on HPCs without the need for individual job submissions. The Nimrod portal sits outside of HPC and submits work to the HPC on your behalf.
 
Embedded Nimrod is a version of the Nimrod high throughput computing tool that can be utilized _within_ batch jobs on the HPC.

Embedded Nimrod builds a miniature Nimrod environment _within_ your PBS job resources and starts processing the experiment plan file you included with the job submission.

## Embedded Nimrod Use Cases

Embedded Nimrod is best suited for the following use cases:
* workloads with tasks that are repeated over and over for statistical sampling,
* workloads with tasks that are run with different input parameters,
* workloads with tasks that have a relatively, or annoyingly, short walltime, 
(such that the time taken to set up and take down the job is comparable to the walltime of the actual task,
* workloads where the computing footprint of each task is relatively small (e.g. `ncpus=1:mem=1gb`) 

## Advantages

1. Unlike a job array or a sequence of regular batch jobs (eek!), all the looping over parameter values or inputs can be contained within the one PBS job. 
2. Once an embedded Nimrod job starts it should keep going until all the parameter combinations are finished.
3. Once your job starts, the node resources you requested are yours for the duration of the walltime (or until the Nimrod experiment has been completed) 
4. You can request as much resource as you need. Ideally this would be an entire node, and you would get as many instances (agents) running as can fit within the computational resources.
    *  If, for example, your tasks require 2 cores each (`ompthreads=2`), then if you requested `ncpus=24` cores in total, then you would automatically get 12 tasks running in parallel.
    *  If, instead, your tasks require 1 core (`ompthreads=1`) and 10GB of RAM, then if you requested `ncpus=12` cores then 12 agents running your processing would fit within the RAM of a Tinaroo HPC node. 
5. Unlike Job Arrays which are constrained to a single integer index value and your imagination for how to use it, the Nimrod experiment plan file allows for a variety of parameter types and methods of specifying them.
6. The configuration of tasks within the job are primarily governed by two resource parameters, *`ncpus`* and *`ompthreads`*. Memory footprint also needs to specified.
7. Embedded Nimrod can be run with multiple nodes (`select=4`). To extend our previous example, if your tasks require 2 cores each (`ompthreads=2`) and you request 24 cores (`ncpus=24`) on 4 nodes (`select=4`), then you would get 48 tasks runnning in parallel.

The formula used to determine the number of agents to spawn is:
```
select * (ncpus / ompthreads)
```

## Disadvantages

1. Unlike job arrays, you need to ensure that you request sufficient memory for the _total_ number of tasks that will run concurrently on the same node. 
2. If you had a large number of parameter combinations to run through you might have to break the sweeps up into more manageable chunks.
3. It kinda forces you to use TMPDIR ;-)

## Parameter Types and Declarations

The following parameter types and declarations are supported:

* ranges of integers 

  `parameter i integer range from 1 to 11 step 2`

* lists of integers 

  `parameter j integer select anyof 1 3 5 7 9`

* ranges and lists of float parameter values 

  `parameter x float range from 1.5 to 1.8 step 0.1`

  `parameter y float range from 5.0E2 to 5.5E2 step 0.1E2`

  `parameter z float select anyof 1.51 1.55 1.62 1.77 1.80`

* single or lists of text values

  `parameter t text "someText"`

  `parameter u text select anyof "AAA" "BBB" "CCC"`

* random selections of values in a range

  `parameter k integer random from 1 to 101 points 5`

* ~~even an empty parameter that gets updated later using a JSON file inputted to the Nimrod~~
  - coming soon(tm)

## How to Use Embedded Nimrod

Using Embedded Nimrod is as simple as:
* adding `#NIM` specifications to your existing PBSPro job submission script
* increasing the resource requests to match the number of jobs you want to run in parallel.
* submitting your PBS job script 
* waiting for PBS job to start and for the _magic_ to happen


While the job is running, the batch system will deploy and run a personal Nimrod/G infrastructure to manage the combinations of parameters contained in the plan file.

### A Sample Job Script 

```bash
#!/usr/bin/env nimexec
#PBS -N NimrodDemo
#PBS -A UQ-RCC
#PBS -l walltime=168:00:00
#PBS -l select=4:ncpus=12:ompthreads=2:mem=24GB

#NIM shebang /bin/bash
#NIM parameter i integer range from 1 to 3 step 1
#NIM parameter x float range from 5.0E2 to 5.2E2 step 0.2E2
#NIM parameter y float range from 1.5 to 1.7 step 0.2

# In this demo I will run 24 tasks in parallel (with 2cpus & 4GB per task) in 4 half a HPC nodes.
# The select statement is requesting ncpus=12 (i.e. 6x2cpus) and mem=24GB (i.e. 6x4GB) 
# The ompthreads value governs how many cpus each task is allocated, and ncpus / ompthreads governs how parallel instances can fit.
# The walltime is the total for the entire job (i.e. a multiple of the single task walltime)


echo "$NIMROD_VAR_i,$NIMROD_VAR_x,$NIMROD_VAR_y"
```

#### Beware of System Load

This is not really a parsing gotcha but worth a mention, nonetheless.

We have seen situations where the PBS Pro batch system intervenes when it detects excessive load.
(your job is supposed to stay within the jobs resources you requested)
The batch system allows a little bit of momentary lee-way but will quickly kill off a job that appears to be running out of control.

If your Nimrod experiment involves strenuous computations, and/or uses Java or MATLAB compiler runtime environments, then you may need to decrease the density of tasks running by increasing the ompthreads setting.

So, for example, if your job could run on a single CPU and you might like to run your experiment with `ompthreads=2` to halve the number of tasks performed concurrently.

We are working on a better mechanism to handle this situation.

#### Environment variables and modules don't inherit across nodes

When using multi-node jobs, environment variables (and thus modules) aren't carried over. If a custom environment or modules are required, it is recommended that load any required modules within the job script.

## License

This project is licensed under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0):

Copyright &copy; 2019 [The University of Queensland](http://uq.edu.au/)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

* * *

This project uses the [`JSON for Modern C++`](https://github.com/nlohmann/json) library by Niels Lohmann which is licensed under the [MIT License](http://opensource.org/licenses/MIT) (see above). Copyright &copy; 2013-2018 [Niels Lohmann](http://nlohmann.me/)

* * *

This project uses the [`parg`](https://github.com/jibsen/parg) library by Jørgen Ibsen which is licensed under [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
