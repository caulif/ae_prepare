# Our custom modules.
from Kernel import Kernel
from agent.Aion.SA_ClientAgent import SA_ClientAgent as ClientAgent
from agent.Aion.SA_Aggregator import SA_AggregatorAgent as AggregatorAgent
from model.LatencyModel import LatencyModel
from util import util
from util import param

# Standard modules.
from datetime import timedelta
from math import floor
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
import numpy as np
from os.path import exists
import pandas as pd
from sys import exit
from time import time

# Some config files require additional command line parameters to easily
# control agent or simulation hyperparameters during coarse parallelization.
import argparse

parser = argparse.ArgumentParser(description='Detailed options for PPFL config.')
parser.add_argument('-c', '--config', required=True,
                    help='Name of config file to execute')
parser.add_argument('-i', '--num_iterations', type=int, default=5,
                    help='Number of iterations for the secure multiparty protocol)')
parser.add_argument('-k', '--skip_log', action='store_true',
                    help='Skip writing agent logs to disk')
parser.add_argument('-l', '--log_dir', default=None,
                    help='Log directory name (default: unix timestamp at program start)')
parser.add_argument('-n', '--num_clients', type=int, default=5,
                    help='Number of clients for the secure multiparty protocol)')
parser.add_argument('--round_time', type=int, default=10,
                    help='Fixed time the server waits for one round')
parser.add_argument('-s', '--seed', type=int, default=None,
                    help='numpy.random.seed() for simulation')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Maximum verbosity!')
parser.add_argument('-p', '--parallel_mode', type=bool, default=True,
                    help='turn on parallel mode at server side')
parser.add_argument('-d', '--debug_mode', type=bool, default=False,
                    help='print debug info')
parser.add_argument('-V' , '--vector_len', type=int, default=1000, help='vector length')
parser.add_argument('-A', '--aggregator_size', type=int, default=16, help='Size of the aggregator')

args, remaining_args = parser.parse_known_args()


# Historical date to simulate.  Required even if not relevant.
historical_date = pd.to_datetime('2023-01-01')

# Requested log directory.
log_dir = args.log_dir
skip_log = args.skip_log

# Random seed specification on the command line.  Default: None (by clock).
# If none, we select one via a specific random method and pass it to seed()
# so we can record it for future use.  (You cannot reasonably obtain the
# automatically generated seed when seed() is called without a parameter.)

# Note that this seed is used to (1) make any random decisions within this
# config file itself and (2) to generate random number seeds for the
# (separate) Random objects given to each agent.  This ensure that when
# the agent population is appended, prior agents will continue to behave
# in the same manner save for influences by the new agents.  (i.e. all prior
# agents still have their own separate PRNG sequence, and it is the same as
# before)

seed = args.seed
if not seed: seed = int(pd.Timestamp.now().timestamp() * 1000000) % (2 ** 32 - 1)
np.random.seed(seed)

# Config parameter that causes util.util.print to suppress most output.
util.silent_mode = not args.verbose

num_clients = args.num_clients
round_time = args.round_time
num_iterations = args.num_iterations
parallel_mode = args.parallel_mode
debug_mode = args.debug_mode
vector_len = args.vector_len
aggregator_size = args.aggregator_size

# split_size = args.split_size
# max_logreg_iterations = args.max_logreg_iterations
# epsilon = args.epsilon
# learning_rate = args.learning_rate
# clear_learning = args.clear_learning
# collusion = args.collusion



# Since the simulator often pulls historical data, we use a real-world
# nanosecond timestamp (pandas.Timestamp) for our discrete time "steps",
# which are considered to be nanoseconds.  For other (or abstract) time
# units, one can either configure the Timestamp interval, or simply
# interpret the nanoseconds as something else.

# What is the earliest available time for an agent to act during the
# simulation?
midnight = historical_date
kernelStartTime = midnight

# When should the Kernel shut down?
kernelStopTime = midnight + pd.to_timedelta('2000:00:00')

# This will configure the kernel with a default computation delay
# (time penalty) for each agent's wakeup and recvMsg.  An agent
# can change this at any time for itself.  (nanoseconds)
defaultComputationDelay = 1000000000 * 0.1  # ns

# IMPORTANT NOTE CONCERNING AGENT IDS: the id passed to each agent must:
#    1. be unique
#    2. equal its index in the agents list
# This is to avoid having to call an extra getAgentListIndexByID()
# in the kernel every single time an agent must be referenced.


### Configure the Kernel.
kernel = Kernel("Base Kernel",
                random_state=np.random.RandomState(seed=np.random.randint(low=0, high=2 ** 32, dtype='uint64')))

### Obtain random state for whatever latency model will be used.
latency_rstate = np.random.RandomState(seed=np.random.randint(low=0, high=2 ** 32, dtype='uint64'))

### Configure the agents.  When conducting "agent of change" experiments, the
### new agents should be added at the END only.
agent_count = 0
agents = []
agent_types = []

### What accuracy multiplier will be used?
accy_multiplier = 100000

### What will be the scale of the shared secret?
secret_scale = 1000000

### FOR MACHINE LEARNING APPLICATIONS: LOAD DATA HERE
#
#   The data should be loaded only once (for speed).  Data should usually be
#   shuffled, split into training and test data, and passed to the client
#   parties.
#
#   X_data should be a numpy array with column-wise features and row-wise
#   examples.  y_data should contain the same number of rows (examples)
#   and a single column representing the label.
#
#   Usually this will be passed through a function to shuffle and split
#   the data into the structures expected by the PPFL clients.  For example:
#   X_train, X_test, y_train, y_test = train_test_split(X_data, y_data, test_size=0.25, random_state = shuffle_seed)
#

# For the template, we generate some random numbers that could serve as example data.
# Note that this data is unlikely to be useful for learning.  It just fills the need
# for data of a specific format.

# Randomly shuffle and split the data for training and testing.
# X_train, X_test, y_train, y_test = train_test_split(X_data, y_data, test_size=0.25)

#
#
### END OF LOAD DATA SECTION


### Configure a population of cooperating learning client agents.
a, b = agent_count, agent_count + num_clients

client_init_start = time()

# Iterate over all client IDs.
# Client index number starts from 1.
for i in range(a, b):
    agents.append(ClientAgent(id=i,
                              name="PPFL Client Agent {}".format(i),
                              type="ClientAgent",
                              iterations=num_iterations,
                              num_clients=num_clients,
                              debug_mode=debug_mode,
                              vector_len = vector_len,
                              aggregator_size=aggregator_size,
                              random_state=np.random.RandomState(
                                  seed=np.random.randint(low=0, high=2 ** 32, dtype='uint64'))))

agent_types.extend(["ClientAgent" for i in range(a, b)])

client_init_end = time()
init_seconds = client_init_end - client_init_start
td_init = timedelta(seconds=init_seconds)
print(f"Client init took {td_init}")

### Configure a service agent.

agents.extend([AggregatorAgent(
    id=b,  # set id to be a number after all clients
    name="PPFL Service Agent",
    type="AggregatorAgent",
    random_state=np.random.RandomState(seed=np.random.randint(low=0, high=2 ** 32, dtype='uint64')),
    msg_fwd_delay=0,
    users=[*range(a, b)],
    iterations=num_iterations,
    round_time=pd.Timedelta(f"{round_time}s"),
    num_clients=num_clients,
    parallel_mode=parallel_mode,
    vector_len = vector_len,
    aggregator_size=aggregator_size,
    debug_mode=debug_mode,
)])

agent_types.extend(["AggregatorAgent"])

### Configure a latency model for the agents.

# Get a new-style cubic LatencyModel from the networking literature.
pairwise = (len(agent_types), len(agent_types))

model_args = {'connected': True,
              'min_latency': np.random.uniform(low=1000000, high=10000000, size=pairwise),
              'jitter': 0.3,
              'jitter_clip': 0.05,
              'jitter_unit': 5,
              }

latency_model = LatencyModel(latency_model='cubic',
                             random_state=latency_rstate,
                             kwargs=model_args)

# Start the kernel running.
results = kernel.runner(agents=agents,
                        startTime=kernelStartTime,
                        stopTime=kernelStopTime,
                        agentLatencyModel=latency_model,
                        defaultComputationDelay=defaultComputationDelay,
                        skip_log=skip_log,
                        log_dir=log_dir)


print()
print(f"######## Microbenchmarks ########")
print(f"Protocol Iterations: {num_iterations}, Clients: {num_clients}, ")

print()
print("Service Agent mean time per iteration")
print(f"    Legal clients confirmation:         {results['Legal clients confirmation']:.6f}s")
print(f"    Online clients confirmation:     {results['Online clients confirmation']:.6f}s")
print(f"    Aggregate share reconstruction: {results['Aggregate share reconstruction']:.6f}s")
print(f"    Model aggregation: {results['Model aggregation']:.6f}s")
print()
print("Client Agent mean time per iteration")
print(f"    Seed sharing:         {results['seed sharing']:.6f}s")
print(f"    Masked model generation:     {results['Masked model generation']:.6f}s")