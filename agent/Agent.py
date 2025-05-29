import os
import sys
import time

import numpy as np
import pandas as pd

from copy import deepcopy
from util.util import log_print
import pandas as pd

class Agent:
    # 添加类变量来存储统计数据
    _stats_df = pd.DataFrame(columns=['Stage', 'Sender', 'Message Type', 'Size (bytes)'])
    _cmd_suffix = '_'.join(sys.argv[1:]) if len(sys.argv) > 1 else 'default'
    _stats_filename = f'communication_stats_{_cmd_suffix}.xlsx'
    _summary_filename = f'communication_summary_{_cmd_suffix}.xlsx'

    def __init__(self, id, name, type, random_state, bandwidth_limit=None):
        self.total_message_bits = 0
        self.id = id
        self.name = name
        self.type = type
        self.random_state = random_state
        self.message_stats = {
            "Seed sharing": {"count": 0, "bits": 0},
            "Legal clients confirmation": {"count": 0, "bits": 0},
            "Masked model upload": {"count": 0, "bits": 0},
            "Model aggregation and mask removal": {"count": 0, "bits": 0},
            "Online clients confirmation": {"count": 0, "bits": 0}
        }

        if not random_state:
            raise ValueError("A valid, seeded np.random.RandomState object is required " +
                             "for every agent.Agent", self.name)
            sys.exit()

        self.kernel = None
        self.currentTime = None
        self.log = []
        self.logEvent("AGENT_TYPE", type)
        # 从环境变量中读取带宽限制
        if bandwidth_limit is None and "AGENT_BANDWIDTH_LIMIT" in os.environ:
            try:
                self.bandwidth_limit = float(os.environ["AGENT_BANDWIDTH_LIMIT"])
                # log_print("Agent {} 从环境变量读取带宽限制: {} Mbps", self.id, self.bandwidth_limit)
            except (ValueError, TypeError):
                self.bandwidth_limit = None
        else:
            self.bandwidth_limit = bandwidth_limit

    ### Flow of required kernel listening methods:
    ### init -> start -> (entire simulation) -> end -> terminate

    def kernelInitializing(self, kernel):
        # Called by kernel one time when simulation first begins.
        # No other agents are guaranteed to exist at this time.

        # Kernel reference must be retained, as this is the only time the
        # agent can "see" it.
        self.kernel = kernel

        log_print("{} exists!", self.name)

    def kernelStarting(self, startTime):
        # Called by kernel one time _after_ simulationInitializing.
        # All other agents are guaranteed to exist at this time.
        # startTime is the earliest time for which the agent can
        # schedule a wakeup call (or could receive a message).

        # Base Agent schedules a wakeup call for the first available timestamp.
        # Subclass agents may override this behavior as needed.

        log_print("Agent {} ({}) requesting kernel wakeup at time {}",
                  self.id, self.name, self.kernel.fmtTime(startTime))

        self.setWakeup(startTime)

    def kernelStopping(self):
        # Called by kernel one time _before_ simulationTerminating.
        # All other agents are guaranteed to exist at this time.

        pass

    def kernelTerminating(self):
        # Called by kernel one time when simulation terminates.
        # No other agents are guaranteed to exist at this time.

        # If this agent has been maintaining a log, convert it to a Dataframe
        # and request that the Kernel write it to disk before terminating.
        if self.log:
            dfLog = pd.DataFrame(self.log)
            dfLog.set_index('EventTime', inplace=True)
            self.writeLog(dfLog)
            
        # 保存统计数据到文件
        # self.save_stats_to_file()

    ### Methods for internal use by agents (e.g. bookkeeping).

    def logEvent(self, eventType, event='', appendSummaryLog=False):
        # Adds an event to this agent's log.  The deepcopy of the Event field,
        # often an object, ensures later state changes to the object will not
        # retroactively update the logged event.

        # We can make a single copy of the object (in case it is an arbitrary
        # class instance) for both potential log targets, because we don't
        # alter logs once recorded.
        e = deepcopy(event)
        self.log.append({'EventTime': self.currentTime, 'EventType': eventType,
                         'Event': e})

        if appendSummaryLog: self.kernel.appendSummaryLog(self.id, eventType, e)

    ### Methods required for communication from other agents.
    ### The kernel will _not_ call these methods on its own behalf,
    ### only to pass traffic from other agents..

    def receiveMessage(self, currentTime, msg):
        # Called each time a message destined for this agent reaches
        # the front of the kernel's priority queue.  currentTime is
        # the simulation time at which the kernel is delivering this
        # message -- the agent should treat this as "now".  msg is
        # an object guaranteed to inherit from the message.Message class.

        self.currentTime = currentTime

        log_print("At {}, agent {} ({}) received: {}",
                  self.kernel.fmtTime(currentTime), self.id, self.name, msg)

    def wakeup(self, currentTime):
        # Agents can request a wakeup call at a future simulation time using
        # Agent.setWakeup().  This is the method called when the wakeup time
        # arrives.

        self.currentTime = currentTime

        log_print("At {}, agent {} ({}) received wakeup.",
                  self.kernel.fmtTime(currentTime), self.id, self.name)

    ### Methods used to request services from the Kernel.  These should be used
    ### by all agents.  Kernel methods should _not_ be called directly!

    ### Presently the kernel expects agent IDs only, not agent references.
    ### It is possible this could change in the future.  Normal agents will
    ### not typically wish to request additional delay.
    def sendMessage(self, recipientID, msg, delay=0, tag="communication", msg_name=None):
        # 消息阶段分类
        # message_type = None
        # sender_type = "Server" if self.type == "AggregatorAgent" else "Client"
        
        # if msg.body['msg'] == "SHARED_MASK":
        #     message_type = "Seed sharing"
        # elif msg.body['msg'] == "VECTOR":
        #     message_type = "Masked model upload"
        # elif msg.body['msg'] == "request shares sum":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "hprf_SUM_SHARES":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "ONLINE_CLIENTS":
        #     message_type = "Online clients confirmation"
        # elif msg.body['msg'] == "FINAL_SUM":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "BFT_SIGN_ONLINE":
        #     message_type = "Online clients confirmation"
        # elif msg.body['msg'] == "BFT_SIGN_FINAL":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "BFT_SIGN_LEGAL":
        #     message_type = "Legal clients confirmation"
        # elif msg.body['msg'] == "BFT_RESPONSE_ONLINE":
        #     message_type = "Online clients confirmation"
        # elif msg.body['msg'] == "BFT_RESPONSE_FINAL":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "BFT_RESPONSE_LEGAL":
        #     message_type = "Legal clients confirmation"
        # elif msg.body['msg'] == "REQ":
        #     message_type = "Model aggregation and mask removal"
        # elif msg.body['msg'] == "SIGN":
        #     message_type = "Legal clients confirmation"
        # elif msg.body['msg'] == "MASK_COMMITMENTS":
        #     message_type = "Seed sharing"
        # elif msg.body['msg'] == "VIEW_CHANGE":
        #     message_type = "Legal clients confirmation"
        # else:
        #     message_type = "UNKNOWN"

        # # 计算消息大小
        # message_size = 0
        # if hasattr(msg, 'body'):
        #     for content in msg.body:
        #         if content == "masked_vector":
        #             continue
        #         message_size += sys.getsizeof(msg.body[content])

        # # 将统计信息添加到内存中的DataFrame
        # if message_type:
        #     new_row = pd.DataFrame({
        #         'Stage': [message_type],
        #         'Sender': [sender_type],
        #         'Message Type': [msg.body['msg']],
        #         'Size (bytes)': [message_size]
        #     })
        #     Agent._stats_df = pd.concat([Agent._stats_df, new_row], ignore_index=True)

        self.kernel.sendMessage(self.id, recipientID, msg, delay=delay, tag=tag)

    def print_message_stats(self):
        print("Message Statistics:")
        for message_type, stats in self.message_stats.items():
            print(f"- {message_type}: Count={stats['count']}, Total bits={stats['bits']}")

    def setWakeup(self, requestedTime):
        self.kernel.setWakeup(self.id, requestedTime)

    def getComputationDelay(self):
        return self.kernel.getAgentComputeDelay(sender=self.id)

    def setComputationDelay(self, requestedDelay):
        self.kernel.setAgentComputeDelay(sender=self.id, requestedDelay=requestedDelay)

    def delay(self, additionalDelay):
        self.kernel.delayAgent(sender=self.id, additionalDelay=additionalDelay)

    def writeLog(self, dfLog, filename=None):
        self.kernel.writeLog(self.id, dfLog, filename)

    def updateAgentState(self, state):
        """ Agents should use this method to replace their custom state in the dictionary
        the Kernel will return to the experimental config file at the end of the
        simulation.  This is intended to be write-only, and agents should not use
        it to store information for their own later use.
    """

        self.kernel.updateAgentState(self.id, state)

    ### Internal methods that should not be modified without a very good reason.

    def __lt__(self, other):
        # Required by Python3 for this object to be placed in a priority queue.

        return ("{}".format(self.id) <
                "{}".format(other.id))

   

