# -*- coding: utf-8 -*-
"""Classes and functions that create the bandwidth measurements document
(v3bw) used by bandwidth authorities."""
# flake8: noqa: E741
# (E741 ambiguous variable name), when using l.
import re
import copy
import logging
import math
import os
from itertools import combinations
from statistics import median, mean
from stem.descriptor import parse_file
import time
from sbws import __version__
from sbws.globals import (SPEC_VERSION, BW_LINE_SIZE, SBWS_SCALE_CONSTANT,
                          TORFLOW_SCALING, MLEFLOW_SCALING, SBWS_SCALING, PROBPROG_SCALING, TORFLOW_BW_MARGIN,
                          TORFLOW_OBS_LAST, TORFLOW_OBS_MEAN,
                          PROP276_ROUND_DIG, MIN_REPORT, MAX_BW_DIFF_PERC)
from sbws.lib import scaling
from sbws.lib.resultdump import ResultSuccess, _ResultType
from sbws.util.filelock import DirectoryLock
from sbws.util.timestamp import (now_isodt_str, unixts_to_isodt_str,
                                 now_unixts, isostr_to_dt_obj,
                                 dt_obj_to_isodt_str)
from sbws.util.state import State

import decimal

#numpyro:
# import numpyro
# import jax
# import numpyro.infer
# import numpyro.optim
# import numpyro.distributions as dist
# from numpyro.distributions import constraints
# import jax.numpy as jnp
import numpy as np
# from numpyro.optim import Adam
# from numpyro.infer import SVI, Trace_ELBO

# import threading
# numpyro.enable_validation(False)

log = logging.getLogger(__name__)

LINE_SEP = '\n'
KEYVALUE_SEP_V1 = '='
KEYVALUE_SEP_V2 = ' '
hus = None

# NOTE: in a future refactor make make all the KeyValues be a dictionary
# with their type, so that it's more similar to stem parser.

# Header KeyValues
# =================
# KeyValues that need to be in a specific order in the Bandwidth File.
HEADER_KEYS_V1_1_ORDERED = ['version']
# KeyValues that are not initialized from the state file nor the measurements.
# They can also be pass as an argument to `Header` to overwrite default values,
# what is done in unit tests.
# `latest bandwidth` is special cause it gets its value from timestamp, which
# is not a KeyValue, but it's always pass as an agument.
# It could be separaed in other list, but so far there is no need, cause:
# 1. when it's pass to the Header to initialize it, it's just ignored.
# 2. when the file is created, it's took into account.
HEADER_KEYS_V1_1_SELF_INITIALIZED = [
    "software",
    "software_version",
    "file_created",
    "latest_bandwidth",
]
# KeyValues that are initialized from arguments.
HEADER_KEYS_V1_1_TO_INIT = [
    "earliest_bandwidth",
    "generator_started",
]

# number_eligible_relays is the number that ends in the bandwidth file
# ie, have not been excluded by one of the filters in 4. below
# They should be call recent_measurement_included_count to be congruent
# with the other KeyValues.
HEADER_KEYS_V1_2 = [
    "number_eligible_relays",
    "minimum_number_eligible_relays",
    "number_consensus_relays",
    "percent_eligible_relays",
    "minimum_percent_eligible_relays",
]

# KeyValues added in the Bandwidth File v1.3.0
HEADER_KEYS_V1_3 = [
    "scanner_country",
    "destinations_countries",
]

# KeyValues that count the number of relays that are in the bandwidth file,
# but ignored by Tor when voting, because they do not have a
# measured bandwidth.
HEADER_RECENT_MEASUREMENTS_EXCLUDED_KEYS = [
    # Number of relays that were measured but all the measurements failed
    # because of network failures or it was
    # not found a suitable helper relay
    'recent_measurements_excluded_error_count',
    # Number of relays that have successful measurements but the measurements
    # were not away from each other in X time (by default 1 day).
    'recent_measurements_excluded_near_count',
    # Number of relays that have successful measurements and they are away from
    # each other but they are not X time recent.
    # By default this is 5 days, which is the same time the older
    # the measurements can be by default.
    'recent_measurements_excluded_old_count',
    # Number of relays that have successful measurements and they are away from
    # each other and recent
    # but the number of measurements are less than X (by default 2).
    'recent_measurements_excluded_few_count',
]
# Added in #29591
# NOTE: recent_consensus_count, recent_priority_list_count,
# recent_measurement_attempt_count and recent_priority_relay_count
# are not reset when the scanner is stop.
# They will accumulate the values since the scanner was ever started.
HEADER_KEYS_V1_4 = [
    # 1.1 header: the number of different consensuses, that sbws has seen,
    # since the last 5 days
    'recent_consensus_count',
    # 2.4 Number of times a priority list has been created
    'recent_priority_list_count',
    # 2.5 Number of relays that there were in a priority list
    # [50, number of relays in the network * 0.05]
    'recent_priority_relay_count',
    # 3.6 header: the number of times that sbws has tried to measure any relay,
    # since the last 5 days
    # This would be the number of times a relays were in a priority list
    'recent_measurement_attempt_count',
    # 3.7 header: the number of times that sbws has tried to measure any relay,
    # since the last 5 days, but it didn't work
    # This should be the number of attempts - number of ResultSuccess -
    # something else we don't know yet
    # So far is the number of ResultError
    'recent_measurement_failure_count',
    # The time it took to report about half of the network.
    'time_to_report_half_network',
] + HEADER_RECENT_MEASUREMENTS_EXCLUDED_KEYS

# Tor version will be obtained from the state file, so it won't be pass as an
# argument, but will be self-initialized.
HEADER_KEYS_V1_4_TO_INIT = ['tor_version']

# KeyValues that are initialized from arguments, not self-initialized.
HEADER_INIT_KEYS = (
    HEADER_KEYS_V1_1_TO_INIT
    + HEADER_KEYS_V1_3
    + HEADER_KEYS_V1_2
    + HEADER_KEYS_V1_4
    + HEADER_KEYS_V1_4_TO_INIT
)

HEADER_INT_KEYS = HEADER_KEYS_V1_2 + HEADER_KEYS_V1_4
# List of all unordered KeyValues currently being used to generate the file
HEADER_UNORDERED_KEYS = (
    HEADER_KEYS_V1_1_SELF_INITIALIZED
    + HEADER_KEYS_V1_1_TO_INIT
    + HEADER_KEYS_V1_3
    + HEADER_KEYS_V1_2
    + HEADER_KEYS_V1_4
    + HEADER_KEYS_V1_4_TO_INIT
)
# List of all the KeyValues currently being used to generate the file
HEADER_ALL_KEYS = HEADER_KEYS_V1_1_ORDERED + HEADER_UNORDERED_KEYS

TERMINATOR = '====='

# Bandwidth Lines KeyValues
# =========================
# Num header lines in v1.X.X using all the KeyValues
NUM_LINES_HEADER_V1 = len(HEADER_ALL_KEYS) + 2
LINE_TERMINATOR = TERMINATOR + LINE_SEP

# KeyValue separator in Bandwidth Lines
BWLINE_KEYVALUES_SEP_V1 = ' '
# not inclding in the files the extra bws for now
BWLINE_KEYS_V0 = ['node_id', 'bw']
BWLINE_KEYS_V1_1 = [
    "master_key_ed25519",
    "nick",
    "rtt",
    "time",
    "success",
    "error_stream",
    "error_circ",
    "error_misc",
    # Added in #292951
    "error_second_relay",
    "error_destination",
]
BWLINE_KEYS_V1_2 = [
    "bw_median",
    "bw_mean",
    "desc_bw_avg",
    "desc_bw_bur",
    "desc_bw_obs_last",
    "desc_bw_obs_mean",
    "consensus_bandwidth",
    "consensus_bandwidth_is_unmeasured",
]

# There were no bandwidth lines key added in the specification version 1.3

# Added in #292951
BWLINE_KEYS_V1_4 = [
    # 1.2 relay: the number of different consensuses, that sbws has seen,
    # since the last 5 days, that have this relay
    'relay_in_recent_consensus_count',
    # 2.6 relay: the number of times a relay was "prioritized" to be measured
    # in the recent days (by default 5).
    'relay_recent_priority_list_count',
    # 3.8 relay:  the number of times that sbws has tried to measure
    # this relay, since the last 5 days
    # This would be the number of times a relay was in a priority list (2.6)
    # since once it gets measured, it either returns ResultError,
    # ResultSuccess or something else happened that we don't know yet
    'relay_recent_measurement_attempt_count',
    # 3.9 relay:  the number of times that sbws has tried to measure
    # this relay, since the last 5 days, but it didn't work
    # This should be the number of attempts - number of ResultSuccess -
    # something else we don't know yet
    # So far is the number of ResultError
    'relay_recent_measurement_failure_count',
    # Number of error results created in the last 5 days that are excluded.
    # This is the sum of all the errors.
    'relay_recent_measurements_excluded_error_count',
    # The number of successful results, created in the last 5 days,
    # that were excluded by a rule, for this relay.
    # 'relay_recent_measurements_excluded_error_count' would be the
    # sum of the following 3 + the number of error results.

    # The number of successful measurements that are not X time away
    # from each other (by default 1 day).
    'relay_recent_measurements_excluded_near_count',
    # The number of successful measurements that are away from each other
    # but not X time recent (by default 5 days).
    'relay_recent_measurements_excluded_old_count',
    # The number of measurements excluded because they are not at least X
    # (by default 2).
    'relay_recent_measurements_excluded_few_count',
    # `vote=0` is used for the relays that were excluded to
    # be reported in the bandwidth file and now they are
    # reported.
    # It tells Tor to do not vote on the relay.
    # `unmeasured=1` is used for the same relays and it is
    # added in case Tor would vote on them in future versions.
    # Maybe these keys should not be included for the relays
    # in which vote=1 and unmeasured=0.
    'vote', 'unmeasured',
    # When there not enough eligible relays (not excluded)
    # under_min_report is 1, `vote` is 0.
    # Added in #29853.
    'under_min_report',
]
BWLINE_KEYS_V1 = BWLINE_KEYS_V0 + BWLINE_KEYS_V1_1 + BWLINE_KEYS_V1_2 \
               + BWLINE_KEYS_V1_4
# NOTE: tech-debt: assign boolean type to vote and unmeasured,
# when the attributes are defined with a type, as stem does.
BWLINE_INT_KEYS = (
    [
        "bw",
        "rtt",
        "success",
        "error_stream",
        "error_circ",
        "error_misc",
    ]
    + BWLINE_KEYS_V1_2
    + BWLINE_KEYS_V1_4
)
# This is boolean, not int.
BWLINE_INT_KEYS.remove('consensus_bandwidth_is_unmeasured')


##################### PROBABILISTIC PROGRAMMING ##########################################################################


def consensus_fetcher_prob_prog(conf, k):
    consensus={}
    bw_exitguard={}
    bw_exit={}
    bw_guard={}
    bw_middle={}
    # file =  conf.getpath('paths', 'consensus_file')
    file = conf.getpath('paths', 'v3bw_fname').format(k)
    otf=open(file, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        # log.debug(line)
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if m.group(6)=='exitguard':
                bw_exitguard['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)),'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
            if m.group(6)=='exit':
                bw_exit['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)),'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
            if m.group(6)=='guard':
                bw_guard['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)),'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
            if m.group(6)=='middle':
                bw_middle['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)),'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
            consensus['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)), 'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
    
    bw_exitguard = sorted(bw_exitguard.items(), key=lambda item: item[1]['number'])
    bw_exit = sorted(bw_exit.items(), key=lambda item: item[1]['number'])
    bw_guard = sorted(bw_guard.items(), key=lambda item: item[1]['number'])
    bw_middle = sorted(bw_middle.items(), key=lambda item: item[1]['number'])
    consensus = sorted(consensus.items(), key=lambda item: item[1]['number'])
    # log.debug('consensus: '+str(consensus))
    return consensus, bw_exitguard, bw_exit, bw_guard, bw_middle

def observation_fetcher_prob_prog(conf):
    consensus={}
    # bw_exitguard={}
    # bw_exit={}
    # bw_guard={}
    # bw_middle={}
    file =  conf.getpath('paths', 'observation_file')
    otf=open(file, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if 'relay'+m.group(5)+m.group(6) in consensus:
                consensus['relay'+m.group(5)+m.group(6)]['bw'].append(max(0.001,int(m.group(3))))
                # if m.group(4)=='exitguard':
                #     bw_exitguard['relay'+m.group(5)+m.group(6)][1]['bw'].append(m.group(3))
                # if m.group(4)=='exit':
                #     bw_exit['relay'+m.group(5)+m.group(6)][1]['bw'].append(m.group(3))
                # if m.group(4)=='guard':
                #     bw_guard['relay'+m.group(5)+m.group(6)][1]['bw'].append(m.group(3))
                # if m.group(4)=='middle':
                #     bw_middle['relay'+m.group(5)+m.group(6)][1]['bw'].append(m.group(3))
            else:
                # if m.group(4)=='exitguard':
                #     bw_exitguard['relay'+m.group(5)+m.group(6)]={'relay': 'relay'+m.group(5)+m.group(6), 'bw': [m.group(3)], 'fp': m.group(1)[9:]}
                # if m.group(4)=='exit':
                #     bw_exit['relay'+m.group(5)+m.group(6)]={'relay': 'relay'+m.group(5)+m.group(6), 'bw': [m.group(3)], 'fp': m.group(1)[9:]}
                # if m.group(4)=='guard':
                #     bw_guard['relay'+m.group(5)+m.group(6)]={'relay': 'relay'+m.group(5)+m.group(6), 'bw': [m.group(3)], 'fp': m.group(1)[9:]}
                # if m.group(4)=='middle':
                #     bw_middle['relay'+m.group(5)+m.group(6)]={'relay': 'relay'+m.group(5)+m.group(6), 'bw': [m.group(3)], 'fp': m.group(1)[9:]}
                consensus['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)),'relay': 'relay'+m.group(5)+m.group(6), 'bw': [max(0.001,int(m.group(3)))], 'fp': m.group(1)[9:]}
    # bw_exitguard = sorted(bw_exitguard.items(), key=lambda item: item[1]['relay'])
    # bw_exit = sorted(bw_exit.items(), key=lambda item: item[1]['relay'])
    # bw_guard = sorted(bw_guard.items(), key=lambda item: item[1]['relay'])
    # bw_middle = sorted(bw_middle.items(), key=lambda item: item[1]['relay'])
    consensus = sorted(consensus.items(), key=lambda item: item[1]['number'])
    # log.debug(consensus)
    # return consensus, bw_exitguard, bw_exit, bw_guard, bw_middle
    return consensus

def weights_fetcher_prob_prog(file):
    weight_used={}
    # file =  conf.getpath('paths', 'observation_file')
    otf=open(file, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if 'relay'+m.group(5)+m.group(6) in weight_used:
                weight_used['relay'+m.group(5)+m.group(6)]['weight'].append(float(m.group(3)+m.group(4).replace("\t", "")))
            else:
                weight_used['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)), 'relay': 'relay'+m.group(5)+m.group(6), 'weight': [float(m.group(3)+m.group(4).replace("\t", ""))], 'fp': m.group(1)[9:]}
    weight_used = sorted(weight_used.items(), key=lambda item: item[1]['number'])
    # log.debug(weight_used)
    return weight_used

def parameters_fetcher_prob_prog(file):
    parameters={}
    # file =  conf.getpath('paths', 'observation_file')
    otf=open(file, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)par=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if 'relay'+m.group(5)+m.group(6) in parameters:
                parameters['relay'+m.group(5)+m.group(6)]['par'].append(float(m.group(3)+m.group(4).replace("\t", "")))
            else:
                parameters['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)), 'relay': 'relay'+m.group(5)+m.group(6), 'par': [float(m.group(3)+m.group(4).replace("\t", ""))], 'fp': m.group(1)[9:]}
    parameters = sorted(parameters.items(), key=lambda item: item[1]['number'])
    # log.debug(parameters)
    return parameters

#################################### SBWS #####################################################################################

def consensus_fetcher(conf):
    consensus={}
    # otf=open("/home/hdarir2/simulation_12relays_random/12relays/shadow.data/hosts/bwauthority/v3bw", "rt")
    path = conf.getpath('paths', 'consensus_file')
    # path = path+'/v3bw'
    otf=open(path, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        if m := re.search(r'bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            consensus['relay'+m.group(3)+m.group(4)]=int(m.group(1))
    return consensus

def observed_bandwidth_fetcher(conf):
    consensus={}
    # otf=open("/home/hdarir2/simulation_12relays_random/12relays/shadow.data/hosts/bwauthority/v3bw", "rt")
    path = conf.getpath('paths', 'observed_bandwidth')
    # path = path+'/v3bw'
    otf=open(path, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        if m := re.search(r'bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            consensus['relay'+m.group(3)+m.group(4)]=int(m.group(1))
    return consensus



################################################## MLEFLOW #####################################################################################################
def true_capacity_fetcher_mleflow(conf):
    consensus={}
    path = conf.getpath('paths', 'observed_bandwidth')
    otf=open(path, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            consensus['relay'+m.group(5)+m.group(6)]={'relay': 'relay'+m.group(5)+m.group(6), 'bw': int(m.group(3)), 'fp': m.group(1)[9:]}
    return consensus


def array_fetcher(conf):
    consensus={}
    path = conf.getpath('paths', 'mleflowarray_file')
    otf=open(path, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)par=[(\S+)](.*)nick=relay(\d+)(\S+)', line):
            consensus['relay'+m.group(4)+m.group(5)]=np.array([float(s) for s in np.array(m.group(3)[:len(m.group(3))-2].split())])
    return consensus

def weights_fetcher_mleflow(file):
    weight_used={}
    # file =  conf.getpath('paths', 'observation_file')
    otf=open(file, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if 'relay'+m.group(5)+m.group(6) in weight_used:
                weight_used['relay'+m.group(5)+m.group(6)]=float(m.group(3)+m.group(4).replace("\t", ""))
            else:
                weight_used['relay'+m.group(5)+m.group(6)]=float(m.group(3)+m.group(4).replace("\t", ""))
    return weight_used

def observation_fetcher_mleflow(conf):
    consensus={}
    file =  conf.getpath('paths', 'observation_file')
    otf=open(file, "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if 'relay'+m.group(5)+m.group(6) in consensus:
                consensus['relay'+m.group(5)+m.group(6)]=max(0.001,int(m.group(3)))
            else:
                consensus['relay'+m.group(5)+m.group(6)]=max(0.001, int(m.group(3)))
                ## minimum of 1 byte per second
    return consensus

def logfac(x):
    logfact=np.zeros(x+1)
    logfact[0]=0
    for i in range(len(logfact)-1):
        logfact[i+1]=logfact[i]+math.log(i+1)
    return logfact

def quant(bw,z):
    minimum=0
    Cls=[]
    L=[]
    m=int(math.ceil(math.log(max(bw)-minimum)/math.log(z)))
    index=np.zeros(len(bw))
    bw2=np.zeros(len(bw))
    RCl = [set() for i in range(m)]
    for i in range(len(bw)):
        for j in range(m):
            if bw[i]<=(minimum+pow(z,j+1)):
                index[i]=j+1
                #always set the minimum bandwidth to 1
                if j==0:
                    bw2[i]=1
                else:
                    bw2[i]=(2*minimum+pow(z,j+1)+pow(z,j))/2
                RCl[j].add(i)
                break
    for j in range(m):
        if j==0:
            Cls.append(1)
        else:
            Cls.append((2*minimum+pow(z,j+1)+pow(z,j))/2)
        L.append(len(RCl[j]))
    return m,bw2, index, RCl, Cls, L

def logsumcal(c,B,Q):
    L=B-0.5*pow((Q*(1/c)-1)/0.5,2)
    xmax=len(B)-1
    L.sort()
    resI=L[xmax]
    L=L-resI
    L=np.exp(L)
    L=L[:xmax]
    res=sum(L)
    res=resI+math.log(1+res)
    return res
########################################################################################################################################################

def round_sig_dig(n, digits=PROP276_ROUND_DIG):
    """Round n to 'digits' significant digits in front of the decimal point.
       Results less than or equal to 1 are rounded to 1.
       Returns an integer.

       digits must be greater than 0.
       n must be less than or equal to 2**73, to avoid floating point errors.
       """
    digits = int(digits)
    assert digits >= 1
    if n <= 1:
        return 1
    digits_in_n = int(math.log10(n)) + 1
    round_digits = max(digits_in_n - digits, 0)
    rounded_n = round(n, -round_digits)
    return int(rounded_n)


def kb_round_x_sig_dig(bw_bs, digits=PROP276_ROUND_DIG):
    """Convert bw_bs from bytes to kilobytes, and round the result to
       'digits' significant digits.
       Results less than or equal to 1 are rounded up to 1.
       Returns an integer.

       digits must be greater than 0.
       n must be less than or equal to 2**82, to avoid floating point errors.
       """
    # avoid double-rounding by using floating-point
    bw_kb = bw_bs / 1000.0
    return round_sig_dig(bw_kb, digits=digits)


def num_results_of_type(results, type_str):
    return len([r for r in results if r.type == type_str])


# Better way to use enums?
def result_type_to_key(type_str):
    return type_str.replace('-', '_')


class V3BWHeader(object):
    """
    Create a bandwidth measurements (V3bw) header
    following bandwidth measurements document spec version 1.X.X.

    :param str timestamp: timestamp in Unix Epoch seconds of the most recent
        generator result.
    :param str version: the spec version
    :param str software: the name of the software that generates this
    :param str software_version: the version of the software
    :param dict kwargs: extra headers. Currently supported:

        - earliest_bandwidth: str, ISO 8601 timestamp in UTC time zone
          when the first bandwidth was obtained
        - generator_started: str, ISO 8601 timestamp in UTC time zone
          when the generator started
    """
    def __init__(self, timestamp, **kwargs):
        assert isinstance(timestamp, str)
        for v in kwargs.values():
            assert isinstance(v, str)
        self.timestamp = timestamp
        # KeyValues with default value when not given by kwargs
        self.version = kwargs.get('version', SPEC_VERSION)
        self.software = kwargs.get('software', 'sbws')
        self.software_version = kwargs.get('software_version', __version__)
        self.file_created = kwargs.get('file_created', now_isodt_str())
        # latest_bandwidth should not be in kwargs, since it MUST be the
        # same as timestamp
        self.latest_bandwidth = unixts_to_isodt_str(timestamp)
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in HEADER_INIT_KEYS]

    def __str__(self):
        if self.version.startswith('1.'):
            return self.strv1
        return self.strv2

    @classmethod
    def from_results(cls, results, scanner_country=None,
                     destinations_countries=None, state_fpath=''):
        kwargs = dict()
        latest_bandwidth = cls.latest_bandwidth_from_results(results)
        earliest_bandwidth = cls.earliest_bandwidth_from_results(results)
        # NOTE: Blocking, reads file
        generator_started = cls.generator_started_from_file(state_fpath)
        recent_consensus_count = cls.consensus_count_from_file(state_fpath)
        timestamp = str(latest_bandwidth)

        # XXX: tech-debt: obtain the other values from the state file using
        # this state variable.
        # Store the state as an attribute of the object?
        state = State(state_fpath)
        tor_version = state.get('tor_version', None)
        if tor_version:
            kwargs['tor_version'] = tor_version

        kwargs['latest_bandwidth'] = unixts_to_isodt_str(latest_bandwidth)
        kwargs['earliest_bandwidth'] = unixts_to_isodt_str(earliest_bandwidth)
        if generator_started is not None:
            kwargs['generator_started'] = generator_started
        # To be compatible with older bandwidth files, do not require it.
        if scanner_country is not None:
            kwargs['scanner_country'] = scanner_country
        if destinations_countries is not None:
            kwargs['destinations_countries'] = destinations_countries
        if recent_consensus_count is not None:
            kwargs['recent_consensus_count'] = recent_consensus_count

        recent_measurement_attempt_count = \
            cls.recent_measurement_attempt_count_from_file(state_fpath)
        if recent_measurement_attempt_count is not None:
            kwargs['recent_measurement_attempt_count'] = \
                str(recent_measurement_attempt_count)

        # If it is a failure that is not a ResultError, then
        # failures = attempts - all mesaurements
        # Works only in the case that old measurements files already had
        # measurements count
        # If this is None or 0, the failures can't be calculated
        if recent_measurement_attempt_count:
            all_measurements = 0
            for result_list in results.values():
                all_measurements += len(result_list)
            measurement_failures = (recent_measurement_attempt_count
                                    - all_measurements)
            kwargs['recent_measurement_failure_count'] = \
                str(measurement_failures)

        priority_lists = cls.recent_priority_list_count_from_file(state_fpath)
        if priority_lists is not None:
            kwargs['recent_priority_list_count'] = str(priority_lists)

        priority_relays = \
            cls.recent_priority_relay_count_from_file(state_fpath)
        if priority_relays is not None:
            kwargs['recent_priority_relay_count'] = str(priority_relays)

        h = cls(timestamp, **kwargs)
        return h

    @classmethod
    def from_lines_v1(cls, lines):
        """
        :param list lines: list of lines to parse
        :returns: tuple of V3BWHeader object and non-header lines
        """
        assert isinstance(lines, list)
        try:
            index_terminator = lines.index(TERMINATOR)
        except ValueError:
            # is not a bw file or is v100
            log.warn('Terminator is not in lines')
            return None
        ts = lines[0]
        kwargs = dict([l.split(KEYVALUE_SEP_V1)
                       for l in lines[:index_terminator]
                       if l.split(KEYVALUE_SEP_V1)[0] in HEADER_ALL_KEYS])
        h = cls(ts, **kwargs)
        # last line is new line
        return h, lines[index_terminator + 1:-1]

    @classmethod
    def from_text_v1(self, text):
        """
        :param str text: text to parse
        :returns: tuple of V3BWHeader object and non-header lines
        """
        assert isinstance(text, str)
        return self.from_lines_v1(text.split(LINE_SEP))

    @classmethod
    def from_lines_v100(cls, lines):
        """
        :param list lines: list of lines to parse
        :returns: tuple of V3BWHeader object and non-header lines
        """
        assert isinstance(lines, list)
        h = cls(lines[0])
        # last line is new line
        return h, lines[1:-1]

    @staticmethod
    def generator_started_from_file(state_fpath):
        '''
        ISO formatted timestamp for the time when the scanner process most
        recently started.
        '''
        state = State(state_fpath)
        if 'scanner_started' in state:
            # From v1.1.0-dev `state` is capable of converting strs to datetime
            return dt_obj_to_isodt_str(state['scanner_started'])
        else:
            return None

    @staticmethod
    def consensus_count_from_file(state_fpath):
        state = State(state_fpath)
        count = state.count("recent_consensus")
        if count:
            return str(count)
        return None

    # NOTE: in future refactor store state in the class
    @staticmethod
    def recent_measurement_attempt_count_from_file(state_fpath):
        """
        Returns the number of times any relay was queued to be measured
        in the recent (by default 5) days from the state file.
        """
        state = State(state_fpath)
        return state.count('recent_measurement_attempt')

    @staticmethod
    def recent_priority_list_count_from_file(state_fpath):
        """
        Returns the number of times
        :meth:`~sbws.lib.relayprioritizer.RelayPrioritizer.best_priority`
        was run
        in the recent (by default 5) days from the state file.
        """
        state = State(state_fpath)
        return state.count('recent_priority_list')

    @staticmethod
    def recent_priority_relay_count_from_file(state_fpath):
        """
        Returns the number of times any relay was "prioritized" to be measured
        in the recent (by default 5) days from the state file.
        """
        state = State(state_fpath)
        return state.count('recent_priority_relay')

    @staticmethod
    def latest_bandwidth_from_results(results):
        return round(max([r.time for fp in results for r in results[fp]]))

    @staticmethod
    def earliest_bandwidth_from_results(results):
        return round(min([r.time for fp in results for r in results[fp]]))

    @property
    def keyvalue_unordered_tuple_ls(self):
        """Return list of KeyValue tuples that do not have specific order."""
        # sort the list to generate determinist headers
        keyvalue_tuple_ls = sorted([(k, v) for k, v in self.__dict__.items()
                                    if k in HEADER_UNORDERED_KEYS])
        return keyvalue_tuple_ls

    @property
    def keyvalue_tuple_ls(self):
        """Return list of all KeyValue tuples"""
        return [('version', self.version)] + self.keyvalue_unordered_tuple_ls

    @property
    def keyvalue_v1str_ls(self):
        """Return KeyValue list of strings following spec v1.X.X."""
        keyvalues = [self.timestamp] + [KEYVALUE_SEP_V1.join([k, v])
                                        for k, v in self.keyvalue_tuple_ls]
        return keyvalues

    @property
    def strv1(self):
        """Return header string following spec v1.X.X."""
        header_str = LINE_SEP.join(self.keyvalue_v1str_ls) + LINE_SEP + \
            LINE_TERMINATOR
        return header_str

    @property
    def keyvalue_v2_ls(self):
        """Return KeyValue list of strings following spec v2.X.X."""
        keyvalue = [self.timestamp] + [KEYVALUE_SEP_V2.join([k, v])
                                       for k, v in self.keyvalue_tuple_ls]
        return keyvalue

    @property
    def strv2(self):
        """Return header string following spec v2.X.X."""
        header_str = LINE_SEP.join(self.keyvalue_v2_ls) + LINE_SEP + \
            LINE_TERMINATOR
        return header_str

    @property
    def num_lines(self):
        return len(self.__str__().split(LINE_SEP))

    def add_stats(self, **kwargs):
        # Using kwargs because attributes might chage.
        [setattr(self, k, str(v)) for k, v in kwargs.items()
         if k in HEADER_KEYS_V1_2]

    def add_time_report_half_network(self):
        """Add to the header the time it took to measure half of the network.

        It is not the time the scanner actually takes on measuring all the
        network, but the ``number_eligible_relays`` that are reported in the
        bandwidth file and directory authorities will vote on.

        This is calculated for half of the network, so that failed or not
        reported relays do not affect too much.

        For instance, if there are 6500 relays in the network, half of the
        network would be 3250. And if there were 4000 eligible relays
        measured in an interval of 3 days, the time to measure half of the
        network would be 3 days * 3250 / 4000.

        Since the elapsed time is calculated from the earliest and the
        latest measurement and a relay might have more than 2 measurements,
        this would give an estimate on how long it would take to measure
        the network including all the valid measurements.

        Log also an estimated on how long it would take with the current
        number of relays included in the bandwidth file.
        """
        # NOTE: in future refactor do not convert attributes to str until
        # writing to the file, so that they do not need to be converted back
        # to do some calculations.
        elapsed_time = (
            (isostr_to_dt_obj(self.latest_bandwidth)
             - isostr_to_dt_obj(self.earliest_bandwidth))
            .total_seconds())

        # This attributes were added later and some tests that
        # do not initialize them would fail.
        eligible_relays = int(getattr(self, 'number_eligible_relays', 0))
        consensus_relays = int(getattr(self, 'number_consensus_relays', 0))
        if not(eligible_relays and consensus_relays):
            return

        half_network = consensus_relays / 2
        # Calculate the time it would take to measure half of the network
        if eligible_relays >= half_network:
            time_half_network = round(
                elapsed_time * half_network / eligible_relays
            )
            self.time_to_report_half_network = str(time_half_network)

        # In any case log an estimated on the time to measure all the network.
        estimated_time = round(
            elapsed_time * consensus_relays / eligible_relays
        )
        log.info("Estimated time to measure the network: %s hours.",
                 round(estimated_time / 60 / 60))

    def add_relays_excluded_counters(self, exclusion_dict):
        """
        Add the monitoring KeyValues to the header about the number of
        relays not included because they were not ``eligible``.
        """
        log.debug("Adding relays excluded counters.")
        for k, v in exclusion_dict.items():
            setattr(self, k, str(v))


class V3BWLine(object):
    """
    Create a Bandwidth List line following the spec version 1.X.X.

    :param str node_id: the relay fingerprint
    :param int bw: the bandwidth value that directory authorities will include
        in their votes.
    :param dict kwargs: extra headers.

    .. note:: tech-debt: move node_id and bw to kwargs and just ensure that
       the required values are in ``**kwargs``
    """
    def __init__(self, node_id, bw, **kwargs):
        assert isinstance(node_id, str)
        assert node_id.startswith('$')
        self.node_id = node_id
        self.bw = bw
        # For now, we do not want to add ``bw_filt`` to the bandwidth file,
        # therefore it is set here but not added to ``BWLINE_KEYS_V1``.
        [setattr(self, k, v) for k, v in kwargs.items()
         if k in BWLINE_KEYS_V1 + ["bw_filt"]]

    def __str__(self):
        return self.bw_strv1

    @classmethod
    def from_results(cls, results, secs_recent=None, secs_away=None,
                     min_num=0, router_statuses_d=None):
        """Convert sbws results to relays' Bandwidth Lines

        ``bs`` stands for Bytes/seconds
        ``bw_mean`` means the bw is obtained from the mean of the all the
        downloads' bandwidth.
        Downloads' bandwidth are calculated as the amount of data received
        divided by the the time it took to received.
        bw = data (Bytes) / time (seconds)
        """
        # log.debug("Len success_results %s", len(success_results))
        node_id = '$' + results[0].fingerprint
        kwargs = dict()
        kwargs['nick'] = results[0].nickname
        if getattr(results[0], 'master_key_ed25519'):
            kwargs['master_key_ed25519'] = results[0].master_key_ed25519
        kwargs['time'] = cls.last_time_from_results(results)
        kwargs.update(cls.result_types_from_results(results))

        # If it has not the attribute, return list to be able to call len
        # If it has the attribute, but it is None, return also list
        kwargs['relay_in_recent_consensus_count'] = str(
            max([
                len(getattr(r, 'relay_in_recent_consensus', []) or [])
                for r in results
            ])
        )

        # Workaround for #34309.
        # Because of a bug, probably in relaylist, resultdump, relayprioritizer
        # or scanner, only the last timestamp is being stored in each result.
        # Temporally count the number of timestamps for all results.
        # If there is an unexpected failure and the result is not stored, this
        # number would be lower than what would be the correct one.
        # This should happen rarely or never.
        ts = set([])
        for r in results:
            if getattr(r, "relay_recent_priority_list", None):
                ts.update(r.relay_recent_priority_list)
        kwargs["relay_recent_priority_list_count"] = str(len(ts))

        # Same comment as the previous paragraph.
        ts = set()
        for r in results:
            if getattr(r, "relay_recent_measurement_attempt", None):
                ts.update(r.relay_recent_measurement_attempt)
        kwargs["relay_recent_measurement_attempt_count"] = str(len(ts))

        success_results = [r for r in results if isinstance(r, ResultSuccess)]

        # NOTE: The following 4 conditions exclude relays from the bandwidth
        # file when the measurements does not satisfy some rules, what makes
        # the relay non-`eligible`.
        # In BWLINE_KEYS_V1_4 it is explained what they mean.
        # In HEADER_RECENT_MEASUREMENTS_EXCLUDED_KEYS it is also
        # explained the what it means the strings returned.
        # They rules were introduced in #28061 and #27338
        # In #28565 we introduce the KeyValues to know why they're excluded.
        # In #28563 we report these relays, but make Tor ignore them.
        # This might confirm #28042.

        # If the relay is non-`eligible`:
        # Create a bandwidth line with the relay, but set ``vote=0`` so that
        # Tor versions with patch #29806 does not vote on the relay.
        # Set ``bw=1`` so that Tor versions without the patch,
        # will give the relay low bandwidth.
        # Include ``unmeasured=1`` in case Tor would vote on unmeasured relays
        # in future versions.
        # And return because there are not bandwidth values.
        # NOTE: the bandwidth values could still be obtained if:
        # 1. ``ResultError`` will store them
        # 2. assign ``results_recent = results`` when there is a ``exclusion
        # reason.
        # This could be done in a better way as part of a refactor #28684.

        kwargs['vote'] = 0
        kwargs['unmeasured'] = 1

        exclusion_reason = None

        number_excluded_error = len(results) - len(success_results)
        if number_excluded_error > 0:
            # then the number of error results is the number of results
            kwargs['relay_recent_measurements_excluded_error_count'] = \
                number_excluded_error
        if not success_results:
            exclusion_reason = 'recent_measurements_excluded_error_count'
            return (cls(node_id, 1, **kwargs), exclusion_reason)

        results_away = \
            cls.results_away_each_other(success_results, secs_away)
        number_excluded_near = len(success_results) - len(results_away)
        if number_excluded_near > 0:
            kwargs['relay_recent_measurements_excluded_near_count'] = \
                number_excluded_near
        if not results_away:
            exclusion_reason = \
                'recent_measurements_excluded_near_count'
            return (cls(node_id, 1, **kwargs), exclusion_reason)
        # log.debug("Results away from each other: %s",
        #           [unixts_to_isodt_str(r.time) for r in results_away])

        results_recent = cls.results_recent_than(results_away, secs_recent)
        number_excluded_old = len(results_away) - len(results_recent)
        if number_excluded_old > 0:
            kwargs['relay_recent_measurements_excluded_old_count'] = \
                number_excluded_old
        if not results_recent:
            exclusion_reason = \
                'recent_measurements_excluded_old_count'
            return (cls(node_id, 1, **kwargs), exclusion_reason)

        if not len(results_recent) >= min_num:
            kwargs['relay_recent_measurements_excluded_few_count'] = \
                len(results_recent)
            # log.debug('The number of results is less than %s', min_num)
            exclusion_reason = \
                'recent_measurements_excluded_few_count'
            return (cls(node_id, 1, **kwargs), exclusion_reason)

        # Use the last consensus if available, since the results' consensus
        # values come from the moment the measurement was made.
        if router_statuses_d and node_id in router_statuses_d:
            consensus_bandwidth = \
                router_statuses_d[node_id].bandwidth * 1000
            consensus_bandwidth_is_unmeasured = \
                router_statuses_d[node_id].is_unmeasured
        else:
            consensus_bandwidth = \
                cls.consensus_bandwidth_from_results(results_recent)
            consensus_bandwidth_is_unmeasured = \
                cls.consensus_bandwidth_is_unmeasured_from_results(
                    results_recent)
        # If there is no last observed bandwidth, there won't be mean either.
        desc_bw_obs_last = \
            cls.desc_bw_obs_last_from_results(results_recent)

        # Exclude also relays without consensus bandwidth nor observed
        # bandwidth, since they can't be scaled
        if (desc_bw_obs_last is None and consensus_bandwidth is None):
            # This reason is not counted, not added in the file, but it will
            # have vote = 0
            return(cls(node_id, 1), "no_consensus_no_observed_bw")

        # For any line not excluded, do not include vote and unmeasured
        # KeyValues
        del kwargs['vote']
        del kwargs['unmeasured']

        # rtt = cls.rtt_from_results(results_recent)
        # if rtt:
        #     kwargs['rtt'] = rtt
        bw = cls.bw_median_from_results(results_recent)
        # XXX: all the class functions could use the bw_measurements instead of
        # obtaining them each time or use a class Measurements.
        bw_measurements = scaling.bw_measurements_from_results(results_recent)
        kwargs['bw_mean'] = cls.bw_mean_from_results(results_recent)
        kwargs['bw_filt'] = scaling.bw_filt(bw_measurements)
        kwargs['bw_median'] = cls.bw_median_from_results(
            results_recent)
        kwargs['desc_bw_avg'] = \
            cls.desc_bw_avg_from_results(results_recent)
        kwargs['desc_bw_bur'] = \
            cls.desc_bw_bur_from_results(results_recent)
        kwargs['consensus_bandwidth'] = consensus_bandwidth
        kwargs['consensus_bandwidth_is_unmeasured'] = \
            consensus_bandwidth_is_unmeasured
        kwargs['desc_bw_obs_last'] = desc_bw_obs_last
        kwargs['desc_bw_obs_mean'] = \
            cls.desc_bw_obs_mean_from_results(results_recent)

        bwl = cls(node_id, bw, **kwargs)
        return bwl, None

    @classmethod
    def from_data(cls, data, fingerprint):
        assert fingerprint in data
        return cls.from_results(data[fingerprint])

    @classmethod
    def from_bw_line_v1(cls, line):
        assert isinstance(line, str)
        kwargs = dict([kv.split(KEYVALUE_SEP_V1)
                       for kv in line.split(BWLINE_KEYVALUES_SEP_V1)
                       if kv.split(KEYVALUE_SEP_V1)[0] in BWLINE_KEYS_V1])
        for k, v in kwargs.items():
            if k in BWLINE_INT_KEYS:
                kwargs[k] = int(v)
        node_id = kwargs['node_id']
        bw = kwargs['bw']
        del kwargs['node_id']
        del kwargs['bw']
        bw_line = cls(node_id, bw, **kwargs)
        return bw_line

    @staticmethod
    def results_away_each_other(results, secs_away=None):
        # log.debug("Checking whether results are away from each other in %s "
        #           "secs.", secs_away)
        if secs_away is None or len(results) < 2:
            return results
        for a, b in combinations(results, 2):
            if abs(a.time - b.time) > secs_away:
                return results
        # log.debug("Results are NOT away from each other in at least %ss: %s",
        #           secs_away, [unixts_to_isodt_str(r.time) for r in results])
        return []

    @staticmethod
    def results_recent_than(results, secs_recent=None):
        if secs_recent is None:
            return results
        results_recent = list(filter(
                            lambda x: (now_unixts() - x.time) < secs_recent,
                            results))
        # if not results_recent:
        #     log.debug("Results are NOT more recent than %ss: %s",
        #               secs_recent,
        #               [unixts_to_isodt_str(r.time) for r in results])
        return results_recent

    @staticmethod
    def bw_median_from_results(results):
        bws = [dl['amount'] / dl['duration']
               for r in results for dl in r.downloads]
        if bws:
            return max(round(median(bws)), 1)
        return 1

    @staticmethod
    def bw_mean_from_results(results):
        bws = [dl['amount'] / dl['duration']
               for r in results for dl in r.downloads]
        # It's safe to return 0 here, because:
        # 1. this value will be the numerator when calculating the ratio.
        # 2. `kb_round_x_sig_dig` returns a minimum of 1.
        if bws:
            return round(mean(bws))
        return 0

    @staticmethod
    def last_time_from_results(results):
        return unixts_to_isodt_str(round(max([r.time for r in results])))

    @staticmethod
    def rtt_from_results(results):
        # convert from miliseconds to seconds
        rtts = [(round(rtt * 1000)) for r in results for rtt in r.rtts]
        rtt = round(median(rtts)) if rtts else None
        return rtt

    @staticmethod
    def result_types_from_results(results):
        rt_dict = dict([(result_type_to_key(rt.value),
                         num_results_of_type(results, rt.value))
                        for rt in _ResultType])
        return rt_dict

    @staticmethod
    def desc_bw_avg_from_results(results):
        """Obtain the last descriptor bandwidth average from the results."""
        for r in reversed(results):
            if r.relay_average_bandwidth is not None:
                return r.relay_average_bandwidth
        log.warning("Descriptor average bandwidth is None.")
        return None

    @staticmethod
    def desc_bw_bur_from_results(results):
        """Obtain the last descriptor bandwidth burst from the results."""
        for r in reversed(results):
            if r.relay_burst_bandwidth is not None:
                return r.relay_burst_bandwidth
        log.warning("Descriptor burst bandwidth is None.")
        return None

    @staticmethod
    def consensus_bandwidth_from_results(results):
        """Obtain the last consensus bandwidth from the results."""
        for r in reversed(results):
            if r.consensus_bandwidth is not None:
                return r.consensus_bandwidth
        log.warning("Consensus bandwidth is None.")
        return None

    @staticmethod
    def consensus_bandwidth_is_unmeasured_from_results(results):
        """Obtain the last consensus unmeasured flag from the results."""
        for r in reversed(results):
            if r.consensus_bandwidth_is_unmeasured is not None:
                return r.consensus_bandwidth_is_unmeasured
            log.warning("Consensus bandwidth is unmeasured is None.")
        return None

    @staticmethod
    def desc_bw_obs_mean_from_results(results):
        desc_bw_obs_ls = []
        for r in results:
            if r.relay_observed_bandwidth is not None:
                desc_bw_obs_ls.append(r.relay_observed_bandwidth)
        if desc_bw_obs_ls:
            return round(mean(desc_bw_obs_ls))
        log.warning("Descriptor observed bandwidth is None.")
        return None

    @staticmethod
    def desc_bw_obs_last_from_results(results):
        # the last is at the end of the list
        for r in reversed(results):
            if r.relay_observed_bandwidth is not None:
                return r.relay_observed_bandwidth
        log.warning("Descriptor observed bandwidth is None.")
        return None

    @property
    def bw_keyvalue_tuple_ls(self):
        """Return list of KeyValue Bandwidth Line tuples."""
        # sort the list to generate determinist headers
        keyvalue_tuple_ls = sorted([(k, v) for k, v in self.__dict__.items()
                                    if k in BWLINE_KEYS_V1])
        return keyvalue_tuple_ls

    @property
    def bw_keyvalue_v1str_ls(self):
        """Return list of KeyValue Bandwidth Line strings following
        spec v1.X.X.
        """
        bw_keyvalue_str = [KEYVALUE_SEP_V1 .join([k, str(v)])
                           for k, v in self.bw_keyvalue_tuple_ls]
        return bw_keyvalue_str

    @property
    def bw_strv1(self):
        """Return Bandwidth Line string following spec v1.X.X."""
        bw_line_str = BWLINE_KEYVALUES_SEP_V1.join(
                        self.bw_keyvalue_v1str_ls) + LINE_SEP
        if len(bw_line_str) > BW_LINE_SIZE:
            # if this is the case, probably there are too many KeyValues,
            # or the limit needs to be changed in Tor
            log.warn("The bandwidth line %s is longer than %s",
                     len(bw_line_str), BW_LINE_SIZE)
        return bw_line_str

    def set_relay_type(self, relay_type):
        self.relay_type = relay_type

    def del_relay_type(self):
        delattr(self, "relay_type")

class V3BWFile(object):
    """
    Create a Bandwidth List file following spec version 1.X.X

    :param V3BWHeader v3bwheader: header
    :param list v3bwlines: V3BWLines
    """
    def __init__(self, v3bwheader, v3bwlines):
        self.header = v3bwheader
        self.bw_lines = v3bwlines

    def __str__(self):
        return str(self.header) + ''.join([str(bw_line) or ''
                                           for bw_line in self.bw_lines])

    @classmethod
    def from_results(cls, conf, k, results, scanner_country=None,
                     destinations_countries=None, state_fpath='',
                     scale_constant=SBWS_SCALE_CONSTANT,
                     scaling_method=TORFLOW_SCALING,
                     torflow_obs=TORFLOW_OBS_LAST,
                     torflow_cap=TORFLOW_BW_MARGIN,
                     round_digs=PROP276_ROUND_DIG,
                     secs_recent=None, secs_away=None, min_num=0,
                     consensus_path=None, max_bw_diff_perc=MAX_BW_DIFF_PERC,
                     reverse=False):
        """Create V3BWFile class from sbws Results.

        :param dict results: see below
        :param str state_fpath: path to the state file
        :param int scaling_method:
            Scaling method to obtain the bandwidth
            Possible values: {None, SBWS_SCALING, TORFLOW_SCALING} = {0, 1, 2}
        :param int scale_constant: sbws scaling constant
        :param int torflow_obs: method to choose descriptor observed bandwidth
        :param bool reverse: whether to sort the bw lines descending or not

        Results are in the form::

            {'relay_fp1': [Result1, Result2, ...],
             'relay_fp2': [Result1, Result2, ...]}

        """
        log.info('Processing results to generate a bandwidth list file.')
        header = V3BWHeader.from_results(results, scanner_country,
                                         destinations_countries, state_fpath)
        bw_lines_raw = []
        bw_lines_excluded = []
        router_statuses_d = cls.read_router_statuses(consensus_path)
        # XXX: Use router_statuses_d to not parse again the file.
        number_consensus_relays = \
            cls.read_number_consensus_relays(consensus_path)
        state = State(state_fpath)

        # Create a dictionary with the number of relays excluded by any of the
        # of the filtering rules that makes relays non-`eligible`.
        # NOTE: In HEADER_RECENT_MEASUREMENTS_EXCLUDED_KEYS it is
        # explained what are the KeyValues.
        # See also the comments in `from_results`.
        exclusion_dict = dict(
            [(b, 0) for b in HEADER_RECENT_MEASUREMENTS_EXCLUDED_KEYS]
            )
        for fp, values in results.items():
            # log.debug("Relay fp %s", fp)
            line, reason = V3BWLine.from_results(values, secs_recent,
                                                 secs_away, min_num,
                                                 router_statuses_d)
            # If there is no reason it means the line will not be excluded.
            if not reason:
                bw_lines_raw.append(line)
            else:
                # Store the excluded lines to include them in the bandwidth
                # file.
                bw_lines_excluded.append(line)
                exclusion_dict[reason] = exclusion_dict.get(reason, 0) + 1
        # Add the headers with the number of excluded relays by reason
        header.add_relays_excluded_counters(exclusion_dict)

        if not bw_lines_raw:
            # It could be possible to scale the lines that were successful
            # even if excluded, but is not done here.
            log.info("After applying restrictions to the raw results, "
                     "there is not any. Scaling can not be applied.")
            # Update the header and log the progress.
            cls.update_progress(
                cls, 0, header, number_consensus_relays, state)
            # Set the lines that would be excluded anyway (`vote=0`) with
            # `under_min_report=1`
            cls.set_under_min_report(bw_lines_excluded)
            # Create the bandwidth file with the lines that would be excluded.
            return cls(header, bw_lines_excluded)
        if scaling_method == SBWS_SCALING:
            bw_lines = cls.bw_sbws_scale(conf, bw_lines_raw, scale_constant)
            cls.warn_if_not_accurate_enough(bw_lines, scale_constant)
            # log.debug(bw_lines[-1])
        elif scaling_method == TORFLOW_SCALING:
            bw_lines = cls.bw_torflow_scale(
                conf, bw_lines_raw, torflow_obs, torflow_cap, round_digs,
                router_statuses_d=router_statuses_d
            )
            # log.debug(bw_lines[-1])
            # Update the header and log the progress.
            min_perc = cls.update_progress(
                cls, len(bw_lines), header, number_consensus_relays, state
                )
            # If after scaling the number of lines is less than the percentage
            # of lines to report, set them with `under_min_report`.
            if not min_perc:
                cls.set_under_min_report(bw_lines)
        elif scaling_method == PROBPROG_SCALING:
            bw_lines = cls.bw_probprog_scale(conf, k, bw_lines_raw)
        elif scaling_method == MLEFLOW_SCALING:
            bw_lines = cls.bw_mleflow_scale(conf, k, bw_lines_raw)
        else:
            bw_lines = cls.bw_kb(bw_lines_raw)
            # log.debug(bw_lines[-1])
        # Not using the result for now, just warning
        cls.is_max_bw_diff_perc_reached(
            bw_lines, max_bw_diff_perc, router_statuses_d
        )
        header.add_time_report_half_network()
        f = cls(header, bw_lines + bw_lines_excluded)
        return f

    @classmethod
    def from_v1_fpath(cls, fpath):
        log.info('Parsing bandwidth file %s', fpath)
        with open(fpath) as fd:
            text = fd.read()
        all_lines = text.split(LINE_SEP)
        header, lines = V3BWHeader.from_lines_v1(all_lines)
        bw_lines = [V3BWLine.from_bw_line_v1(line) for line in lines]
        return cls(header, bw_lines)

    @classmethod
    def from_v100_fpath(cls, fpath):
        log.info('Parsing bandwidth file %s', fpath)
        with open(fpath) as fd:
            text = fd.read()
        all_lines = text.split(LINE_SEP)
        header, lines = V3BWHeader.from_lines_v100(all_lines)
        bw_lines = sorted([V3BWLine.from_bw_line_v1(l) for l in lines],
                          key=lambda l: l.bw)
        return cls(header, bw_lines)

    @staticmethod
    def set_under_min_report(bw_lines):
        """
        Mondify the Bandwidth Lines adding the KeyValue `under_min_report`,
        `vote`.
        """
        log.debug("Setting `under_min_report` to %s lines.", len(bw_lines))
        for l in bw_lines:
            l.under_min_report = 1
            l.vote = 0

    @staticmethod
    def bw_kb(bw_lines, reverse=False):
        bw_lines_scaled = copy.deepcopy(bw_lines)
        for l in bw_lines_scaled:
            l.bw = max(round(l.bw / 1000), 1)
        return sorted(bw_lines_scaled, key=lambda x: x.bw, reverse=reverse)

    @staticmethod
    def bw_sbws_scale(conf, bw_lines, scale_constant=SBWS_SCALE_CONSTANT,
                      reverse=False):
        """Return a new V3BwLine list scaled using sbws method.

        :param list bw_lines:
            bw lines to scale, not self.bw_lines,
            since this method will be before self.bw_lines have been
            initialized.
        :param int scale_constant:
            the constant to multiply by the ratio and
            the bandwidth to obtain the new bandwidth
        :returns list: V3BwLine list
        """
        log.debug('Scaling bandwidth using sbws method.')
        mt = [l.bw for l in bw_lines]
        m = sum(mt)/len(mt)
        # log.debug(m)
        # m = median([l.bw for l in bw_lines])
        bw_lines_scaled = copy.deepcopy(bw_lines)
        consensus = consensus_fetcher(conf)
        observed_bw = observed_bandwidth_fetcher(conf)
        for l in bw_lines_scaled:
            # min is to limit the bw to descriptor average-bandwidth
            # max to avoid bandwidth with 0 value
            # l.bw = max(round(min(l.desc_bw_avg,
            #                      l.bw * scale_constant / m)
            #                  / 1000), 1)
            # log.debug(l)
            # in bytes /s
            ct = consensus[l.nick]*1000
            bt = observed_bw[l.nick]*1000
            # log.debug(ct)
            # log.debug(bt)
            l.bw = max(round(l.bw * min(ct, bt) / m
                             / 1000), 1)
            
        return sorted(bw_lines_scaled, key=lambda x: x.nick, reverse=reverse)
    
    @staticmethod
    def bw_mleflow_scale(conf, k, bw_lines, max_noise = 1.3, min_noise = 0.7,
                      reverse=False):
        log.debug('Scaling bandwidth using mleflow method.')
        
        # log.debug(m)
        # m = median([l.bw for l in bw_lines])
        bw_lines_scaled = copy.deepcopy(bw_lines)
        true_capacities = true_capacity_fetcher_mleflow(conf)

        bw=np.array([])
        for d in true_capacities:
            bw = np.append(bw, [true_capacities[d]['bw']])
        # log.debug('bw: '+str(bw))


        [m,bw2, index, RCl, Cls,L]= quant(bw,1.1)
        log.debug(Cls)
        lamb = int(conf.getpath('paths', 'lambda'))
        LF=logfac(lamb)
        if k>0:
            Logm = array_fetcher(conf)
        else:
            Logm = {}
            for d in true_capacities:
                Logm[str(d)]=np.array([0 for i in range(len(Cls))], dtype =float)
        log.debug('Array at epoch '+str(k)+' is '+str(Logm))

        file = conf.getpath('paths', 'weight_first')
        weight_used_first = weights_fetcher_mleflow(file)

        file = conf.getpath('paths', 'weight_second')
        weight_used_second = weights_fetcher_mleflow(file)
        
        file = conf.getpath('paths', 'weight_third')
        weight_used_third = weights_fetcher_mleflow(file)
        
        weights ={}
        for d in true_capacities:
            weights[str(d)] = (weight_used_first[str(d)]+weight_used_second[str(d)]+weight_used_third[str(d)])/3
        log.debug('weights average are: '+str(weights))
        
        observations = observation_fetcher_mleflow(conf)
        log.debug('observations are: '+str(observations))

        for l in bw_lines_scaled:
            # if l.bw == 0:
            #     obs = 1
            # else:
            #     obs = l.bw/1000
            xmax = np.zeros(len(Cls))
            xmin = np.zeros(len(Cls))
            for j in range(len(Cls)):
                xmax[j] = int(round(max_noise*Cls[j]/observations[l.nick]-1))
                xmin[j] = int(round(min_noise*Cls[j]/observations[l.nick]-1))
                if xmax[j]>lamb:
                    xmax[j]=lamb
                if xmin[j]<0: 
                    xmin[j]=0
                if xmin[j]>lamb:
                    xmax[j]=-1
            M=int(max(xmax))
            a=int(math.floor(M))
            B=np.array([-lamb*weights[l.nick]+x*math.log(lamb*weights[l.nick])-LF[x] for x in range(a+1)])
            Q=np.array([observations[l.nick]*(x+1) for x in range(a+1)])
            for j in range(len(Cls)):
                if xmax[j]>=0:
                    v=int(math.floor(xmax[j]))+1
                    u=int(math.ceil(xmin[j]))
                    L=logsumcal(Cls[j],B[u:v],Q[u:v])
                    Logm[l.nick][j]=Logm[l.nick][j]+L
                else:
                    Logm[l.nick][j]=-math.inf
            l.bw = Cls[np.argmax(Logm[l.nick])]
        
        output = conf.getpath('paths', 'mleflowarray_file')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'w') as fd:
                for  d in true_capacities:
                    fd.write('node_id='+str(true_capacities[d]['fp'])+'\t'+'par='+str(Logm[d]).replace('\n'," ")+'\t'+'nick='+str(true_capacities[d]['relay'])+'\n')
                    
        return sorted(bw_lines_scaled, key=lambda x: x.nick, reverse=reverse)

    @staticmethod
    def bw_probprog_scale(conf, k, bw_lines,
                      reverse=False):
        
        log.debug('Scaling bandwidth using probabilistic programming method.')
        bw_lines_scaled = copy.deepcopy(bw_lines)
        
        estimates, estimates_exitguard, estimates_exit, estimates_guard, estimates_middle = consensus_fetcher_prob_prog(conf, k)
        log.debug('estimates: '+str(estimates))

        observations = observation_fetcher_prob_prog(conf)
        log.debug('observations: '+str(observations))
        
        file = conf.getpath('paths', 'weight_first')
        weight_used_first = weights_fetcher_prob_prog(file)
        log.debug('weight_used_first: '+str(weight_used_first))

        file = conf.getpath('paths', 'weight_second')
        weight_used_second = weights_fetcher_prob_prog(file)
        log.debug('weight_used_second: '+str(weight_used_second))

        file = conf.getpath('paths', 'weight_third')
        weight_used_third = weights_fetcher_prob_prog(file)
        log.debug('weight_used_third: '+str(weight_used_third))

        est=np.array([])
        for d in estimates:
            log.debug('part of estimate: '+str(d[1]['bw']))
            est = np.append(est, [d[1]['bw']])
            # est.append(d[1]['bw'])
        log.debug('est: '+str(est))

        est_exitguard=np.array([])
        for d in estimates_exitguard:
            est_exitguard = np.append(est_exitguard, [d[1]['bw']])
            # est_exitguard.append(d[1]['bw'])
        log.debug('est_exitguard: '+str(est_exitguard))

        est_exit=np.array([])
        for d in estimates_exit:
            est_exit = np.append(est_exit, [d[1]['bw']])
            # est_exit.append(d[1]['bw'])
        log.debug('est_exit: '+str(est_exit))
        
        est_guard=np.array([])
        for d in estimates_guard:
            est_guard = np.append(est_guard, [d[1]['bw']])
            # est_guard.append(d[1]['bw'])
        log.debug('est_guard: '+str(est_guard))
        
        est_middle=np.array([])
        for d in estimates_middle:
            est_middle = np.append(est_middle, [d[1]['bw']])
            # est_middle.append(d[1]['bw'])
        log.debug('est_middle: '+str(est_middle))

        obs=[np.array([]) for i in range(len(est))]
        log.debug('obs: '+str(obs))
        for i in range(len(observations)):
        # for d in observations:
            obs[i] = np.append(obs[i], [observations[i][1]['bw']])
            # obs.append(d[1]['bw'])
        log.debug('obs: '+str(obs))


        w_1 =[np.array([]) for i in range(len(est))]
        for i in range(len(weight_used_first)):
        # for d in weight_used_first:
            w_1[i] = np.append(w_1[i], [weight_used_first[i][1]['weight']])
            # w_1.append(d[1]['weight'])
        log.debug('w_1: '+str(w_1))

        w_2 =[np.array([]) for i in range(len(est))]
        for i in range(len(weight_used_second)):
        # for d in weight_used_second:
            w_2[i] = np.append(w_2[i], [weight_used_second[i][1]['weight']])
            # w_2.append(d[1]['weight'])
        log.debug('w_2: '+str(w_2))

        w_3 =[np.array([]) for i in range(len(est))]
        for i in range(len(weight_used_third)):
        # for d in weight_used_third:
            w_3[i]= np.append(w_3[i], [weight_used_third[i][1]['weight']])
            # w_3.append(d[1]['weight'])
        log.debug('w_3: '+str(w_3))

        obs_this_round = np.array([])
        for d in obs:
            obs_this_round = np.append(obs_this_round, [d[d.size-1]])
            # obs_this_round.append(d[len(d)-1])
        log.debug('obs_this_round: '+str(obs_this_round))
        
        if k ==0:
            par1gc = [np.array([]) for i in range(len(est))]
            par1mc = [np.array([]) for i in range(len(est))]
            par1ec = [np.array([]) for i in range(len(est))]
            par2gc = [np.array([]) for i in range(len(est))]
            par2mc = [np.array([]) for i in range(len(est))]
            par2ec = [np.array([]) for i in range(len(est))]
        else:
            #get them from file
            file = conf.getpath('paths', 'par1gc')
            par1gc_dict = parameters_fetcher_prob_prog(file)
            file = conf.getpath('paths', 'par1mc')
            par1mc_dict = parameters_fetcher_prob_prog(file)
            file = conf.getpath('paths', 'par1ec')
            par1ec_dict = parameters_fetcher_prob_prog(file)
            file = conf.getpath('paths', 'par2gc')
            par2gc_dict = parameters_fetcher_prob_prog(file)
            file = conf.getpath('paths', 'par2mc')
            par2mc_dict = parameters_fetcher_prob_prog(file)
            file = conf.getpath('paths', 'par2ec')
            par2ec_dict = parameters_fetcher_prob_prog(file)
            par1gc =[np.array([]) for i in range(len(est))]
            for i in range(len(par1gc_dict)):
                par1gc[i] = np.append(par1gc[i], [par1gc_dict[i][1]['par']])
                # par1gc.append(d[1]['par'])
            par1mc =[np.array([]) for i in range(len(est))]
            for i in range(len(par1mc_dict)):
                par1mc[i] = np.append(par1mc[i], [par1mc_dict[i][1]['par']])
            par1ec =[np.array([]) for i in range(len(est))]
            for i in range(len(par1ec_dict)):
                par1ec[i] = np.append(par1ec[i], [par1ec_dict[i][1]['par']])
            par2gc =[np.array([]) for i in range(len(est))]
            for i in range(len(par2gc_dict)):
                par2gc[i] = np.append(par2gc[i], [par2gc_dict[i][1]['par']])
            par2mc =[np.array([]) for i in range(len(est))]
            for i in range(len(par2mc_dict)):
                par2mc[i] = np.append(par2mc[i], [par2mc_dict[i][1]['par']])
            par2ec =[np.array([]) for i in range(len(est))]
            for i in range(len(par2ec_dict)):
                par2ec[i] = np.append(par2ec[i], [par2ec_dict[i][1]['par']])
        new_par1gc, new_par1mc, new_par1ec, new_par2gc, new_par2mc, new_par2ec= parameters_calculation(est_exitguard, est_exit, est_guard, est_middle, obs_this_round, par1gc, par1mc, par1ec, par2gc, par2mc, par2ec, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0,  5350, 5350)    
        # new_est, new_par1gc, new_par1mc, new_par1ec, new_par2gc, new_par2mc, new_par2ec=prob_programming_shadow(est_exitguard, est_exit, est_guard, est_middle, w_1, w_2, w_3 , obs_this_round, observations,  par1gc, par1mc, par1ec, par2gc, par2mc, par2ec, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0,  5350, 5350,10, 100000)    
        # hus = probabilistic_programming_algo(model, guide, 10000, relay_estimate, relay_par1gc, relay_par1mc, relay_par1ec, relay_par2gc, relay_par2mc, relay_par2ec, number_of_paths, relay_weight_first, relay_weight_second, relay_weight_third, relay_observations)
        
        # for i in range(3):
        #     log.debug('starting loop')
        #     thread = threading.Thread(target=probabilistic_programming_algo(model, guide, 100000, 10750, [0], [0], [1796.45], [0], [0], [1], 100, [0], [0], [0.25], [6636]))
        #     thread.start()
        #     # wait here for the result to be available before continuing
        #     # thread.join()
        #     while hus is None:
        #         time.sleep(4)
        #     r= hus
        #     log.debug('Probabilistic programming: '+str(r))

        output = conf.getpath('paths', 'par1gc')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par1gc[i][len(new_par1gc[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1
        output = conf.getpath('paths', 'par1mc')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par1mc[i][len(new_par1mc[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1 
        output = conf.getpath('paths', 'par1ec')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par1ec[i][len(new_par1ec[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1
        
        output = conf.getpath('paths', 'par2gc')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par2gc[i][len(new_par2gc[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1
        output = conf.getpath('paths', 'par2mc')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par2mc[i][len(new_par2mc[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1
        output = conf.getpath('paths', 'par2ec')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                i = 0
                for  d in estimates:
                    fd.write('node_id='+str(d[1]['fp'])+'\t'+'par='+str(new_par2ec[i][len(new_par2ec[i])-1])+'\t'+'nick='+str(d[1]['relay'])+'\n')
                    i = i + 1
        ############## PROBABILISTIC PROGRAMMING SCRIPT SHOULD COME HERE ################################################################################
        # i = 0
        # for l in bw_lines_scaled:
        #     l.bw = new_est[i]
        #     i=i+1
        return sorted(bw_lines_scaled, key=lambda x: x.nick, reverse=reverse)

    @staticmethod
    def warn_if_not_accurate_enough(bw_lines,
                                    scale_constant=SBWS_SCALE_CONSTANT):
        margin = 0.001
        accuracy_ratio = median([l.bw for l in bw_lines]) / scale_constant
        log.info('The generated lines are within {:.5}% of what they should '
                 'be'.format((1 - accuracy_ratio) * 100))
        if accuracy_ratio < 1 - margin or accuracy_ratio > 1 + margin:
            log.warning('There was %f%% error and only +/- %f%% is '
                        'allowed', (1 - accuracy_ratio) * 100, margin * 100)

    @staticmethod
    def is_max_bw_diff_perc_reached(bw_lines,
                                    max_bw_diff_perc=MAX_BW_DIFF_PERC,
                                    router_statuses_d=None):
        if router_statuses_d:
            sum_consensus_bw = sum(list(map(
                lambda x: x.bandwidth * 1000,
                router_statuses_d.values()
            )))
        else:
            sum_consensus_bw = sum([
                l.consensus_bandwidth for l in bw_lines
                if getattr(l, 'consensus_bandwidth', None)
            ])
        # Because the scaled bandwidth is in KB, but not the stored consensus
        # bandwidth, multiply by 1000.
        # Do not count the bandwidths for the relays that were excluded
        sum_bw = sum([l.bw for l in bw_lines if getattr(l, "vote", 1)]) * 1000
        # Percentage difference
        diff_perc = (
            abs(sum_consensus_bw - sum_bw)
            # Avoid ZeroDivisionError
            / (max(1, (sum_consensus_bw + sum_bw)) / 2)
            ) * 100
        log.info("The difference between the total consensus bandwidth (%s)"
                 "and the total measured bandwidth (%s) is %s%%.",
                 sum_consensus_bw, sum_bw, round(diff_perc))
        if diff_perc > MAX_BW_DIFF_PERC:
            log.warning("It is more than %s%%", max_bw_diff_perc)
            return True
        return False

    @staticmethod
    def bw_torflow_scale(conf, bw_lines, desc_bw_obs_type=TORFLOW_OBS_MEAN,
                         cap=TORFLOW_BW_MARGIN,
                         num_round_dig=PROP276_ROUND_DIG, reverse=False,
                         router_statuses_d=None):
        """
        Obtain final bandwidth measurements applying Torflow's scaling
        method.

        See details in :ref:`torflow_aggr`.
        """
        log.info("Calculating relays' bandwidth using Torflow method.")
        mt = [l.bw for l in bw_lines]
        m = sum(mt)/len(mt)
        # log.debug(m)
        # m = median([l.bw for l in bw_lines])
        bw_lines_scaled = copy.deepcopy(bw_lines)
        consensus = consensus_fetcher(conf)
        
        for l in bw_lines_scaled:
            # min is to limit the bw to descriptor average-bandwidth
            # max to avoid bandwidth with 0 value
            # l.bw = max(round(min(l.desc_bw_avg,
            #                      l.bw * scale_constant / m)
            #                  / 1000), 1)
            # log.debug(l)
            # in bytes /s
            ct = consensus[l.nick]*1000
            
            # log.debug(ct)
            # log.debug(bt)
            l.bw = max(round(l.bw * ct / m
                             / 1000), 1)
            
        return sorted(bw_lines_scaled, key=lambda x: x.nick, reverse=reverse)

    @staticmethod
    def read_number_consensus_relays(consensus_path):
        """Read the number of relays in the Network from the cached consensus
        file."""
        num = None
        try:
            num = len(list(parse_file(consensus_path)))
        except (FileNotFoundError, AttributeError):
            log.info("It is not possible to obtain statistics about the "
                     "percentage of measured relays because the cached "
                     "consensus file is not found.")
        log.debug("Number of relays in the network %s", num)
        return num

    @staticmethod
    def read_router_statuses(consensus_path):
        """Read the router statuses from the cached consensus file."""
        router_statuses_d = None
        try:
            router_statuses_d = dict([
                (r.fingerprint, r)
                for r in parse_file(consensus_path)
            ])
        except (FileNotFoundError, AttributeError):
            log.warning("It is not possible to obtain the last consensus"
                        "cached file %s.", consensus_path)
        return router_statuses_d

    @staticmethod
    def measured_progress_stats(num_bw_lines, number_consensus_relays,
                                min_perc_reached_before):
        """ Statistics about measurements progress,
        to be included in the header.

        :param list bw_lines: the bw_lines after scaling and applying filters.
        :param str consensus_path: the path to the cached consensus file.
        :param str state_fpath: the path to the state file
        :returns dict, bool: Statistics about the progress made with
            measurements and whether the percentage of measured relays has been
            reached.

        """
        # cached-consensus should be updated every time that scanner get the
        # network status or descriptors?
        # It will not be updated to the last consensus, but the list of
        # measured relays is not either.
        assert isinstance(number_consensus_relays, int)
        assert isinstance(num_bw_lines, int)
        statsd = {}
        statsd['number_eligible_relays'] = num_bw_lines
        statsd['number_consensus_relays'] = number_consensus_relays
        statsd['minimum_number_eligible_relays'] = round(
            statsd['number_consensus_relays'] * MIN_REPORT / 100)
        statsd['percent_eligible_relays'] = round(
            num_bw_lines * 100 / statsd['number_consensus_relays'])
        statsd['minimum_percent_eligible_relays'] = MIN_REPORT
        if statsd['number_eligible_relays'] < \
                statsd['minimum_number_eligible_relays']:
            # if min percent was was reached before, warn
            # otherwise, debug
            if min_perc_reached_before is not None:
                log.warning('The percentage of the measured relays is less '
                            'than the %s%% of the relays in the network (%s).',
                            MIN_REPORT, statsd['number_consensus_relays'])
            else:
                log.info('The percentage of the measured relays is less '
                         'than the %s%% of the relays in the network (%s).',
                         MIN_REPORT, statsd['number_consensus_relays'])
            return statsd, False
        return statsd, True

    @property
    def is_min_perc(self):
        if getattr(self.header, 'number_eligible_relays', 0) \
                < getattr(self.header, 'minimum_number_eligible_relays', 0):
            return False
        return True

    @property
    def sum_bw(self):
        return sum([l.bw for l in self.bw_lines if hasattr(l, 'bw')])

    @property
    def num(self):
        return len(self.bw_lines)

    @property
    def mean_bw(self):
        return mean([l.bw for l in self.bw_lines if hasattr(l, 'bw')])

    @property
    def median_bw(self):
        return median([l.bw for l in self.bw_lines if hasattr(l, 'bw')])

    @property
    def max_bw(self):
        return max([l.bw for l in self.bw_lines if hasattr(l, 'bw')])

    @property
    def min_bw(self):
        return min([l.bw for l in self.bw_lines if hasattr(l, 'bw')])

    @property
    def info_stats(self):
        if not self.bw_lines:
            return
        [log.info(': '.join([attr, str(getattr(self, attr))])) for attr in
         ['sum_bw', 'mean_bw', 'median_bw', 'num',
          'max_bw', 'min_bw']]

    def update_progress(self, num_bw_lines, header, number_consensus_relays,
                        state):
        """
        Returns True if the minimim percent of Bandwidth Lines was reached
        and False otherwise.
        Update the header with the progress.
        """
        min_perc_reached_before = state.get('min_perc_reached')
        if number_consensus_relays is not None:
            statsd, success = self.measured_progress_stats(
                num_bw_lines, number_consensus_relays, min_perc_reached_before)
            # add statistics about progress always
            header.add_stats(**statsd)
            if not success:
                # From sbws 1.1.0 the lines are reported (#29853) even if they
                # are less than the minimum percent.
                state['min_perc_reached'] = None
                return False
            else:
                state['min_perc_reached'] = now_isodt_str()
                return True

    def bw_line_for_node_id(self, node_id):
        """Returns the bandwidth line for a given node fingerprint.

        Used to combine data when plotting.
        """
        bwl = [l for l in self.bw_lines if l.node_id == node_id]
        if bwl:
            return bwl[0]
        return None

    def to_plt(self, attrs=['bw'], sorted_by=None):
        """Return bandwidth data in a format useful for matplotlib.

        Used from external tool to plot.
        """
        x = [i for i in range(0, self.num)]
        ys = [[getattr(l, k) for l in self.bw_lines] for k in attrs]
        return x, ys, attrs

    def write(self, conf, output):
        if output == '/dev/stdout':
            log.info("Writing to stdout is not supported.")
            return
        log.info('Writing v3bw file to %s', output)
        # To avoid inconsistent reads, the bandwidth data is written to an
        # archive path, then atomically symlinked to 'latest.v3bw'
        out_dir = os.path.dirname(output)
        # out_link = os.path.join(out_dir, 'v3bw')
        # out_link_tmp = out_link + '.tmp'
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                # fd.write(str(self.header))
                for line in self.bw_lines:
                    # fd.write(str(line))
                    fd.write('node_id='+str(line.node_id)+'\t'+'bw='+str(line.bw)+'\t'+'nick='+str(line.nick)+'\n')
        output = conf.getpath('paths', 'estimates_file')
        out_dir = os.path.dirname(output)
        with DirectoryLock(out_dir):
            with open(output, 'a') as fd:
                # fd.write(str(self.header))
                for line in self.bw_lines:
                    # fd.write(str(line))
                    fd.write('node_id='+str(line.node_id)+'\t'+'bw='+str(line.bw)+'\t'+'nick='+str(line.nick)+'\n')
            # output_basename = os.path.basename(output)
            # # To atomically symlink a file, we need to create a temporary link,
            # # then rename it to the final link name. (POSIX guarantees that
            # # rename is atomic.)
            # log.debug('Creating symlink {} -> {}.'
            #           .format(out_link_tmp, output_basename))
            # os.symlink(output_basename, out_link_tmp)
            # log.debug('Renaming symlink {} -> {} to {} -> {}.'
            #           .format(out_link_tmp, output_basename,
            #                   out_link, output_basename))
            # os.rename(out_link_tmp, out_link)

# def nonzero(a):
#     return jax.lax.cond(a[0] > 0, a[0], lambda _: 1, a[0], lambda _: 0)

# def model(guess_scale,  sum_bottleneck_weight_gc, sum_bottleneck_weight_mc, sum_bottleneck_weight_ec, sum_weight_gc, sum_weight_mc, sum_weight_ec, number_of_paths, used_weight_guard, used_weight_middle,  used_weight_exit, data_of_relay):
#     scale0 = guess_scale 
#     shape0 = 1
#     C=numpyro.sample("capacity", dist.Weibull(scale0, shape0))    
#     with numpyro.plate("obs", (data_of_relay).size) as i:
#         transform2 = [DoubleAffineTransform(loc1=C+number_of_paths*used_weight_guard[i]*sum_bottleneck_weight_mc[i]+number_of_paths*used_weight_guard[i]*sum_bottleneck_weight_ec[i]+number_of_paths*used_weight_middle[i]*sum_bottleneck_weight_gc[i]+number_of_paths*used_weight_middle[i]*sum_bottleneck_weight_ec[i]+number_of_paths*used_weight_exit[i]*sum_bottleneck_weight_gc[i]+number_of_paths*used_weight_exit[i]*sum_bottleneck_weight_mc[i], scale1=-sum_bottleneck_weight_gc[i]-sum_bottleneck_weight_mc[i]-sum_bottleneck_weight_ec[i], loc2=1-number_of_paths*used_weight_middle[i]*nonzero(used_weight_guard[i])*(1-sum_weight_gc[i])-number_of_paths*used_weight_middle[i]*nonzero(used_weight_exit[i])*(1-sum_weight_ec[i])-number_of_paths*used_weight_guard[i]*nonzero(used_weight_middle[i])*(1-sum_weight_mc[i])-number_of_paths*used_weight_guard[i]*nonzero(used_weight_exit[i])*(1-sum_weight_ec[i])-number_of_paths*used_weight_exit[i]*nonzero(used_weight_guard[i])*(1-sum_weight_gc[i])-number_of_paths*used_weight_exit[i]*nonzero(used_weight_middle[i])*(1-sum_weight_mc[i]), scale2=nonzero(used_weight_guard[i])*(1-sum_weight_gc[i])+nonzero(used_weight_middle[i])*(1-sum_weight_mc[i])+nonzero(used_weight_exit[i])*(1-sum_weight_ec[i]), total_nb_paths=number_of_paths, obs=data_of_relay[i] )]
#         return numpyro.sample("obs_{}".format(i), dist.TransformedDistribution(dist.Poisson(number_of_paths*(used_weight_guard[i]+used_weight_middle[i]+used_weight_exit[i])), transform2), obs=data_of_relay[i])
    
# def guide(guess_scale,  sum_bottleneck_weight_gc, sum_bottleneck_weight_mc, sum_bottleneck_weight_ec, sum_weight_gc, sum_weight_mc, sum_weight_ec, number_of_paths, used_weight_guard, used_weight_middle,  used_weight_exit, data_of_relay):
#     transform = [dist.transforms.AffineTransform(loc=jax.numpy.max(data_of_relay), scale=1)]
#     scale_q = numpyro.param("scale_q", guess_scale, constraint=constraints.positive)
#     shape_q = numpyro.param("shape_q", 1, constraint=constraints.positive)
#     return numpyro.sample("capacity", dist.TransformedDistribution(dist.Weibull(scale_q, shape_q), transform))

# class DoubleAffineTransform(numpyro.distributions.transforms.Transform):
#     """
# #     Transform via the pointwise affine mapping :math:`y = (\text{loc1} + \text{scale1} \times x)/(\text{loc2} + \text{scale2} \times x)`.

# #     Args:
# #         loc1 / loc2 (Tensor or float): Location parameter.
# #         scale1 / scale2 (Tensor or float): Scale parameter.
# #         event_dim (int): Optional size of `event_shape`. This should be zero
# #             for univariate random variables, 1 for distributions over vectors,
# #             2 for distributions over matrices, etc.
# #     """
  
#     bijective = True
    
#     def __init__(self, loc1, scale1, loc2, scale2, total_nb_paths,obs, event_dim=0):

#         self.loc1 = loc1
#         self.loc2 = loc2
#         self.scale1 = scale1
#         self.scale2 = scale2
#         self.total_nb_paths = total_nb_paths
#         self.obs = obs
#         self._event_dim = event_dim

#     @property
#     def domain(self):
#         return constraints._Interval(0, self.total_nb_paths)


#     @property
#     def codomain(self):
#         return constraints._GreaterThan(self.obs)

#     def _call(self, x):
#         scale1 = self.scale1
#         scale2 = self.scale2
#         loc1 = self.loc1
#         loc2 = self.loc2
#         total_nb_paths = self.total_nb_paths
#         result = (loc1 + scale1 * x) / (loc2 + scale2 * x)
#         return result


#     def _inverse(self, y):
#         scale1 = self.scale1
#         scale2 = self.scale2
#         loc1 = self.loc1
#         loc2 = self.loc2
#         total_nb_paths = self.total_nb_paths
        
#         result = (loc2 * y - loc1) / (scale1 - scale2 * y)
#         return result

    
#     def log_abs_det_jacobian(self, x, y, intermediates=None):

        
#         scale1 = self.scale1
#         scale2 = self.scale2
#         loc1 = self.loc1
#         loc2 = self.loc2
#         obs = self.obs
#         total_nb_paths= self.total_nb_paths
#         result = jnp.broadcast_to(jnp.log(jnp.abs((scale1  - scale2 * y)/ (loc2 + scale2 * x))), jnp.shape(x))
#         return result


def input_for_model_underloaded(avg_client, estimated_C_guard, estimated_C_middle, estimated_C_exit, observation_all, Wgc, Wmc, Wec, index_of_relay):
    
    first_position = copy.deepcopy(estimated_C_guard)
    second_position = copy.deepcopy(estimated_C_middle)
    third_position = copy.deepcopy(estimated_C_exit)

    obs_all = copy.deepcopy(observation_all)

    sum_bottleneck_weight_pairs_gc=0
    sum_bottleneck_weight_pairs_mc=0
    sum_bottleneck_weight_pairs_ec=0
    
    sum_weight_pairs_gc=0
    sum_weight_pairs_mc=0
    sum_weight_pairs_ec=0
    
    
    bottleneck_target=obs_all[index_of_relay] 
    
    # used in exit
    if Wec>0:
        wm= np.delete(second_position, index_of_relay)
        l=sum(wm)
        wm=wm/l
        observation_all_middle=np.delete(obs_all, index_of_relay)
    
        wg= np.delete(first_position, index_of_relay)
#         observation_all_guard=np.delete(observation_all, index_of_relay)
        
        # log.debug(first_position)
        # log.debug(wg)
    
        for i in range(len(observation_all_middle)):
            wg2=np.delete(wg,i)
            l=sum(wg2)
            wg2=wg2/l
            observation_all_guard2=np.delete(observation_all_middle,i)
            for j in range(len(observation_all_guard2)):
                if min(observation_all_middle[i],observation_all_guard2[j], avg_client)<bottleneck_target:
                    sum_bottleneck_weight_pairs_ec=sum_bottleneck_weight_pairs_ec+min(observation_all_middle[i],observation_all_guard2[j], avg_client)*wm[i]*wg2[j]
                    sum_weight_pairs_ec=sum_weight_pairs_ec+wm[i]*wg2[j]
    
    # used in middle
    if Wmc>0:
        wg= np.delete(first_position, index_of_relay)
        l=sum(wg)
        wg=wg/l
        observation_all_guard=np.delete(obs_all, index_of_relay)
    
        we= np.delete(third_position, index_of_relay)
#         observation_all_exit=np.delete(observation_all, index_of_relay)
        
    
    
        for i in range(len(observation_all_guard)):
            we2=np.delete(we,i)
            l=sum(we2)
            we2=we2/l
            observation_all_exit2=np.delete(observation_all_guard,i)
            for j in range(len(observation_all_exit2)):
                if min(observation_all_guard[i],observation_all_exit2[j], avg_client)<bottleneck_target:
                    sum_bottleneck_weight_pairs_mc=sum_bottleneck_weight_pairs_mc+min(observation_all_guard[i],observation_all_exit2[j], avg_client)*wg[i]*we2[j]
                    sum_weight_pairs_mc=sum_weight_pairs_mc+wg[i]*we2[j]
    
    
    
    # used in guard
    if Wgc>0:
        wm= np.delete(second_position, index_of_relay)
        l=sum(wm)
        wm=wm/l
        observation_all_middle=np.delete(obs_all, index_of_relay)
    
        we= np.delete(third_position, index_of_relay)
#         observation_all_exit=np.delete(observation_all, index_of_relay)
        
    
    
        for i in range(len(observation_all_middle)):
            we2=np.delete(we,i)
            l=sum(we2)
            we2=we2/l
            observation_all_exit2=np.delete(observation_all_middle,i)
            for j in range(len(observation_all_exit2)):
                if min(observation_all_middle[i],observation_all_exit2[j], avg_client)<bottleneck_target:
                    sum_bottleneck_weight_pairs_gc=sum_bottleneck_weight_pairs_gc+min(observation_all_middle[i],observation_all_exit2[j], avg_client)*wm[i]*we2[j]
                    sum_weight_pairs_gc=sum_weight_pairs_gc+wm[i]*we2[j]
    return [ sum_bottleneck_weight_pairs_gc, sum_bottleneck_weight_pairs_mc, sum_bottleneck_weight_pairs_ec, sum_weight_pairs_gc, sum_weight_pairs_mc, sum_weight_pairs_ec]

def parameters_calculation(estimates_guard_exit, estimates_exit, estimates_guard, estimates_not_flagged, observations_this_round, par1gc, par1mc, par1ec, par2gc, par2mc, par2ec, Wgd, Wmd, Wed, Wge, Wme, Wee, Wgg, Wmg, Weg, Wgm, Wmm, Wem,  minclient, maxclient):
                            
    scale_estimate= np.append(estimates_guard_exit, estimates_exit)
    scale_estimate= np.append(scale_estimate, estimates_guard)
    scale_estimate= np.append(scale_estimate, estimates_not_flagged)
    # log.debug(scale_estimate)
    expected_client=(maxclient-minclient)/2+minclient
    log.debug(scale_estimate)

    estimates= np.append(estimates_guard_exit, estimates_exit)
    estimates= np.append(estimates, estimates_guard)
    estimates= np.append(estimates, estimates_not_flagged)
    
    estimated_C_guard= np.append(Wgd*estimates_guard_exit, Wge*estimates_exit)
    estimated_C_guard= np.append(estimated_C_guard, Wgg*estimates_guard)
    estimated_C_guard= np.append(estimated_C_guard, Wgm*estimates_not_flagged)
    log.debug(estimated_C_guard)                               
        
    estimated_C_middle= np.append(Wmd*estimates_guard_exit, Wme*estimates_exit)
    estimated_C_middle= np.append(estimated_C_middle, Wmg*estimates_guard)
    estimated_C_middle= np.append(estimated_C_middle, Wmm*estimates_not_flagged)
    log.debug(estimated_C_middle)    
        
    estimated_C_exit= np.append(Wed*estimates_guard_exit, Wee*estimates_exit)
    estimated_C_exit= np.append(estimated_C_exit, Weg*estimates_guard)
    estimated_C_exit= np.append(estimated_C_exit, Wem*estimates_not_flagged)
    log.debug(estimated_C_exit)


    new_par1gc = copy.deepcopy(par1gc)
    new_par1mc = copy.deepcopy(par1mc)
    new_par1ec = copy.deepcopy(par1ec)
    new_par2gc = copy.deepcopy(par2gc)
    new_par2mc = copy.deepcopy(par2mc)
    new_par2ec = copy.deepcopy(par2ec)


        
    for i in range(len(estimates_guard_exit)):
        [bpgc, bpmc, bpec, pgc, pmc, pec]=input_for_model_underloaded(expected_client, estimated_C_guard, estimated_C_middle, estimated_C_exit, observations_this_round, Wgd, Wmd, Wed, i)
        ## should print the values to a file
        new_par1gc[i]=np.append(new_par1gc[i],[bpgc])
        new_par1mc[i]=np.append(new_par1mc[i],[bpmc])
        new_par1ec[i]=np.append(new_par1ec[i],[bpec])
        new_par2gc[i]=np.append(new_par2gc[i],[pgc])
        new_par2mc[i]=np.append(new_par2mc[i],[pmc])
        new_par2ec[i]=np.append(new_par2ec[i],[pec])
        

    for i in range(len(estimates_exit)):
        [bpgc, bpmc, bpec, pgc, pmc, pec]=input_for_model_underloaded(expected_client, estimated_C_guard, estimated_C_middle, estimated_C_exit, observations_this_round, Wge, Wme, Wee, i+len(estimates_guard_exit))
        new_par1gc[i+len(estimates_guard_exit)]=np.append(new_par1gc[i+len(estimates_guard_exit)],[bpgc])
        new_par1mc[i+len(estimates_guard_exit)]=np.append(new_par1mc[i+len(estimates_guard_exit)],[bpmc])
        new_par1ec[i+len(estimates_guard_exit)]=np.append(new_par1ec[i+len(estimates_guard_exit)],[bpec])
        new_par2gc[i+len(estimates_guard_exit)]=np.append(new_par2gc[i+len(estimates_guard_exit)],[pgc])
        new_par2mc[i+len(estimates_guard_exit)]=np.append(new_par2mc[i+len(estimates_guard_exit)],[pmc])
        new_par2ec[i+len(estimates_guard_exit)]=np.append(new_par2ec[i+len(estimates_guard_exit)],[pec])
        
        
    for i in range(len(estimates_guard)):
        [bpgc, bpmc, bpec, pgc, pmc, pec]=input_for_model_underloaded(expected_client, estimated_C_guard, estimated_C_middle, estimated_C_exit, observations_this_round, Wgg, Wmg, Weg, i+len(estimates_guard_exit)+len(estimates_exit))
        new_par1gc[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par1gc[i+len(estimates_guard_exit)+len(estimates_exit)],[bpgc])
        new_par1mc[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par1mc[i+len(estimates_guard_exit)+len(estimates_exit)],[bpmc])
        new_par1ec[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par1ec[i+len(estimates_guard_exit)+len(estimates_exit)],[bpec])
        new_par2gc[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par2gc[i+len(estimates_guard_exit)+len(estimates_exit)],[pgc])
        new_par2mc[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par2mc[i+len(estimates_guard_exit)+len(estimates_exit)],[pmc])
        new_par2ec[i+len(estimates_guard_exit)+len(estimates_exit)]=np.append(new_par2ec[i+len(estimates_guard_exit)+len(estimates_exit)],[pec])
        
        
    for i in range(len(estimates_not_flagged)):
        [bpgc, bpmc, bpec, pgc, pmc, pec]=input_for_model_underloaded(expected_client, estimated_C_guard, estimated_C_middle, estimated_C_exit, observations_this_round, Wgm, Wmm, Wem, i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit))
        new_par1gc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par1gc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[bpgc])
        new_par1mc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par1mc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[bpmc])
        new_par1ec[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par1ec[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[bpec])
        new_par2gc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par2gc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[pgc])
        new_par2mc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par2mc[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[pmc])
        new_par2ec[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)]=np.append(new_par2ec[i+len(estimates_guard_exit)+len(estimates_guard)+len(estimates_exit)],[pec])
        
    return new_par1gc, new_par1mc, new_par1ec, new_par2gc, new_par2mc, new_par2ec

# def probabilistic_programming_algo(mdl, gd, num_steps_inference, relay_estimate, relay_par1gc, relay_par1mc, relay_par1ec, relay_par2gc, relay_par2mc, relay_par2ec, number_of_paths, relay_weight_first, relay_weight_second, relay_weight_third, relay_observations):    
#     optimizer =Adam(0.01)
#     svi = SVI(mdl, gd, optim=optimizer, loss=Trace_ELBO())
#     svi_result= svi.run(jax.random.PRNGKey(0), num_steps_inference, relay_estimate,  jnp.array(relay_par1gc), jnp.array(relay_par1mc), jnp.array(relay_par1ec), jnp.array(relay_par2gc), jnp.array(relay_par2mc), jnp.array(relay_par2ec),number_of_paths, jnp.array(relay_weight_first), jnp.array(relay_weight_second), jnp.array(relay_weight_third),jnp.array(relay_observations), progress_bar=False)
#     global hus
#     hus = max(relay_observations)+ svi_result.params["scale_q"]
#     # return max(relay_observations)+ svi_result.params["scale_q"]