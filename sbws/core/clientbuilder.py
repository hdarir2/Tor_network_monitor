''' Measure the relays. '''
import queue
import bisect
import numpy as np
import signal
import sys
import threading
import traceback
import uuid
import subprocess
from multiprocessing.context import TimeoutError
from stem.control import EventType
from ..lib.circuitbuilder import GapsCircuitBuilder as CB
from ..lib.resultdump import ResultDump
from ..lib.resultdump import (
    ResultSuccess, ResultErrorCircuit, ResultErrorStream,
    ResultErrorSecondRelay,  ResultError, ResultErrorDestination
    )
# from ..lib.resultdump import (load_result_file2)
from ..lib.relaylist import RelayList
from ..lib.relayprioritizer import RelayPrioritizer
from ..lib.destination import (DestinationList,
                               connect_to_destination_over_circuit, find_circuit_built)
from ..util.timestamp import now_isodt_str
from ..util.state import State
from sbws.globals import fail_hard, HTTP_GET_HEADERS, TIMEOUT_MEASUREMENTS
import sbws.util.stem as stem_utils
import sbws.util.requests as requests_utils
from argparse import ArgumentDefaultsHelpFormatter
from multiprocessing.dummy import Pool
import time
import os
import logging
import random
from stem import (SocketError, InvalidRequest, UnsatisfiableRequest,
                  OperationFailed, ControllerError, InvalidArguments,
                  ProtocolError, SocketClosed)
from stem import CircuitExtensionFailed,  Timeout
from sbws.util.filelock import DirectoryLock
from .. import settings
from ..lib.heartbeat import Heartbeat
import re
from sbws.lib.v3bwfile import V3BWLine
from ..lib.resultdump import (Result)
rng = random.SystemRandom()
log = logging.getLogger(__name__)
# Declare the objects that manage the threads global so that sbws can exit
# gracefully at any time.
pool = None
rd = None
controller = None

FILLUP_TICKET_MSG = """Something went wrong.
Please create an issue at
https://gitlab.torproject.org/tpo/network-health/sbws/-/issues with this
traceback."""


def stop_threads(signal, frame, exit_code=0):
    global rd, pool
    log.debug('Stopping sbws.')
    # Avoid new threads to start.
    settings.set_end_event()
    # Stop Pool threads
    pool.close()
    pool.join()
    # Stop ResultDump thread
    rd.thread.join()
    # Stop Tor thread
    controller.close()
    sys.exit(exit_code)


# signal.signal(signal.SIGTERM, stop_threads)

def dumpstacks():
    log.critical(FILLUP_TICKET_MSG)
    thread_id2name = dict([(t.ident, t.name) for t in threading.enumerate()])
    for thread_id, stack in sys._current_frames().items():
        log.critical("Thread: %s(%d)",
                     thread_id2name.get(thread_id, ""), thread_id)
        log.critical(traceback.format_stack("".join(stack)))
    # If logging level is less than DEBUG (more verbose), start pdb so that
    # developers can debug the issue.
    if log.getEffectiveLevel() < logging.DEBUG:
        import pdb
        pdb.set_trace()
    # Otherwise exit.
    else:
        # Change to stop threads when #28869 is merged
        sys.exit(1)



def gen_parser(sub):
    d = 'The script responsible for building client connections'
    sub.add_parser('clientbuilder', formatter_class=ArgumentDefaultsHelpFormatter,
                   description=d)

def circuit_chooser(controller):
    circuits_id=[]
    # circuits_purpose=[]
    # circuits_build_flags=[]
    circuits=controller.get_circuits()
    for circ in circuits:
        if circ.purpose == 'GENERAL' and len(circ.build_flags)==1 and circ.build_flags[0]=='NEED_CAPACITY':
            maybe=0
            for c in circ.path:
                if c[1] == 'relay1exitguard':
                    maybe=1
            if maybe ==0:
                circuits_id.append(circ.id)
            # hus=circ.path
            # log.debug(hus[0][0])
    while len(circuits_id)==0:
        circuits=controller.get_circuits()
        for circ in circuits:
            if circ.purpose == 'GENERAL' and len(circ.build_flags)==1 and circ.build_flags[0]=='NEED_CAPACITY':
                # log.debug(circ.path)
                maybe=0
                for c in circ.path:
                    if c[1] == 'relay1exitguard':
                        maybe=1
                if maybe ==0:
                    circuits_id.append(circ.id)
        log.debug('Waiting for circuit')
        time.sleep(5)
        # circuits_purpose.append(circ.purpose)
        # circuits_build_flags.append(circ.build_flags)
    circ_id=int(random.choice(circuits_id))
    log.debug('Client chose CIRC %s', circ_id)
    # time.sleep(1)
    return circ_id

def stream_chooser(controller):
    streams_id=[]
    streams=controller.get_streams()
    # streams_id.append(streams[0].id)
    while len(streams)==0:
        time.sleep(1)
        streams=controller.get_streams()
        log.debug('Waiting for stream')
    streams_id.append(streams[0].id)
    
    # log.debug(streams)
    st=streams_id[0]
    return st


def _pick_ideal_second_hop_authority(rl, cont):
    '''
    Sbws builds two hop circuits. Given the **relay** to measure with
    destination **dest**, pick a second relay that is or is not an exit
    according to **is_exit**.
    '''
    candidates = rl.authorities
    candidates = sorted(candidates, key=lambda r: r.consensus_bandwidth,
                        reverse=True)
    nb_candidates=len(candidates)
    index_cand=random.randint(0, nb_candidates-2)
    chosen = candidates[index_cand]
    return chosen

def _pick_ideal_second_hop_relay2exit(rl):
    candidates = rl.exits
    for i in range(len(candidates)):
        if str(candidates[i].nickname)=='relay2exitguard':
            log.debug('Found it')
            # chosen =ch
            return candidates[i]

def create_path_relay(rl, cb):
    # helper1 = _pick_ideal_second_hop_authority(rl, cb.controller)
    # # helper2 = _pick_ideal_second_hop_relay2exit(
    #         # rl)
    # helper2 = _pick_ideal_second_hop_authority(rl, cb.controller)
    # while helper2.nickname == helper1.nickname:
    #     helper2 = _pick_ideal_second_hop_authority(rl, cb.controller)
    # helper3 = _pick_ideal_second_hop_authority(rl, cb.controller)
    # while helper3.nickname == helper1.nickname or helper3.nickname == helper2.nickname:
    #     helper3 = _pick_ideal_second_hop_authority(rl, cb.controller)
    # circ_fps = [helper1.fingerprint, helper2.fingerprint, helper3.fingerprint]
    # nicknames = [helper1.nickname, helper2.nickname, helper3.nickname]
    # exit_policy = helper3.exit_policy
    # time.sleep(1)
    circ_fps=[]
    nicknames=[]
    candidates=rl.authorities
    for i in range(3):
        circ_fps.append(candidates[i].fingerprint)
        nicknames.append(candidates[i].nickname)
    exit_policy=candidates[2].exit_policy
    return circ_fps, nicknames, exit_policy

def consensus_fetcher(conf):
    consensus=[]
    bw_exitguard=[]
    bw_exit=[]
    bw_guard=[]
    bw_middle=[]
    # otf=open("/home/hdarir2/simulation_12relays_random/12relays/shadow.data/hosts/bwauthority/v3bw", "rt")
    path = conf.getpath('paths', 'consensus_file')
    # path = path+'/v3bw'
    otf=open(path, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            if m.group(6)=='exitguard':
                bw_exitguard.append({'relay': 'relay'+m.group(5)+m.group(6),'bw': m.group(3), 'fp':m.group(1)[9:]})
            if m.group(6)=='exit':
                bw_exit.append({'relay': 'relay'+m.group(5)+m.group(6),'bw': m.group(3), 'fp':m.group(1)[9:]})
            if m.group(6)=='guard':
                bw_guard.append({'relay': 'relay'+m.group(5)+m.group(6),'bw': m.group(3), 'fp':m.group(1)[9:]})
            if m.group(6)=='middle':
                bw_middle.append({'relay': 'relay'+m.group(5)+m.group(6),'bw': m.group(3), 'fp':m.group(1)[9:]})
            consensus.append({'relay': 'relay'+m.group(5)+m.group(6), 'bw': m.group(3), 'fp':m.group(1)[9:]})
    return consensus, bw_exitguard, bw_exit, bw_guard, bw_middle

## For unordered consensus:
def fetcher(file):
    consensus={}
    # path = path+'/v3bw'
    otf=open(file, "rt")
    # otf=open("/home/hdarir2/simulation_3relays/3relays_sbws_final/shadow.data/hosts/bwauthority/v3bw", "rt")
    for line in otf:
        if m := re.search('(\S+)(.*)bw=(\d+)(.*)nick=relay(\d+)(\S+)', line):
            consensus['relay'+m.group(5)+m.group(6)]={'number': int(m.group(5)), 'relay': 'relay'+m.group(5)+m.group(6), 'bw': m.group(3), 'fp': m.group(1)[9:]}
    consensus = sorted(consensus.items(), key=lambda item: item[1]['number'])
    # log.debug(consensus)
    return consensus

def writer(output, consensus):
    out_dir = os.path.dirname(output)
    with DirectoryLock(out_dir):
        with open(output, 'a') as fd:
                # fd.write(str(self.header))
            for  d in consensus:
                    # fd.write(str(line))
                fd.write('node_id='+str(d[1]['fp'])+'\t'+'bw='+str(d[1]['bw'])+'\t'+'nick='+str(d[1]['relay'])+'\n')


def cum_density(c):
    cumbw = np.cumsum(c).astype(float)
    return cumbw / np.sum(c)

def rand_relay(c):

    x = random.random()
    return bisect.bisect_left(cum_density(c), x)


def weight_builder(consensus,bw_exitguard, bw_exit, bw_guard, bw_middle, Wgd, Wmd, Wed, Wge, Wme, Wee, Wgg, Wmg, Weg, Wgm, Wmm, Wem):
    bw_first=[]
    bw_second=[]
    bw_third=[]
    bw_first_tag=[[] for i in range(len(consensus))]
    bw_second_tag=[[] for i in range(len(consensus))]
    bw_third_tag=[[] for i in range(len(consensus))]
    for i in range(len(bw_exitguard)):
        bw_first.append(Wgd*int(bw_exitguard[i]['bw']))
        bw_second.append(Wmd*int(bw_exitguard[i]['bw']))
        bw_third.append(Wed*int(bw_exitguard[i]['bw']))
        bw_first_tag[i]=[bw_exitguard[i]['relay'], Wgd*int(bw_exitguard[i]['bw']), bw_exitguard[i]['fp']]
        bw_second_tag[i]=[bw_exitguard[i]['relay'], Wmd*int(bw_exitguard[i]['bw']), bw_exitguard[i]['fp']]
        bw_third_tag[i]=[bw_exitguard[i]['relay'], Wed*int(bw_exitguard[i]['bw']), bw_exitguard[i]['fp']]
    for i in range(len(bw_exit)):
        bw_first.append(Wge*int(bw_exit[i]['bw']))
        bw_second.append(Wme*int(bw_exit[i]['bw']))
        bw_third.append(Wee*int(bw_exit[i]['bw']))
        bw_first_tag[i+len(bw_exitguard)]=[bw_exit[i]['relay'], Wge*int(bw_exit[i]['bw']), bw_exit[i]['fp']]
        bw_second_tag[i+len(bw_exitguard)]=[bw_exit[i]['relay'], Wme*int(bw_exit[i]['bw']), bw_exit[i]['fp']]
        bw_third_tag[i+len(bw_exitguard)]=[bw_exit[i]['relay'], Wee*int(bw_exit[i]['bw']), bw_exit[i]['fp']]
    for i in range(len(bw_guard)):
        bw_first.append(Wgg*int(bw_guard[i]['bw']))
        bw_second.append(Wmg*int(bw_guard[i]['bw']))
        bw_third.append(Weg*int(bw_guard[i]['bw']))
        bw_first_tag[i+len(bw_exitguard)+len(bw_exit)]=[bw_guard[i]['relay'], Wgg*int(bw_guard[i]['bw']), bw_guard[i]['fp']]
        bw_second_tag[i+len(bw_exitguard)+len(bw_exit)]=[bw_guard[i]['relay'], Wmg*int(bw_guard[i]['bw']), bw_guard[i]['fp']]
        bw_third_tag[i+len(bw_exitguard)+len(bw_exit)]=[bw_guard[i]['relay'], Weg*int(bw_guard[i]['bw']), bw_guard[i]['fp']]
    for i in range(len(bw_middle)):
        bw_first.append(Wgm*int(bw_middle[i]['bw']))
        bw_second.append(Wmm*int(bw_middle[i]['bw']))
        bw_third.append(Wem*int(bw_middle[i]['bw']))
        bw_first_tag[i+len(bw_exitguard)+len(bw_exit)+len(bw_guard)]=[bw_middle[i]['relay'], Wgm*int(bw_middle[i]['bw']), bw_middle[i]['fp']]
        bw_second_tag[i+len(bw_exitguard)+len(bw_exit)+len(bw_guard)]=[bw_middle[i]['relay'], Wmm*int(bw_middle[i]['bw']), bw_middle[i]['fp']]
        bw_third_tag[i+len(bw_exitguard)+len(bw_exit)+len(bw_guard)]=[bw_middle[i]['relay'], Wem*int(bw_middle[i]['bw']), bw_middle[i]['fp']]
    return bw_first, bw_second, bw_third, bw_first_tag, bw_second_tag, bw_third_tag
    

def relay_selector(consensus, bw_first, bw_second, bw_third):
    n1=rand_relay(bw_first)
    n2=rand_relay(bw_second)
    n3=rand_relay(bw_third)
    relay1=consensus[n1]['relay']
    relay2=consensus[n2]['relay']
    relay3=consensus[n3]['relay']
    return relay1, relay2, relay3

def atomic_symlink(output):
    out_dir = os.path.dirname(output)
    out_link = os.path.join(out_dir, 'v3bw')
    out_link_tmp = out_link + '.tmp'
    with DirectoryLock(out_dir):
        output_basename = os.path.basename(output)
            # To atomically symlink a file, we need to create a temporary link,
            # then rename it to the final link name. (POSIX guarantees that
            # rename is atomic.)
        log.debug('Creating symlink {} -> {}.'
                      .format(out_link_tmp, output_basename))
        os.symlink(output_basename, out_link_tmp)
        log.debug('Renaming symlink {} -> {} to {} -> {}.'
                      .format(out_link_tmp, output_basename,
                              out_link, output_basename))
        os.rename(out_link_tmp, out_link)

def normalizer(bw_first, bw_second, bw_third):
    s1 = 0
    for i in range(len(bw_first)):
        s1 = s1 + bw_first[i][1]
    s2 = 0
    for i in range(len(bw_second)):
        s2 = s2 + bw_second[i][1]
    s3 = 0
    for i in range(len(bw_third)):
        s3 = s3 + bw_third[i][1]
    return s1, s2, s3



def main_loop(args, conf, controller, relay_list, circuit_builder):
    nb_epochs = conf.getint('general', 'number_epochs')
    data_period = conf.getint('general', 'data_period')
    for k in range(nb_epochs):
        if k>0 and conf.getpath('paths', 'generator') == 'yes':
            file = conf.getpath('paths', 'v3bw_fname').format(k)
            cons = fetcher(file)

            output = conf.getpath('paths', 'consensus_file')
            out_dir = os.path.dirname(output)
            with DirectoryLock(out_dir):
                with open(output, 'wt') as fd:
                    fd.write('946684801'+'\n')
                    fd.write('node_id=$2FC9C693F06E1DB7102D982B80223143AECEE79A'+'\t'+'bw=1'+'\t'+'nick=4uthority1'+'\n')
                    fd.write('node_id=$626CA8768127CDF08F7B02F9FC3788EB0992927B'+'\t'+'bw=1'+'\t'+'nick=4uthority2'+'\n')
                    fd.write('node_id=$4B73A2C90A6DA50C998227EFFFED416598E77F2C'+'\t'+'bw=1'+'\t'+'nick=4uthority3'+'\n')
            writer(output, cons)
            # atomic_symlink(output)
        time_start=time.time()
        Wgd=0
        Wmd=0
        Wed=1
        Wge=0
        Wme=0
        Wee=1
        Wgg=1
        Wmg=0
        Weg=0
        Wgm=0
        Wmm=1
        Wem=0
        consensus, bw_exitguard, bw_exit, bw_guard, bw_middle= consensus_fetcher(conf)
        # log.debug(consensus)
        bw_first, bw_second, bw_third, bw_first_tag, bw_second_tag, bw_third_tag=weight_builder(consensus,bw_exitguard, bw_exit, bw_guard, bw_middle, Wgd, Wmd, Wed, Wge, Wme, Wee, Wgg, Wmg, Weg, Wgm, Wmm, Wem)
        # log.debug(bw_first_tag)
        
        if conf.getpath('paths', 'generator') == 'yes':
            sum_first, sum_second, sum_third = normalizer(bw_first_tag, bw_second_tag, bw_third_tag)
            # Writhing the weight used for first position:
            output = conf.getpath('paths', 'weight_first')
            out_dir = os.path.dirname(output)
            with DirectoryLock(out_dir):
                with open(output, 'a') as fd:
                    for  d in bw_first_tag:
                        fd.write('node_id='+str(d[2])+'\t'+'bw='+str(d[1]/sum_first)+'\t'+'nick='+str(d[0])+'\n')
            # Writhing the weight used for second position:
            output = conf.getpath('paths', 'weight_second')
            out_dir = os.path.dirname(output)
            with DirectoryLock(out_dir):
                with open(output, 'a') as fd:
                    for  d in bw_second_tag:
                        fd.write('node_id='+str(d[2])+'\t'+'bw='+str(d[1]/sum_second)+'\t'+'nick='+str(d[0])+'\n')
            # Writhing the weight used for third position:
            output = conf.getpath('paths', 'weight_third')
            out_dir = os.path.dirname(output)
            with DirectoryLock(out_dir):
                with open(output, 'a') as fd:
                    for  d in bw_third_tag:
                        fd.write('node_id='+str(d[2])+'\t'+'bw='+str(d[1]/sum_third)+'\t'+'nick='+str(d[0])+'\n')


        relay1, relay2, relay3=relay_selector(consensus, bw_first, bw_second, bw_third)
        circ_fps=[]
        nicknames=[]
        circ_fps2=[]
        nicknames2=[]
        ##ADD A FOURTH RELAY:
        relays=relay_list.notauthorities
        for r in relays:
            if r.nickname==relay1:
                circ_fps.append(r.fingerprint)
                nicknames.append(r.nickname)
                circ_fps2.append(r.fingerprint)
                nicknames2.append(r.nickname)
        ##ADDING AN AUTHORITY
        # relays=relay_list.authorities
        # for r in relays:
        #     if r.nickname=='4uthority1':
        #         circ_fps.append(r.fingerprint)
        #         nicknames.append(r.nickname)
        # relays=relay_list.notauthorities
        ###
        for r in relays:
            if r.nickname==relay2:
                circ_fps.append(r.fingerprint)
                nicknames.append(r.nickname)
                circ_fps2.append(r.fingerprint)
                nicknames2.append(r.nickname)
        ##ADDING AN AUTHORITY INSTEAD
        # relays=relay_list.authorities
        # for r in relays:
        #     if r.nickname=='4uthority2':
        #         circ_fps.append(r.fingerprint)
        #         nicknames.append(r.nickname)
        # relays=relay_list.notauthorities
        ###
        for r in relays:
            if r.nickname==relay3:
                circ_fps.append(r.fingerprint)
                nicknames.append(r.nickname)
                circ_fps2.append(r.fingerprint)
                nicknames2.append(r.nickname)
        relays=relay_list.authorities
        #ADDING AN AUTHORITY INSTEAD
        # relays=relay_list.authorities
        # for r in relays:
        #     if r.nickname=='4uthority3':
        #         circ_fps.append(r.fingerprint)
        #         nicknames.append(r.nickname)
        # relays=relay_list.notauthorities
        ###
        ###########################

        circ_id, reason = circuit_builder.build_circuit(circ_fps)
        while circ_id == None:
            log.debug('Waiting to build CIRC')
            time.sleep(10)
            circ_id, reason = circuit_builder.build_circuit(circ_fps)
            
        log.debug('Built circuit with path %s (%s)',
                circ_fps2, nicknames2)    
        time.sleep(1)
        ###########
    
        ###ONE RELAY CIRCUIT

        # relays=relay_list.notauthorities
        # nb_candidates=len(relays)
        # index_cand=random.randint(0, nb_candidates-1)
        # chosen = relays[index_cand]
        # circ_fps=[chosen.fingerprint]
        # nicknames=[chosen.nickname]
        # circ_id, reason = circuit_builder.build_circuit(circ_fps)
        # # circ_id = controller.new_circuit([chosen], purpose='general', build_flags='ONEHOP_TUNNEL')
        # while circ_id == None:
        #     circ_id, reason = circuit_builder.build_circuit(circ_fps)
        #     # circ_id = controller.new_circuit([chosen], purpose='general', build_flags='ONEHOP_TUNNEL')
        #     log.debug('Waiting to build CIRC')
        #     time.sleep(10)
        # log.debug('Built circuit with path %s (%s)',
        #           circ_fps, nicknames)    
        # time.sleep(1)
        ###############

    
        ##FIND AN ALREADY BUILT CIRCUIT
        # circ_id=circuit_chooser(controller)

        #####

        stream_id=stream_chooser(controller)
        log.debug('Attaching stream %s to circ %s', stream_id, circ_id)
    
        controller.attach_stream(stream_id, circ_id)
        # if len(streams)==0:
        #     log.debug('ERROR')
        # for st in streams:
        #     if st.status == 'NEW' and st.purpose == 'USER':
        #         log.debug(st.id)
        
        # connect_to_destination_over_circuit(circ_id, controller)
        # log.debug("Connecting to destination over circuit.")

        # # # with stem_utils.stream_building_lock:
        # listener = stem_utils.attach_stream_to_circuit_listener(controller, circ_id)
        # stem_utils.add_event_listener(controller, listener, EventType.STREAM)
        # time.sleep(5)
        #     # stem_utils.remove_event_listener(cont, listener)
        # log.debug('Connected over circuit %s', circ_id)
        # log.debug('Attaching stream %s to circ %s %s', st.id, circ_id,
        #                   circuit_str(controller, circ_id))
        #         try:
        #             controller.attach_stream(st.id, circ_id)
        time_stop=time.time()
        time.sleep(time_start+(data_period*60)-time_stop)
        circuit_builder.close_circuit(circ_id)




def run_speedtest(args, conf):
    """Initializes all the data and threads needed to measure the relays.

    It launches or connect to Tor in a thread.
    It initializes the list of relays seen in the Tor network.
    It starts a thread to read the previous measurements and wait for new
    measurements to write them to the disk.
    It initializes a class that will be used to order the relays depending
    on their measurements age.
    It initializes the list of destinations that will be used for the
    measurements.
    It initializes the thread pool that will launch the measurement threads.
    The pool starts 3 other threads that are not the measurement (worker)
    threads.
    Finally, it calls the function that will manage the measurement threads.

    """
    global rd, pool, controller

    controller = stem_utils.launch_or_connect_to_tor(conf)
    state = State(conf.getpath('paths', 'state_fname'))
    state['tor_version'] = str(controller.get_version())
    measurements_period = conf.getint('general', 'data_period')
    rl = RelayList(args, conf, controller, measurements_period, state)
    cb = CB(args, conf, controller, rl)
    main_loop(args, conf, controller, rl, cb)
    

def main(args, conf):
    run_speedtest(args, conf)
