''' Measure the relays. '''
import queue

import signal
import sys
import threading
import traceback
import uuid
import subprocess
from multiprocessing.context import TimeoutError

from ..lib.circuitbuilder import GapsCircuitBuilder as CB
from ..lib.resultdump import ResultDump
from ..lib.resultdump import (
    ResultSuccess, ResultErrorCircuit, ResultErrorStream,
    ResultErrorSecondRelay,  ResultError, ResultErrorDestination
    )
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

from .. import settings
from ..lib.heartbeat import Heartbeat

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


def timed_recv_from_server(circ_id, cont):
    # start_time = time.time()
    # exit_code=runtgen()
    exit_code=connect_to_destination_over_circuit(circ_id, cont)
    # end_time = time.time()
    if exit_code==0:
        return True
    else:
        return False
    



# def get_random_range_string(content_length, size):
#     '''
#     Return a random range of bytes of length **size**. **content_length** is
#     the size of the file we will be requesting a range of bytes from.

#     For example, for content_length of 100 and size 10, this function will
#     return one of the following: '0-9', '1-10', '2-11', [...] '89-98', '90-99'
#     '''
#     assert size <= content_length
#     # start can be anywhere in the content_length as long as it is **size**
#     # bytes away from the end or more. Because range is [start, end) (doesn't
#     # include the end value), add 1 to the end.
#     start = rng.choice(range(0, content_length - size + 1))
#     # Unlike range, the byte range in an http header is [start, end] (does
#     # include the end value), so we subtract one
#     end = start + size - 1
#     # start and end are indexes, while content_length is a length, therefore,
#     # the largest index end should ever be should be less than the total length
#     # of the content. For example, if content_length is 10, end could be
#     # anywhere from 0 to 9.
#     assert end < content_length
#     return 'bytes={}-{}'.format(start, end)


# def measure_rtt_to_server(session, conf):
#     ''' Make multiple end-to-end RTT measurements by making small HTTP requests
#     over a circuit + stream that should already exist, persist, and not need
#     rebuilding. If something goes wrong and not all of the RTT measurements can
#     be made, return None. Otherwise return a list of the RTTs (in seconds).

#     :returns tuple: results or None if the if the measurement fail.
#         None or exception if the measurement fail.

#     '''
#     rtts = []
    # size = conf.getint('scanner', 'min_download_size')
    # for _ in range(0, conf.getint('scanner', 'num_rtts')):
    #     log.debug('Measuring RTT to %s', dest.url)
    #     # random_range = get_random_range_string(content_length, size)
    #     # success, data = timed_recv_from_server(session, dest, random_range)
    #     if not success:
    #         # data is an exception
    #         log.debug('While measuring the RTT to %s we hit an exception '
    #                   '(does the webserver support Range requests?): %s',
    #                   dest.url, data)
    #         return None, data
    #     assert success
    #     # data is an RTT
    #     assert isinstance(data, float) or isinstance(data, int)
    #     rtts.append(data)
    # return rtts, None


def measure_bandwidth_to_server(conf, circ_id, cont):
    """
    :returns tuple: results or None if the if the measurement fail.
        None or exception if the measurement fail.

    """
    results = []
    success = timed_recv_from_server(circ_id, cont) ##SHOULD BE CHANGED
    if not success:
            # data is an exception
        log.debug('While measuring the bandwidth  we hit an '
                      'exception (tgen not working)')
        return results, None
    assert success
    return results, None


def _pick_ideal_second_hop_relay(relay,  rl, cont, is_exit):
    '''
    Sbws builds two hop circuits. Given the **relay** to measure with
    destination **dest**, pick a second relay that is or is not an exit
    according to **is_exit**.
    '''
    ##NEW
    if is_exit:
        candidates = rl.exits
    else:
        candidates = rl.non_exits
    ##
    # candidates = rl.authorities
    if not len(candidates):
        return None
    # if is_exit:
    #     candidates = [c for c in candidates
    #                   if c.fingerprint != relay.fingerprint]
    min_relay_bw = rl.exit_min_bw() if is_exit else rl.non_exit_min_bw()
    log.debug('Picking a 2nd hop to measure %s from %d choices. is_exit=%s',
              relay.nickname, len(candidates), is_exit)
    for min_bw_factor in [2, 1.75, 1.5, 1.25, 1]:
        min_bw = relay.consensus_bandwidth * min_bw_factor

        if min_bw < min_relay_bw:
            min_bw = min_relay_bw
        new_candidates = stem_utils.only_relays_with_bandwidth(
            cont, candidates, min_bw=min_bw)
        if len(new_candidates) > 0:
            chosen = rng.choice(new_candidates)
            log.debug(
                'Found %d candidate 2nd hops with at least %sx the bandwidth '
                'of %s. Returning %s (bw=%s).',
                len(new_candidates), min_bw_factor, relay.nickname,
                chosen.nickname, chosen.consensus_bandwidth)
            return chosen
    candidates = sorted(candidates, key=lambda r: r.consensus_bandwidth,
                        reverse=True)
    nb_candidates=len(candidates)
    index_cand=random.randint(0, nb_candidates-1)
    chosen = candidates[index_cand]
    # chosen2 = candidates[nb_candidates-1]
    log.debug(
        'Didn\'t find any 2nd hops at least as fast as %s (bw=%s). It\'s '
        'probably really fast. Returning %s (bw=%s), the fastest '
        'candidate we have.', relay.nickname, relay.consensus_bandwidth,
        chosen.nickname, chosen.consensus_bandwidth)
    return chosen

def _pick_ideal_second_hop_authority(relay,  rl, cont, is_exit):
    '''
    Sbws builds two hop circuits. Given the **relay** to measure with
    destination **dest**, pick a second relay that is or is not an exit
    according to **is_exit**.
    '''
    # if relay.nickname =='relay2exitguard':
    #     log.debug(relay.nickname)
    candidates = rl.authorities
    if not len(candidates):
        return None
    # if is_exit:
    #     candidates = [c for c in candidates
    #                   if c.fingerprint != relay.fingerprint]
    min_relay_bw = rl.exit_min_bw() if is_exit else rl.non_exit_min_bw()
    log.debug('Picking a 2nd hop to measure %s from %d choices. is_exit=%s',
              relay.nickname, len(candidates), is_exit)
    for min_bw_factor in [2, 1.75, 1.5, 1.25, 1]:
        min_bw = relay.consensus_bandwidth * min_bw_factor

        if min_bw < min_relay_bw:
            min_bw = min_relay_bw
        new_candidates = stem_utils.only_relays_with_bandwidth(
            cont, candidates, min_bw=min_bw)
        if len(new_candidates) > 0:
            chosen = rng.choice(new_candidates)
            log.debug(
                'Found %d candidate 2nd hops with at least %sx the bandwidth '
                'of %s. Returning %s (bw=%s).',
                len(new_candidates), min_bw_factor, relay.nickname,
                chosen.nickname, chosen.consensus_bandwidth)
            return chosen
    candidates = sorted(candidates, key=lambda r: r.consensus_bandwidth,
                        reverse=True)
    # nb_candidates=len(candidates)
    # index_cand=random.randint(0, nb_candidates-1)
    
    ###CHOSING AN AUTHORITY OF CHOICE:
    # for c in candidates:
    #     if c.nickname == '4uthority2':
    #         chosen = c
    ########

    ###CHOOSING AN AUTHORITY FOR EACH TYPE OF RELAYS:
    r = relay.nickname
    if r.find('exit')!=-1:
        for c in candidates:
            if c.nickname == '4uthority3':
                chosen = c
    else:
        if r.find('guard')!=-1:
            for c in candidates:
                if c.nickname == '4uthority1':
                    chosen = c
        else:
            for c in candidates:
                if c.nickname == '4uthority2':
                    chosen = c

    
    # if relay in rl.exits:
    #     for c in candidates:
    #         if c.nickname == '4uthority3':
    #             chosen = c
    # else:
    #     if relay in rl.guards:
    #         for c in candidates:
    #             if c.nickname == '4uthority1':
    #                 chosen = c
    #     else:
    #         for c in candidates:
    #             if c.nickname == '4uthority2':
    #                 chosen = c
    ####

    # index_cand=1
    # chosen = candidates[index_cand]
    log.debug('chosen %s', chosen.nickname)
    # chosen2 = candidates[nb_candidates-1]
    log.debug(
        'Didn\'t find any 2nd hops at least as fast as %s (bw=%s). It\'s '
        'probably really fast. Returning %s (bw=%s), the fastest '
        'candidate we have.', relay.nickname, relay.consensus_bandwidth,
        chosen.nickname, chosen.consensus_bandwidth)
    return chosen

def _pick_ideal_second_hop_relay2exit(relay,  rl, cont, is_exit):
    candidates = rl.exits
    for i in range(len(candidates)):
        if str(candidates[i].nickname)=='relay2exitguard':
            log.debug('Found it')
            # chosen =ch
            return candidates[i]
        log.debug(candidates[i].nickname)
    log.debug('NONE')
    # return chosen


def error_no_helper(relay,  our_nick=""):
    reason = 'Unable to select a second relay'
    log.debug(reason + ' to help measure %s (%s)',
              relay.fingerprint, relay.nickname)
    return [
        ResultErrorSecondRelay(relay, [], 'tgen server', our_nick,
                               msg=reason),
        ]


def create_path_relay(relay, rl, cb, relay_as_entry=True):
    ##RELAY AS AUTHORITY
    # if relay.nickname == 'relay2exitguard':
    #     helper1=_pick_ideal_second_hop_authority(
    #         relay, rl, cb.controller, is_exit=relay_as_entry)
    # else:
    #     helper1 = _pick_ideal_second_hop_relay2exit(
    #         relay, rl, cb.controller, is_exit=relay_as_entry)
    #######
    ##OTHER RELAYS PROBER
    # helper1 = _pick_ideal_second_hop(relay, rl, cb.controller, is_exit=relay_as_entry)
    ###########
    ##AUTHORITIES PROBERS
    helper1 = _pick_ideal_second_hop_authority(relay, rl, cb.controller, is_exit=relay_as_entry)
    ######

    ##RELAY ITSELF:
    # circ_fps = [relay.fingerprint]
    # nicknames = [relay.nickname]
    # exit_policy = relay.exit_policy
    #######


    # helper2 = _pick_ideal_second_hop(
    #         relay, rl, cb.controller, is_exit=relay_as_entry)
    # while helper2.nickname == helper1.nickname:
    #     helper2 = _pick_ideal_second_hop(
    #         relay, rl, cb.controller, is_exit=relay_as_entry)
    # log.debug(helper2.nickname)
    # if not helper:
    #     return error_no_helper(relay)
    
    # if relay_as_entry:
    #     circ_fps = [relay.fingerprint, helper1.fingerprint]
    #     nicknames = [relay.nickname, helper1.nickname]
    #     exit_policy = helper1.exit_policy
    # else:
    #     circ_fps = [helper1.fingerprint, relay.fingerprint]
    #     nicknames = [helper1.nickname, relay.nickname]
    #     exit_policy = relay.exit_policy

    circ_fps = [relay.fingerprint, helper1.fingerprint]
    nicknames = [relay.nickname, helper1.nickname]
    exit_policy = helper1.exit_policy

    # circ_fps = [relay.fingerprint, helper1.fingerprint, helper2.fingerprint]
    # nicknames = [relay.nickname, helper1.nickname, helper2.nickname]
    # exit_policy = helper1.exit_policy

    # circ_fps = [relay.fingerprint]
    # nicknames = [relay.nickname]
    # exit_policy = relay.exit_policy
    return circ_fps, nicknames, exit_policy


def error_no_circuit(circ_fps, nicknames, reason, relay,  our_nick):
    log.debug('Could not build circuit with path %s (%s): %s ',
              circ_fps, nicknames, reason)
    return [
        ResultErrorCircuit(relay, circ_fps, 'tgen server', our_nick,
                           msg=reason),
    ]


def measure_relay(args, conf, cb, rl, relay):
    """
    Select a Web server, a relay to build the circuit,
    build the circuit and measure the bandwidth of the given relay.

    :return Result: a measurement Result object

    """
    ##IF I AM WORKING ON 1 RELAY:
    if relay.nickname == 'relay2exitguard' or relay.nickname== 'relay5guard' or relay.nickname=='relay6guard':
        return 0
    if  relay.nickname=='relay3exit':
        return 0
    #####

    log.debug('Measuring %s %s', relay.nickname, relay.fingerprint)
    our_nick = conf['scanner']['nickname']
 
    built_circuits=find_circuit_built()
    for k in built_circuits:
        cb.close_circuit(k)
        log.debug("Closing circuit %s", k)
    
    ##NEW
    if relay in rl.exits:
        r = create_path_relay(relay, rl, cb, relay_as_entry=False)
    else:
        r = create_path_relay(relay, rl, cb)
    ##
    # r = create_path_relay(relay, rl, cb)

    if len(r) == 1:
        return r
    circ_fps, nicknames, exit_policy = r

    # Build the circuit
    circ_id, reason = cb.build_circuit(circ_fps)

    if not circ_id:
        return error_no_circuit(circ_fps, nicknames, reason, relay,
                                our_nick)
    log.debug('Built circuit with path %s (%s) to measure %s (%s)',
              circ_fps, nicknames, relay.fingerprint, relay.nickname)

    # SECOND: measure bandwidth
    bw_results, reason = measure_bandwidth_to_server(
        conf, circ_id, cb.controller)
    
    cb.close_circuit(circ_id)
    # Finally: store result
    log.debug('Success measurement for %s (%s) via circuit %s (%s) ',
              relay.fingerprint, relay.nickname, circ_fps, nicknames)
    return 0


def dispatch_worker_thread(*a, **kw):
    return measure_relay(*a, **kw)


def _should_keep_result(did_request_maximum, result_time, download_times):
    # In the normal case, we didn't ask for the maximum allowed amount. So we
    # should only allow ourselves to keep results that are between the min and
    # max allowed time
    msg = "Keeping measurement time {:.2f}".format(result_time)
    if not did_request_maximum and \
            result_time >= download_times['min'] and \
            result_time < download_times['max']:
        log.debug(msg)
        return True
    # If we did request the maximum amount, we should keep the result as long
    # as it took less than the maximum amount of time
    if did_request_maximum and \
            result_time < download_times['max']:
        log.debug(msg)
        return True
    # In all other cases, return false
    log.debug('Not keeping result time %f.%s', result_time,
              '' if not did_request_maximum else ' We requested the maximum '
              'amount allowed.')
    return False


def _next_expected_amount(expected_amount, result_time, download_times,
                          min_dl, max_dl):
    if result_time < download_times['toofast']:
        # Way too fast, greatly increase the amount we ask for
        expected_amount = int(expected_amount * 5)
    elif result_time < download_times['min'] or \
            result_time >= download_times['max']:
        # As long as the result is between min/max, keep the expected amount
        # the same. Otherwise, adjust so we are aiming for the target amount.
        expected_amount = int(
            expected_amount * download_times['target'] / result_time)
    # Make sure we don't request too much or too little
    expected_amount = max(min_dl, expected_amount)
    expected_amount = min(max_dl, expected_amount)
    return expected_amount


def result_putter(result_dump):
    ''' Create a function that takes a single argument -- the measurement
    result -- and return that function so it can be used by someone else '''

    def closure(measurement_result):
        log.debug("Logged result in tgen.stdout")
    return closure


def result_putter_error(target):
    ''' Create a function that takes a single argument -- an error from a
    measurement -- and return that function so it can be used by someone else
    '''
    def closure(object):
        log.warning("".join(traceback.format_exception(
            type(object), object, object.__traceback__))
            )
    return closure


def main_loop(args, conf, controller, relay_list, circuit_builder, result_dump,
              relay_prioritizer, destinations, pool):
    """Starts and reuse the threads that measure the relays forever.

    It starts a loop that will be run while there is not and event signaling
    that sbws is stopping.
    """
    log.info("Started the main loop to measure the relays.")
    hbeat = Heartbeat(conf.getpath('paths', 'state_fname'))

    # Set the time to wait for a thread to finish as the half of an HTTP
    # request timeout.
    # Do not start a new loop if sbws is stopping.
    while not settings.end_event.is_set():
        log.debug("Starting a new measurement loop.")
        num_relays = 0
        # Since loop might finish before pending_results is 0 due waiting too
        # long, set it here and not outside the loop.
        # pending_results = []
        loop_tstart = time.time()

        # Register relay fingerprints to the heartbeat module
        hbeat.register_consensus_fprs(relay_list.relays_fingerprints)
        num_relays_to_measure = len(relay_list.notauthorities)
        for target in relay_prioritizer.best_priority():
            log.info("Pending measurements: %s out of %s: ", num_relays_to_measure-num_relays, num_relays_to_measure)
            target.increment_relay_recent_measurement_attempt()
            num_relays += 1
            measure_relay(args, conf, circuit_builder, relay_list, target)
            # else:
            #     log.info('%s do not want to measure this relay')
            
        #     # callback and callback_err must be non-blocking
        #     callback = result_putter(result_dump)
        #     callback_err = result_putter_error(target)
        #     r = pool.apply_async(
        #         dispatch_worker_thread,
        #         [args, conf, circuit_builder, relay_list,
        #          target], {}, callback, callback_err)
        #     # pending_results.append(async_result)

        #     # Register this measurement to the heartbeat module
        #     hbeat.register_measured_fpr(target.fingerprint)
        
        # num_relays_to_measure = relay_list.nb_relays() ##TO CHANGE LATER (INCLUDE IN CONFIG)
        # pending_results = [r for r in pending_results if not r.ready()]
        # for i in range(num_relays_to_measure):
        #     log.info("Pending measurements: %s out of %s: ", num_relays_to_measure-i, num_relays_to_measure)
        #     time.sleep(20)
            # pending_results = [r for r in pending_results if not r.ready()]

        # wait_for_results(num_relays_to_measure, pending_results)
        log.debug("exited wait for result")
        # Print the heartbeat message
        hbeat.print_heartbeat_message()

        loop_tstop = time.time()
        loop_tdelta = (loop_tstop - loop_tstart) / 60
        log.debug("Attempted to measure %s relays in %s minutes",
                  num_relays, loop_tdelta)


def wait_for_results(num_relays_to_measure, pending_results):
    """Wait for the pool to finish and log progress.

    While there are relays being measured, just log the progress
    and sleep :const:`~sbws.globals.TIMEOUT_MEASUREMENTS` (3mins),
    which is aproximately the time it can take to measure a relay in
    the worst case.

    When there has not been any relay measured in ``TIMEOUT_MEASUREMENTS``
    and there are still relays pending to be measured, it means there is no
    progress and call :func:`~sbws.core.scanner.force_get_results`.

    This can happen in the case of a bug that makes either
    :func:`~sbws.core.scanner.measure_relay`,
    :func:`~sbws.core.scanner.result_putter` (callback) and/or
    :func:`~sbws.core.scanner.result_putter_error` (callback error) stall.

    .. note:: in a future refactor, this could be simpler by:

      1. Initializing the pool at the begingging of each loop
      2. Callling :meth:`~Pool.close`; :meth:`~Pool.join` after
         :meth:`~Pool.apply_async`,
         to ensure no new jobs are added until the pool has finished with all
         the ones in the queue.

      As currently, there would be still two cases when the pool could stall:

      1. There's an exception in ``measure_relay`` and another in
         ``callback_err``
      2. There's an exception ``callback``.

      This could also be simpler by not having callback and callback error in
      ``apply_async`` and instead just calling callback with the
      ``pending_results``.

      (callback could be also simpler by not having a thread and queue and
      just storing to disk, since the time to write to disk is way smaller
      than the time to request over the network.)
    """
    # num_last_measured = 1
    pending_results = [r for r in pending_results if not r.ready()]

    while len(pending_results) > 0:
        log.info("Pending measurements: %s out of %s: ",
                 len(pending_results), num_relays_to_measure)
        time.sleep(20)
        # old_pending_results = pending_results
        pending_results = [r for r in pending_results if not r.ready()]
        # num_last_measured = len(old_pending_results) - len(pending_results)
    # if len(pending_results) > 0:
    #     force_get_results(pending_results)
    if len(pending_results)==0:
        return 0


def force_get_results(pending_results):
    """Try to get either the result or an exception, which gets logged.

    It is call by :func:`~sbws.core.scanner.wait_for_results` when
    the time waiting for the results was long.

    To get either the :class:`~sbws.lib.resultdump.Result` or an exception,
    call :meth:`~AsyncResult.get` with timeout.
    Timeout is low since we already waited.

    ``get`` is not call before, because it blocks and the callbacks
    are not call.
    """
    log.debug("Forcing get")
    for r in pending_results:
        try:
            result = r.get(timeout=20)
            log.warning("Result %s was not stored, it took too long.",
                        result)
        # TimeoutError is raised when the result is not ready, ie. has not
        # been processed yet
        except TimeoutError:
            log.warning("A result was not stored, it was not ready.")
        # If the result raised an exception, `get` returns it,
        # then log any exception so that it can be fixed.
        # This should not happen, since `callback_err` would have been call
        # first.
        except Exception as e:
            log.critical(FILLUP_TICKET_MSG)
            # If the exception happened in the threads, `log.exception` does
            # not have the traceback.
            # Using `format_exception` instead of of `print_exception` to show
            # the traceback in all the log handlers.
            log.warning("".join(traceback.format_exception(
                        type(e), e, e.__traceback__)))


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

    # When there will be a refactor where conf is global, this can be removed
    # from here.
    state = State(conf.getpath('paths', 'state_fname'))
    # XXX: tech-debt: create new function to obtain the controller and to
    # write the state, so that a unit test to check the state tor version can
    # be created
    # Store tor version whenever the scanner starts.
    state['tor_version'] = str(controller.get_version())
    # Call only once to initialize http_headers
    settings.init_http_headers(conf.get('scanner', 'nickname'), state['uuid'],
                               state['tor_version'])
    # To do not have to pass args and conf to RelayList, pass an extra
    # argument with the data_period
    measurements_period = conf.getint('general', 'data_period')
    # measurements_period = 10*60
    rl = RelayList(args, conf, controller, measurements_period, state)
    cb = CB(args, conf, controller, rl)
    rd = ResultDump(args, conf)
    rp = RelayPrioritizer(args, conf, rl, rd)
    destinations, error_msg = DestinationList.from_config(
        conf, cb, rl, controller)
    if not destinations:
        fail_hard(error_msg)
    max_pending_results = conf.getint('scanner', 'measurement_threads')
    pool = Pool(max_pending_results)
    try:
        main_loop(args, conf, controller, rl, cb, rd, rp, destinations, pool)
    except KeyboardInterrupt:
        log.info("Interrupted by the user.")
        stop_threads(signal.SIGINT, None)
    # Any exception not catched at this point would make the scanner stall.
    # Log it and exit gracefully.
    except Exception as e:
        log.critical(FILLUP_TICKET_MSG)
        log.exception(e)
        stop_threads(signal.SIGTERM, None, 1)


def gen_parser(sub):
    d = 'The scanner side of sbws. This should be run on a well-connected '\
        'machine on the Internet with a healthy amount of spare bandwidth. '\
        'This continuously builds circuits, measures relays, and dumps '\
        'results into a datadir, commonly found in ~/.sbws'
    sub.add_parser('scanner', formatter_class=ArgumentDefaultsHelpFormatter,
                   description=d)


def main(args, conf):
    if conf.getint('scanner', 'measurement_threads') < 1:
        fail_hard('Number of measurement threads must be larger than 1')

    min_dl = conf.getint('scanner', 'min_download_size')
    max_dl = conf.getint('scanner', 'max_download_size')
    if max_dl < min_dl:
        fail_hard('Max download size %d cannot be smaller than min %d',
                  max_dl, min_dl)

    os.makedirs(conf.getpath('paths', 'datadir'), exist_ok=True)

    state = State(conf.getpath('paths', 'state_fname'))
    state['scanner_started'] = now_isodt_str()
    # Generate an unique identifier for each scanner
    if 'uuid' not in state:
        state['uuid'] = str(uuid.uuid4())

    run_speedtest(args, conf)
