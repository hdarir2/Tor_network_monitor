from math import ceil

from sbws.globals import (fail_hard, SBWS_SCALE_CONSTANT, TORFLOW_SCALING, MLEFLOW_SCALING,
                          SBWS_SCALING, PROBPROG_SCALING, TORFLOW_BW_MARGIN, PROP276_ROUND_DIG,
                          DAY_SECS, NUM_MIN_RESULTS, GENERATE_PERIOD)
from sbws.lib.v3bwfile import V3BWFile
from sbws.lib.resultdump import load_recent_results_in_datadir
from argparse import ArgumentDefaultsHelpFormatter
import os
import logging
from sbws.util.timestamp import now_fname
from sbws.lib import destination
import time
log = logging.getLogger(__name__)


def gen_parser(sub):
    d = 'Generate a v3bw file based on recent results. A v3bw file is the '\
        'file Tor directory authorities want to read and base their '\
        'bandwidth votes on. '\
        'To avoid inconsistent reads, configure tor with '\
        '"V3BandwidthsFile /path/to/latest.v3bw". '\
        '(latest.v3bw is an atomically created symlink in the same '\
        'directory as output.) '\
        'If the file is transferred to another host, it should be written to '\
        'a temporary path, then renamed to the V3BandwidthsFile path.\n'\
        'The default scaling method is torflow\'s one. To use different'\
        'scaling methods or no scaling, see the options.'
    p = sub.add_parser('generate', description=d,
                       formatter_class=ArgumentDefaultsHelpFormatter)
    p.add_argument('--output', default=None, type=str,
                   help='If specified, write the v3bw here instead of what is'
                   'specified in the configuration')
    # The reason for --scale-constant defaulting to 7500 is because at one
    # time, torflow happened to generate output that averaged to 7500 bw units
    # per relay. We wanted the ability to try to be like torflow. See
    # https://lists.torproject.org/pipermail/tor-dev/2018-March/013049.html
    p.add_argument('--scale-constant', default=SBWS_SCALE_CONSTANT, type=int,
                   help='When scaling bw weights, scale them using this const '
                   'multiplied by the number of measured relays')
    p.add_argument('--scale-sbws', action='store_true',
                   help='If specified, do not use bandwidth values as they '
                   'are, but scale them such that we have a budget of '
                   'scale_constant * num_measured_relays = bandwidth to give '
                   'out, and we do so proportionally')
    p.add_argument('-t', '--scale-torflow', action='store_true',
                   default=True,
                   help='If specified, scale measurements using torflow\'s '
                   'method. This option is kept for compatibility with older '
                   'versions and it is silently ignored, since it is the '
                   'default.')
    p.add_argument('-w', '--raw', action='store_true',
                   help='If specified, do use bandwidth raw measurements '
                   'without any scaling.')
    p.add_argument('--scale-probprog', action='store_true',
                   help='If specified, use probabilistic programming algorithm')
    p.add_argument('--scale-mleflow', action='store_true',
                   help='If specified, use mleflow algorithm')
    p.add_argument('-m', '--torflow-bw-margin', default=TORFLOW_BW_MARGIN,
                   type=float,
                   help="Cap maximum bw when scaling as Torflow. ")
    p.add_argument('-r', '--round-digs', '--torflow-round-digs',
                   default=PROP276_ROUND_DIG, type=int,
                   help="Number of most significant digits to round bw.")
    p.add_argument('-p', '--secs-recent', default=None, type=int,
                   help="How many secs in the past are results being "
                        "still considered. Default is {} secs. If not scaling "
                        "as Torflow the default is data_period in the "
                        "configuration.".format(GENERATE_PERIOD))
    p.add_argument('-a', '--secs-away', default=DAY_SECS, type=int,
                   help="How many secs results have to be away from each "
                        "other.")
    p.add_argument('-n', '--min-num', default=NUM_MIN_RESULTS, type=int,
                   help="Mininum number of a results to consider them.")
    return p


def main(args, conf):
    os.makedirs(conf.getpath('paths', 'v3bw_dname'), exist_ok=True)

    datadir = conf.getpath('paths', 'datadir')
    if not os.path.isdir(datadir):
        fail_hard('%s does not exist', datadir)
    if args.scale_constant < 1:
        fail_hard('--scale-constant must be positive')
    if args.torflow_bw_margin < 0:
        fail_hard('toflow-bw-margin must be major than 0.')
    if args.scale_sbws:
        scaling_method = SBWS_SCALING
    elif args.raw:
        scaling_method = None
    elif args.scale_probprog:
        scaling_method = PROBPROG_SCALING
    elif args.scale_mleflow:
        scaling_method = MLEFLOW_SCALING
    else:
        # sbws will scale as torflow until we have a better algorithm for
        # scaling (#XXX)
        scaling_method = TORFLOW_SCALING
    if args.secs_recent:
        fresh_days = ceil(args.secs_recent / 24 / 60 / 60)
    else:
        log.warning('Please specify the window of observation consideration --secs_recent')
        return
    reset_bw_ipv4_changes = conf.getboolean('general', 'reset_bw_ipv4_changes')
    reset_bw_ipv6_changes = conf.getboolean('general', 'reset_bw_ipv6_changes')
    nb_epochs = conf.getint('general', 'number_epochs')
    for k in range(nb_epochs):
        results = load_recent_results_in_datadir(
            fresh_days, datadir,
            on_changed_ipv4=reset_bw_ipv4_changes,
            on_changed_ipv6=reset_bw_ipv6_changes)
        if len(results) < 1:
            log.warning('No recent results, so not generating anything. (Have you '
                    'ran sbws scanner recently?)')
            return
        state_fpath = conf.getpath('paths', 'state_fname')
        consensus_path = os.path.join(conf.getpath('tor', 'datadir'),
                                  "cached-consensus")
        # Accept None as scanner_country to be compatible with older versions.
        scanner_country = conf['scanner'].get('country')
        destinations_countries = destination.parse_destinations_countries(conf)
        bw_file = V3BWFile.from_results(conf, k, results, scanner_country,
                                    destinations_countries, state_fpath,
                                    args.scale_constant, scaling_method,
                                    torflow_cap=args.torflow_bw_margin,
                                    round_digs=args.round_digs,
                                    secs_recent=args.secs_recent,
                                    secs_away=args.secs_away,
                                    min_num=args.min_num,
                                    consensus_path=consensus_path)
        f=open(conf.getpath('paths', 'observation_file'), 'a')
        f.write('End epoch'+'\n')
        f.close()

        if scaling_method != PROBPROG_SCALING:
            output = conf.getpath('paths', 'v3bw_fname').format(k+1)
            bw_file.write(conf, output)
            bw_file.info_stats

        data_period = conf.getint('general', 'data_period')*60
        time.sleep(data_period)
