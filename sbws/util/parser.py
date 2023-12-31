import sbws.core.cleanup
import sbws.core.scanner
import sbws.core.generate
import sbws.core.stats
import sbws.core.clientbuilder
import sbws.core.scanner_original
from sbws import __version__

from argparse import ArgumentParser, RawTextHelpFormatter
import os


def _default_dot_sbws_dname():
    home = os.path.expanduser('~')
    return os.path.join(home, '.sbws')


def create_parser():
    p = ArgumentParser(formatter_class=RawTextHelpFormatter)
    p.add_argument(
        '--version', action='version', help='sbws version',
        version='{}'.format(__version__))
    p.add_argument('--log-level',
                   choices=['debug', 'info', 'warning', 'error', 'critical'],
                   help='Override the sbws log level')
    p.add_argument('-c', '--config',
                   help='Path to the sbws config file')
    sub = p.add_subparsers(dest='command')
    sbws.core.cleanup.gen_parser(sub)
    sbws.core.scanner.gen_parser(sub)
    sbws.core.generate.gen_parser(sub)
    sbws.core.stats.gen_parser(sub)
    sbws.core.clientbuilder.gen_parser(sub)
    sbws.core.scanner_original.gen_parser(sub)
    return p
