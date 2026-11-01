"""Read-only command interface, fail-closed exit codes, no secrets in reports."""
from __future__ import annotations
import argparse
import json
import sys

from .capture import capture
from .checks import changes, posture, sarif, text_report, SEVERITIES
from .errors import DriftError, InputError
from .model import canonical, read_snapshot, write_new


def build_parser():
    parser=argparse.ArgumentParser(prog='pg-security-drift',description='PostgreSQL RLS/grant metadata drift review (read-only)')
    parser.add_argument('--version',action='version',version='0.1.0')
    sub=parser.add_subparsers(dest='command',required=True)
    def scopes(p):
        p.add_argument('--schema',action='append',dest='schemas',default=None,
                       help='Schema to review; repeat flag to include multiple schemas. Default: public')
    def report(p):
        scopes(p)
        p.add_argument('--format',choices=['text','json','sarif'],default='text')
        p.add_argument('--output',help='Create new report file without overwriting')
        p.add_argument('--fail-on',choices=['none','low','medium','high','critical'],default='high')
    scan=sub.add_parser('scan',help='Capture catalogs via psql and audit immediately')
    report(scan);scan.add_argument('--psql',default='psql',help='psql executable location')
    snap=sub.add_parser('snapshot',help='Capture read-only catalog metadata into an exclusive JSON baseline')
    snap.add_argument('--output',required=True);snap.add_argument('--psql',default='psql')
    audit=sub.add_parser('audit',help='Audit existing catalog snapshot offline')
    report(audit);audit.add_argument('--input',required=True)
    compare=sub.add_parser('compare',help='Compare two snapshots; fail on NEW or worsened findings only')
    report(compare);compare.add_argument('--baseline',required=True);compare.add_argument('--current',required=True)
    return parser


def _severity_fails(report, level, incremental=False):
    if level=='none':return False
    floor=SEVERITIES[level]
    items=report.get('new',[]) if incremental else report.get('findings',[])
    changed=report.get('changed',[]) if incremental else []
    return any(SEVERITIES[x['severity']]>=floor for x in items) or any(
        SEVERITIES[x['after']['severity']]>=floor and
        SEVERITIES[x['after']['severity']]>SEVERITIES[x['before']['severity']] for x in changed)


def main(argv=None):
    args=build_parser().parse_args(argv)
    try:
        if args.command=='snapshot':
            raw=canonical(capture(args.psql))
            write_new(args.output,raw)
            print('Snapshot exported. Treat metadata as sensitive; protect the baseline independently.')
            return 0
        if args.command=='scan':
            report=posture(capture(args.psql),tuple(args.schemas or ['public']))
        elif args.command=='audit':
            report=posture(read_snapshot(args.input),tuple(args.schemas or ['public']))
        else:
            report=changes(read_snapshot(args.baseline),read_snapshot(args.current),tuple(args.schemas or ['public']))
        result=(json.dumps(sarif(report),sort_keys=True,ensure_ascii=True) if args.format=='sarif'
                else json.dumps(report,sort_keys=True,ensure_ascii=True,indent=2) if args.format=='json'
                else text_report(report))
        if args.output:write_new(args.output,result)
        else:print(result)
        return int(_severity_fails(report,args.fail_on,args.command=='compare'))
    except DriftError:
        print('pg-security-drift: input invalid or audit incomplete; no approval issued.',file=sys.stderr)
        return 2
    except Exception:
        # Include no DSN, driver stderr, SQL body or raw database metadata in error output.
        print('pg-security-drift: unexpected operational error; no approval issued.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
