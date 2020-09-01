#!/usr/bin/python2.7
"""Kick Virtual Ass.

Usage:
  capx sum [-f <filter>] [-d <display-filter>] [-t] [--add-column <column>]... 
              [-w <new-path>] <cap-file>...
  capx [-f <filter>] [-q | [-d <display-filter>] [-t] [--add-column <column>]...] 
          [-w <new-path>] <cap-file>...

Options:
  -f <filter>            filter caps with a bpf filter
  -d <display-filter>    filter shown packets using wireshark display filter syntax
  -t                     show column titles
  -w <new-path>          save merged and filtered cap to <new_path>
  -q                     do not print packet table on screen
  --add-column <column>  add a column to the displayed table, 
                         using tshark's column names.
"""
# TODO: *Maybe* add --remove-column ?
# TODO: *Maybe* add --order-by ?
# TODO: add --unify-cols
#       for example: make ip.dst and arp.dst.proto_ipv4 the same column

#===============================================================================

from docopt import docopt
from glob import glob
import os
import pandas as pd
import random
import string
from StringIO import StringIO
from subprocess import call, Popen, PIPE

#===============================================================================

# see all possible categories and columns:
# https://www.wireshark.org/docs/dfref/
COLUMNS = ['eth.src','eth.dst','ip.src','arp.src.proto_ipv4','ip.dst','arp.dst.proto_ipv4','frame.protocols','_ws.col.Protocol','tcp.srcport','udp.srcport','tcp.dstport','udp.dstport','frame.time','_ws.col.Info']
TSHARK_OPTIONS = ['-n']

#===============================================================================

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class Cap(object):
    #___________________________________________________________________________
    def __init__(self, original_path, display_filter=None):
        self.original_path = original_path
        self.path = self.original_path
        self.display_filter = display_filter

    #___________________________________________________________________________
    def __str__(self, columns=COLUMNS, display_filter=None, tshark_options=TSHARK_OPTIONS, tshark_extra_options=[]):
        column_args = []
        for column in columns:
            column_args.append('-e')
            column_args.append(column)
        tshark_cmd = 'tshark -T fields'.split()
        tshark_cmd.extend(column_args)
        if display_filter is None:
            display_filter = self.display_filter
        if display_filter is not None:
            tshark_cmd.extend(['-Y', display_filter])
        tshark_cmd.extend(tshark_options)
        tshark_cmd.extend(tshark_extra_options)
        tshark_cmd.extend(['-r', self.path])
        p = Popen(tshark_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        return out

    #___________________________________________________________________________
    def bpf_filter(self, bpf, new_path):
        call(['tcpdump', '-r', self.path, '-w', new_path, bpf])
        self.filtered_path = new_path
        self.path = self.filtered_path

    #___________________________________________________________________________
    def get_DataFrame(self, columns=COLUMNS, display_filter=None, tshark_options=TSHARK_OPTIONS, tshark_extra_options=[]):
        tshark_extra_options.extend(['-E', 'header=y'])
        textio = StringIO(self.__str__(columns=columns, display_filter=display_filter or self.display_filter, tshark_options=tshark_options, tshark_extra_options=tshark_extra_options))
        return pd.read_table(textio, parse_dates=['frame.time']).fillna('')


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class UnifiedCap(Cap):
    #___________________________________________________________________________
    def __init__(self, cap_pathes, new_path, display_filter=None):
        """
        cap_pathes: a list of pathes or globes
        """
        self.original_paths=cap_pathes
        merge_cmd = ['mergecap', '-w', new_path]
        merge_cmd.extend(cap_pathes)
        call(merge_cmd)
        self.path = new_path
        self.display_filter = display_filter


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class CapsGroup(object):
    #___________________________________________________________________________
    def __init__(self, cap_pathes, display_filter=None):
        self.display_filter=display_filter
        caps=[Cap(path, display_filter=display_filter) for path in cap_pathes]
        self.caps = caps

    #___________________________________________________________________________
    def __str__(self, columns=COLUMNS, display_filter=None, tshark_options=TSHARK_OPTIONS, tshark_extra_options=[]):
        for cap in self.caps:
            # should I maybe run cap.__str__(...) and pass on all arguments?
            print cap

    #___________________________________________________________________________
    def get_DataFrame(self, columns=COLUMNS, display_filter=None, tshark_options=TSHARK_OPTIONS, tshark_extra_options=[]):
        dfs = [cap.get_DataFrame(coluns=columns, display_filter=display_filter or self.display_filter, tshark_options=tshark_options, tshark_extra_options=tshark_extra_options) for cap in self.caps]
        return pd.concat(dfs)


#===============================================================================

#_______________________________________________________________________________
def sum_df(df, group_by_cols=COLUMNS[:11]):
    f = {'frame.time': ['min', 'max', 'count']}
    gb = df.groupby(group_by_cols)
    new_df = gb.agg(f).reset_index()
    new_df.columns = [' '.join(col).strip() for col in new_df.columns.values]
    new_df.rename(columns = {'frame.time min':'min_time', 'frame.time max':'max_tim', 'frame.time count': 'count'}, inplace = True)
    # drop empty columns
    for col in new_df.columns:
        u = new_df[col].unique()
        if len(u) == 1 and u[0] == '':
            new_df.drop(col,inplace=True,axis=1)
    return new_df

#_______________________________________________________________________________
def globalisation(globs):
    all_files = []
    for g in globs:
        all_files.extend(glob(g))
    return all_files

#_______________________________________________________________________________
def filename_suffix_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

#_______________________________________________________________________________
def get_temp_path(tempdir='/tmp/'):
    filename = 'capxcap%s.pcap'
    fullpath = os.path.join(tempdir, filename)
    suffix = filename_suffix_generator()
    while os.path.exists(fullpath %suffix):
        suffix = filename_suffix_generator()
    return fullpath %suffix


#_______________________________________________________________________________
def main():
    args = docopt(__doc__, version='0.0')
    files = globalisation(args['<cap-file>'])
    if args['-f']:
        temp_path = get_temp_path()
        cap = UnifiedCap(files, temp_path, args['-d'])
        final_path = args['-w'] or get_temp_path()
        cap.bpf_filter(args['-f'], final_path)
    else:
        final_path = args['-w'] or get_temp_path()
        cap = UnifiedCap(files, final_path, args['-d'])
    if args['-q']:
        return
    cols = COLUMNS
    cols.extend(args['--add-column'])
    if args['sum']:
        df = cap.get_DataFrame(cols, args['-d'])
        sumed = sum_df(df)
        print sumed.to_csv(sep='\t', header=args['-t'], index=False)
        return
    if args['-t']:
        print cap.__str__(tshark_extra_options='-E header=y'.split())
    else:
        print cap
    return
        

#===============================================================================

if __name__ == '__main__':
    main()


#=====================================END=======================================
