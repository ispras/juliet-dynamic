#!/usr/bin/python3
# This program is under the terms of the Apache License 2.0.

import os
from subprocess import Popen, PIPE, TimeoutExpired, STDOUT, DEVNULL
import multiprocessing as mp
from enum import Enum
from argparse import ArgumentParser
import json
import shutil
import signal
import glob

parser = ArgumentParser()
parser.add_argument('-c', '--cwe', default='all',
        metavar='CWE_NUM_1 CWE_NUM_2 ...', help='Run specified CWE.', nargs='*')
parser.add_argument('-t', '--tool', dest='tool', type=str, default='sydr',
        help='Tool name.')
parser.add_argument('-e', '--error', action='store_true',
        default=False,
        help='Print false positive and false negative tests.')
parser.add_argument('-d', '--delete', dest='delete', action='store_true',
        default=False, help='Delete results and collect them again.')
parser.add_argument('-r', '--reproduce', dest='reproduce', action='store_true',
        default=False,
        help='Recalculate statistics and reproduce sanitizers verification.')
parser.add_argument('-j', dest='threads', type=int, default=1,
        help='Set number of threads.')
options = parser.parse_args()

class CWE(Enum):
    ALL = 0
    CWE121 = 1
    CWE122 = 2
    CWE124 = 3
    CWE126 = 4
    CWE127 = 5
    CWE190 = 6
    CWE191 = 7
    CWE194 = 8
    CWE195 = 9
    CWE197 = 10
    CWE369 = 11
    CWE680 = 12

full_names = {
        "CWE121" : "Stack Based Buffer Overflow",
        "CWE122" : "Heap Based Buffer Overflow",
        "CWE124" : "Buffer Underwrite",
        "CWE126" : "Buffer Overread",
        "CWE127" : "Buffer Underread",
        "CWE190" : "Integer Overflow",
        "CWE191" : "Integer Underflow",
        "CWE194" : "Unexpected Sign Extension",
        "CWE195" : "Signed to Unsigned Conversion Error",
        "CWE197" : "Numeric Truncation Error",
        "CWE369" : "Divide by Zero",
        "CWE680" : "Integer Overflow to Buffer Overflow"
}

def TPR(tp, fn):
    return tp / (tp + fn) * 100

def TNR(tn, fp):
    return tn / (tn + fp) * 100

def ACC(tp, tn, fp, fn):
    return (tp + tn) / (tp + tn + fp + fn) * 100

def get_input(bin):
    if 'CWE194' in bin:
        return 'inputs/short_input'
    elif 'CWE197' in bin:
        return 'inputs/int_input'
    elif 'Underflow' in bin and 'unsigned' not in bin:
        if 'int64_t' in bin:
            return 'inputs/sign_int64_t_input'
        elif 'char' in bin:
            return 'inputs/sign_char_input'
        else:
            return 'inputs/sign_int_input'
    elif 'float' in bin:
        return 'inputs/float_input'
    elif 'char' in bin:
        return 'inputs/char_input'
    elif 'int64_t' in bin:
        return 'inputs/int64_t_input'
    else:
        return 'inputs/int_input'

def get_cases(dir):
    cases = []
    stats = {}
    if os.path.exists('results/stats.json'):
        with open('results/stats.json', 'r') as json_file:
            stats = json.load(json_file)
    for root, subdirictories, files in os.walk(dir):
        files.sort()
        files = [f for f in files if 'san' not in f]
        # filter out all random testcases.
        files = [f for f in files if '_12' not in f]
        # grab files only with symbolic input
        files = [f for f in files if 'fscanf' in f or 'fgets' in f]
        if '64' in dir:
            files = [f for f in files if 'CWE680' not in f]

        if 'all' not in options.cwe:
            new_files = []
            for c in options.cwe:
                new_files += [f for f in files if ('CWE' + c) in f]
            files = new_files

        cwe = CWE.ALL
        for bin in files:
            path = os.path.join(root, bin)
            if path in stats:
                continue
            for i in range(1, len(CWE)):
                if CWE(i).name in bin:
                    cwe = CWE(i)
                    break
            input = get_input(bin)
            cases += [(path, cwe, input)]
    return cases

def run_sydr(path, cwe, input):
    """Run Sydr.

    Parameters
    ----------
    path : str
        Path to Juliet test case binary.
    cwe : CWE
        CWE enum for this test case.
    input : str
        Path to file containing stdin for this test case.

    Returns
    -------
    :obj:`list` of :obj:`str`
        List of generated inputs that may trigger an error.

    """
    sec_predicate = {
            "CWE121" : "bounds",
            "CWE122" : "bounds",
            "CWE124" : "bounds",
            "CWE126" : "bounds",
            "CWE127" : "bounds",
            "CWE190" : "intoverflow-func",
            "CWE191" : "intoverflow-func",
            "CWE194" : "bounds",
            "CWE195" : "bounds",
            "CWE197" : "trunc",
            "CWE369" : "zerodiv",
            "CWE680" : "intoverflow-func"
    }

    out_path = path.replace('bin/', 'results/')
    args = ['sydr/sydr', '-o', out_path, '--security', sec_predicate[cwe.name],
            '--no-invert', '--solving-timeout', '60', '--sym-stdin', '--', path]

    if not os.path.exists(out_path):
        with open(input) as stdin:
            proc = Popen(args, stdout=PIPE, stderr=PIPE, stdin=stdin)
            try:
                out, err = proc.communicate(timeout=300)
            except TimeoutExpired:
                proc.terminate()
                out, err = proc.communicate()

    inputs = []
    with open(os.path.join(out_path, 'sydr.log')) as log:
        for line in log:
            if 'Found new input' in line:
                input_path = os.path.join(line[line.find('"') + 1 : line.rfind('"')], 'stdin')
                inputs.append(input_path)
    return inputs

def check_case(case):
    proc = None

    def handle(signum, frame):
        if proc:
            proc.terminate()
        exit(1)

    signal.signal(signal.SIGTERM, handle)

    path, cwe, input = case
    run_tool = globals().get('run_' + options.tool)
    inputs = run_tool(path, cwe, input)

    positive = True if path.endswith('bad') else False
    res = 'FN' if positive else 'TN'
    if inputs:
        res = 'TP' if positive else 'FP'

    san_check = res
    if res == 'TP':
        san_check = 'FN'
        san_path = path + '_san'
        for input_path in inputs:
            with open(input_path) as stdin:
                proc = Popen(san_path, stdout=PIPE, stderr=PIPE, stdin=stdin)
                try:
                    out, err = proc.communicate(timeout=30)
                except TimeoutExpired:
                    proc.terminate()
                    out, err = proc.communicate()
            if b'AddressSanitizer' in err or b'UndefinedBehaviorSanitizer' in err:
                san_check = 'TP'
                break

    return path, res, san_check

def print_results(name, pos, neg, res, res_san):
    tpr_w = TPR(res['TP'], res['FN'])
    acc_w = ACC(res['TP'], res['TN'], res['FP'], res['FN'])
    tpr_s = TPR(res_san['TP'], res_san['FN'])
    acc_s = ACC(res_san['TP'], res['TN'], res['FP'], res_san['FN'])
    tnr = TNR(res['TN'], res['FP'])

    c = max(len(k) + len(v) + 6 for k, v in full_names.items())
    print("=" * c)
    if name == "ALL":
        print("| TOTAL" + " " * (c - 8) + "|")
    else:
        cnt = len(name) + len(full_names[name])
        print('| {}: {}'.format(name, full_names[name]) + " " * (c - cnt - 5) + "|")
    print("=" * c)
    print()
    print("Positive cases: {:>12}".format(pos))
    print("Negative cases: {:>12}".format(neg))
    print()
    print("True Positive:  {:>12}".format(res['TP']))
    print("False Positive: {:>12}".format(res['FP']))
    print("False Negative: {:>12}".format(res['FN']))
    print("True Negative:  {:>12}".format(res['TN']))
    print()
    print("TPR:            {:>12}".format(str(f"{tpr_w:.{2}f}%")))
    print("TNR:            {:>12}".format(str(f"{tnr:.{2}f}%")))
    print("ACC:            {:>12}".format(str(f"{acc_w:.{2}f}%")))
    print()
    print("Sanitizers verification")
    print()
    print("True Positive:  {:>12}".format(res_san['TP']))
    print("False Positive: {:>12}".format(res['FP']))
    print("False Negative: {:>12}".format(res_san['FN']))
    print("True Negative:  {:>12}".format(res['TN']))
    print()
    print("TPR:            {:>12}".format(str(f"{tpr_s:.{2}f}%")))
    print("TNR:            {:>12}".format(str(f"{tnr:.{2}f}%")))
    print("ACC:            {:>12}".format(str(f"{acc_s:.{2}f}%")))

def collect_results():
    stats = {}
    if os.path.exists('results/stats.json'):
        with open('results/stats.json', 'r') as json_file:
            stats = json.load(json_file)
    for i in range(0, len(CWE)):
        cwe_num = CWE(i).name[CWE(i).name.find('E') + 1:]
        if 'all' not in options.cwe and cwe_num not in options.cwe:
            continue
        if not options.error:
            pos = 0
            neg = 0
            tp_s = 0
            fn_s = 0
            res = {
                'TP' : 0,
                'FP' : 0,
                'FN' : 0,
                'TN' : 0
            }
            res_san = {
                'TP' : 0,
                'FN' : 0
            }
            has_stats = False
            for key in stats:
                if CWE(i).name == 'ALL' or CWE(i).name in key:
                    has_stats = True
                    if key.endswith('bad'):
                        pos += 1
                    else:
                        neg += 1
                    res[stats[key]['class']] += 1
                    if stats[key]['class'] == 'TP' or stats[key]['class'] == 'FN':
                        res_san[stats[key]['san_check']] += 1

            if has_stats:
                print_results(CWE(i).name, pos, neg, res, res_san)
        else:
            if CWE(i).name == 'ALL':
                continue
            c = max(len(k) for k in stats)
            print("=" * c)
            cnt = len(CWE(i).name) + len(full_names[CWE(i).name])
            print('| {}: {}'.format(CWE(i).name, full_names[CWE(i).name]) + " " * (c - cnt - 5) + "|")
            print("=" * c)
            for key in stats:
                if CWE(i).name in key:
                    if stats[key]['class'] == 'TN' or stats[key]['san_check'] == 'TP':
                        continue
                    stat = stats[key]
                    print("{}".format(key))
                    if stat['class'] == 'TP' and stat['class'] != stat['san_check']:
                        print("{} (after sanitizers verification)".format(stat['san_check']))
                    else:
                        print("{}".format(stat['class']))
                    print()
        if i != len(CWE) - 1:
            print()

def main():
    tool = 'run_' + options.tool
    run_tool = globals().get(tool)
    if not run_tool:
        raise NotImplementedError("Function %s not implemented" % tool)

    if options.delete:
        stats = {}
        if os.path.exists('results/stats.json'):
            with open('results/stats.json', 'r') as json_file:
                stats = json.load(json_file)
            if 'all' in options.cwe:
                stats.clear()
                shutil.rmtree('results/')
            else:
                for c in options.cwe:
                    delete = []
                    cwe = 'CWE' + str(c)
                    for key in stats:
                        if cwe in key:
                            delete.append(key)
                    dirs = glob.glob('results/bin32/' + cwe + '*')
                    dirs += glob.glob('results/bin64/' + cwe + '*')
                    for dir in dirs:
                        shutil.rmtree(dir)
                    for key in delete:
                        stats.pop(key)
                for root, subdirs, files in os.walk('results/'):
                    for subdir in subdirs:
                        if len(os.listdir(os.path.join(root, subdir))) == 0:
                            shutil.rmtree(os.path.join(root, subdir))
                files = os.listdir('results/')
                if len(files) == 1 and files[0] == 'stats.json':
                    shutil.rmtree('results/')
                if os.path.exists('results/'):
                    with open('results/stats.json', 'w') as json_file:
                        json.dump(stats, json_file)

    if options.reproduce and os.path.exists('results/stats.json'):
        os.remove('results/stats.json')

    cases = get_cases('bin/bin32/')
    cases += get_cases('bin/bin64/')
    size = len(cases)
    stats = {}
    if os.path.exists('results/stats.json'):
        with open('results/stats.json', 'r') as json_file:
            stats = json.load(json_file)
    pool = mp.Pool(options.threads)

    def handle(signum, frame):
        pool.terminate()
        exit(1)

    signal.signal(signal.SIGTERM, handle)

    current = 0
    try:
        for path, res, san_check in pool.imap_unordered(check_case, cases):
            if not options.error:
                current += 1
                print("{}/{}".format(current, size))
                print("{}".format(path))
                if res == 'TP' and res != san_check:
                    print("{} (after sanitizers verification)".format(san_check))
                else:
                    print("{}".format(res))
                print()
            new = {
                path: {
                    "class" : res,
                    "san_check" : san_check
                }
            }
            stats.update(new)
            with open('results/stats.json', 'w') as json_file:
                json.dump(stats, json_file)
        pool.close()
        collect_results()
    except KeyboardInterrupt:
        pool.terminate()
        print("\n\nStopped by user")

if __name__ == "__main__":
    main()
