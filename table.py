#!/usr/bin/python3

import re

results = []
total = ()
name = ''
pos_neg = ''
tpr_w = ''
tnr_w = ''
acc_w = ''
tpr_s = ''
tnr_s = ''
acc_s = ''
with open('stats.txt', 'r') as stats:
    san = False
    t = False
    for line in stats:
        if 'TOTAL' in line:
            t = True
            name = r'\textbf{TOTAL}'
        if 'CWE' in line:
            parsed = re.split('[ |\n]', line)
            parsed = [x for x in parsed if x != '']
            name = ' '.join(parsed)
        elif 'Positive cases' in line:
            pos_neg = re.search(r'\d+', line).group()
        elif 'TPR' in line and not san:
            tpr_w = re.search(r'\d+\.\d+', line).group()
            if tpr_w.endswith(".00"):
                tpr_w = tpr_w[:-3]
            tpr_w += '\%'
        elif 'TNR' in line and not san:
            tnr_w = re.search(r'\d+\.\d+', line).group()
            if tnr_w.endswith(".00"):
                tnr_w = tnr_w[:-3]
            tnr_w += '\%'
        elif 'ACC' in line and not san:
            acc_w = re.search(r'\d+\.\d+', line).group()
            if acc_w.endswith(".00"):
                acc_w = acc_w[:-3]
            acc_w += '\%'
        elif 'Sanitizers' in line:
            san = True
        elif 'TPR' in line and san:
            tpr_s = re.search(r'\d+\.\d+', line).group()
            if tpr_s.endswith(".00"):
                tpr_s = tpr_s[:-3]
            tpr_s += '\%'
        elif 'TNR' in line and san:
            tnr_s = re.search(r'\d+\.\d+', line).group()
            if tnr_s.endswith(".00"):
                tnr_s = tnr_s[:-3]
            tnr_s += '\%'
        elif 'ACC' in line and san:
            acc_s = re.search(r'\d+\.\d+', line).group()
            if acc_s.endswith(".00"):
                acc_s = acc_s[:-3]
            acc_s += '\%'
            if t:
                total = (name, pos_neg, tpr_w, tnr_w, acc_w, tpr_s, tnr_s, acc_s)
                t = False
            else:
                results += [(name, pos_neg, tpr_w, tnr_w, acc_w, tpr_s, tnr_s, acc_s)]
            san = False

highlight_row = ">{\columncolor[gray]{0.9}}"

print(r"""\documentclass[]{standalone}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{colortbl}
\begin{document}
\begin{tabular}{ l r | """, end='')
for i in range(0, 2):
    print(f"r r {highlight_row}r", end='')
    if not i:
        print("|")
print(r"""}\toprule""")
print(r"""\multirow{2}{*}{\textbf{CWE}} & \multirow{2}{*}{\textbf{P=N}} & """)
print(r"""\multicolumn{3}{c|}{\textbf{Textual errors}} &""")
print(r"""\multicolumn{3}{c}{\textbf{Sanitizers verification}} \\""")
print(r"""&& \textbf{TPR} & \textbf{TNR} & \textbf{ACC} & \textbf{TPR} & \textbf{TNR} & \textbf{ACC} \\""")
for res in results:
    print(r"""{} & {} & {} & {} & {} & {} & {} & {} \\""".format(res[0], res[1], res[2],
        res[3], res[4], res[5], res[6], res[7]))
print(r"""\midrule
{} & {} & {} & {} & {} & {} & {} & {} \\""".format(total[0], total[1], total[2],
        total[3], total[4], total[5], total[6], total[7]))
print(r"""\bottomrule
\end{tabular}
\end{document}""")
