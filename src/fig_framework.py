"""Fig. 1 of the paper: schematic overview of TB-Guard (no data needed). Output: results/figures/fig0_framework.{png,pdf}"""
import os, sys
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
sys.path.insert(0, os.path.dirname(__file__))
from common import FIG
fig,ax=plt.subplots(figsize=(13,6.2)); ax.set_xlim(0,13); ax.set_ylim(-0.1,6.2); ax.axis('off')
C={'in':'#dbe7f6','tr':'#e9e3f5','gr':'#e3f1e6','dec':'#fbe7d6','off':'#eeeeee'}
def box(x,y,w,h,title,lines,col):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.02,rounding_size=0.12',fc=col,ec='#444',lw=1))
    ax.text(x+w/2,y+h-0.22,title,ha='center',va='top',fontsize=10.5,fontweight='bold')
    ax.text(x+0.12,y+h-0.62,'\n'.join(lines),ha='left',va='top',fontsize=8.6,linespacing=1.35)
def arr(x1,y1,x2,y2,txt=None,ls='-'):
    ax.add_patch(FancyArrowPatch((x1,y1),(x2,y2),arrowstyle='-|>',mutation_scale=14,lw=1.3,color='#333',linestyle=ls))
    if txt: ax.text((x1+x2)/2,(y1+y2)/2+0.12,txt,ha='center',fontsize=8,style='italic')
ax.text(6.5,6.0,'TB-Guard: runtime trust-boundary monitor (scores every privileged call before it executes)',ha='center',fontsize=12,fontweight='bold')
box(0.1,2.6,2.5,2.9,'(1) Agent trace prefix',['system / user prompt','assistant text','tool calls + arguments','tool results (lines)','— no labels, no','  injections field —'],C['in'])
box(3.0,2.6,2.7,2.9,'(2) Trust annotation',['principal lattice:','  HIGH  system, user','  MEDIUM agent, own data','  LOW  third-party content','sink privilege 0 / 1 / 2','(only level 1–2 scored)'],C['tr'])
box(6.1,2.6,3.2,2.9,'(3) Causal provenance graph',['nodes: messages, calls, args,','  results, line segments','edges (6 relations): temporal,','  arg→call, result↔segment,','  derivation exact / fuzzy (τ=0.6),','  user endorsement'],C['gr'])
box(9.7,2.6,3.2,2.9,'(4) Relational GraphSAGE',['3 layers, hidden 48, residual,','  LayerNorm, dropout 0.2','node features + 47 call','  features (provenance, delegation,','  instruction cues, behaviour)','readout MLP[h_call ‖ x_call]'],C['gr'])
box(9.7,0.2,3.2,1.9,'(5) Runtime decision',['score s(call) ≥ θ ?','θ = 99th pct of validation','  negatives (1% FPR)','→ BLOCK (trace truncated)'],C['dec'])
box(6.1,0.2,3.2,1.9,'TB-Policy (rule)',['block if an argument derives','from LOW content and is not','endorsed by the user','(interpretable reference)'],C['off'])
box(0.1,0.0,5.6,2.1,'Offline training (per split)',['call labels from AgentDojo injection-task ground truth','class-weighted BCE, Adam lr 3e-3, ≤40 epochs,','early stopping on validation AUPRC','splits: E1 grouped 5-fold · E2 leave-one-suite-out · E3 leave-one-family-out','→ supplies GNN weights to (4) and threshold θ to (5)'],C['off'])
arr(2.6,4.05,3.0,4.05); arr(5.7,4.05,6.1,4.05); arr(9.3,4.05,9.7,4.05)
arr(11.3,2.6,11.3,2.1,'')
arr(7.7,2.6,7.7,2.1,'',ls='--')
os.makedirs(FIG, exist_ok=True)
plt.savefig(os.path.join(FIG, 'fig0_framework.png'),dpi=220,bbox_inches='tight'); plt.savefig(os.path.join(FIG, 'fig0_framework.pdf'),bbox_inches='tight')
