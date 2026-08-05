#!/usr/bin/env python3
"""Render canonical TikZ templates for measurement-backed paper figures.

The measurement pipeline remains the sole numeric source: generated templates
reference macros emitted in ``todo_values_latex.tex``.  Keeping layout and
values separate prevents an opt-in manuscript sync from replacing reviewed
figures with an older hard-coded style.
"""

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
FIGS = RESULTS / "rendered_figures"
FIGS.mkdir(parents=True, exist_ok=True)


def cdf_points(values, step=0.01):
    xs = [round(i * step, 2) for i in range(int(1 / step) + 1)]
    n = len(values) or 1
    ys = []
    for x in xs:
        ys.append(sum(1 for v in values if v <= x) / n)
    return xs, ys


def fmt(v):
    if isinstance(v, float):
        return f"{v:.1f}".rstrip("0").rstrip(".")
    return str(v)


def coord(v):
    return f"{v:.2f}"


def render_coverage(d):
    _ = d["coverage_chart"]
    return r"""\definecolor{acmBlue}{HTML}{4477AA}
\definecolor{acmTeal}{HTML}{228833}
\definecolor{acmSand}{HTML}{D55E00}
\definecolor{acmGrid}{HTML}{D9DDE2}
\begin{tikzpicture}[x=0.50cm,y=0.028cm,font=\sffamily\small]
  \path[use as bounding box] (-1.55,-33.0) rectangle (18.55,139.0);
  \draw[->] (0,0) -- (18.0,0);
  \draw[->] (0,0) -- (0,118);
  \node[rotate=90,font=\small] at (-1.10,59) {Share with signal (\%)};
  \foreach \yy in {0,20,40,60,80,100} {
    \draw[acmGrid] (0,\yy) -- (17.6,\yy);
    \node[anchor=east,font=\small,text=gray,inner xsep=0.8pt,inner ysep=0.2pt] at (-0.14,\yy) {\yy};
  }
  \fill[acmBlue]   (1.0,0) rectangle (1.8,\enterpriseplatformpct);
  \fill[acmTeal]   (1.9,0) rectangle (2.7,\enterprisesoftwarelinkpct);
  \fill[acmSand]   (2.8,0) rectangle (3.6,\enterprisecvelinkpct);
  \node[above,font=\small] at (1.4,\enterpriseplatformpct) {\enterpriseplatformpct};
  \node[above,font=\small] at (2.45,\enterprisesoftwarelinkpct) {\enterprisesoftwarelinkpct};
  \node[above,font=\small] at (3.2,2.70) {\enterprisecvelinkpct};
  \fill[acmBlue]   (4.0,0) rectangle (4.8,\mobileplatformpct);
  \fill[acmTeal]   (4.9,0) rectangle (5.7,\mobilesoftwarelinkpct);
  \fill[acmSand]   (5.8,0) rectangle (6.6,\mobilecvelinkpct);
  \node[above,font=\small] at (4.4,\mobileplatformpct) {\mobileplatformpct};
  \node[above,font=\small] at (5.45,\mobilesoftwarelinkpct) {\mobilesoftwarelinkpct};
  % Mobile's CVE signal is exactly 0.0 (zero-height bar); label it explicitly
  % like every other group so a zero measurement is never silently omitted.
  \node[above,font=\small] at (6.2,1.5) {\mobilecvelinkpct};
  \fill[acmBlue]   (7.0,0) rectangle (7.8,\icsplatformpercentage);
  \fill[acmTeal]   (7.9,0) rectangle (8.7,\icssoftwarelinkpct);
  \fill[acmSand]   (8.8,0) rectangle (9.6,\icscvelinkpct);
  \node[above,font=\small] at (7.4,\icsplatformpercentage) {\icsplatformpercentage};
  \node[above,font=\small] at (8.45,\icssoftwarelinkpct) {\icssoftwarelinkpct};
  \node[above,font=\small] at (9.2,1.70) {\icscvelinkpct};
  % CAPEC has zero observations for all three measured signals. The group is
  % shifted right of ICS (and FiGHT right of CAPEC) so the compact zero label
  % clears the ICS CVE-signal label with margin, matching the caption's
  % "0/0/0" wording rather than a wider decimal form.
  \draw[acmBlue,line width=0.7pt] (10.8,0) -- (11.6,0);
  \draw[acmTeal,line width=0.7pt] (11.7,0) -- (12.5,0);
  \draw[acmSand,line width=0.7pt] (12.6,0) -- (13.4,0);
  \node[above,font=\small,text=gray] at (12.1,2) {0/0/0};
  \fill[acmBlue]   (14.6,0) rectangle (15.4,\fightplatformpercentage);
  \fill[acmTeal]   (15.5,0) rectangle (16.3,\fightsoftwarelinkpercentage);
  \fill[acmSand]   (16.4,0) rectangle (17.2,\fightcvesignalpercentage);
  \node[above,font=\small] at (15.0,\fightplatformpercentage) {\fightplatformpercentage};
  \node[above,font=\small] at (16.05,\fightsoftwarelinkpercentage) {\fightsoftwarelinkpercentage};
  \node[above,font=\small] at (16.8,3.2) {\fightcvesignalpercentage};
  \node[font=\footnotesize] at (2.3,-8) {Enterprise};
  \node[font=\footnotesize] at (5.3,-8) {Mobile};
  \node[font=\footnotesize] at (8.3,-8) {ICS};
  \node[font=\footnotesize,text=gray] at (12.1,-8) {CAPEC};
  \node[font=\footnotesize] at (15.9,-8) {FiGHT};
  \node[below,font=\small,text=gray] at (2.3,-12) {$n=\enterpriseactivetechniquecount$};
  \node[below,font=\small,text=gray] at (5.3,-12) {$n=\mobileactivetechniquecount$};
  \node[below,font=\small,text=gray] at (8.3,-12) {$n=\icsactivetechniquecount$};
  \node[below,font=\small,text=gray] at (12.1,-12) {$n=\capecactiveattackpatterncount$};
  \node[below,font=\small,text=gray] at (15.9,-12) {$n=\fighttechniquecount$};
  \node[font=\small,text=black] at (9.0,-33.0) {Corpus};
  \node[anchor=north,fill=white,fill opacity=0.95,text opacity=1,inner sep=2.2pt] at (9.0,136.0) {
    \begin{tabular}{@{}c@{\hspace{0.8em}}c@{\hspace{0.8em}}c@{}}
      \textcolor{acmBlue}{\rule{0.95em}{0.72em}}\ \ Platform &
      \textcolor{acmTeal}{\rule{0.95em}{0.72em}}\ \ Software link &
      \textcolor{acmSand}{\rule{0.95em}{0.72em}}\ \ CVE signal
    \end{tabular}
  };
\end{tikzpicture}
"""


def render_software_specificity(d):
    _ = d["software_specificity"]
    return r"""% Canonical paper template. Values are generated in results/values.tex.
\providecolor{figureGrayFill}{HTML}{B7BDC5}
\providecolor{figureGreen}{HTML}{228833}
\providecolor{figureOrange}{HTML}{A64000}
\providecolor{figureAxis}{HTML}{667085}
\providecolor{figureGrid}{HTML}{D9DDE2}

\begin{tikzpicture}[x=0.080cm,y=0.96cm,font=\sffamily\footnotesize]
  \pgfmathsetmacro{\baselineNoVersion}{\softwarenoversionnocpepercentage}
  \pgfmathsetmacro{\baselineMid}{\baselineNoVersion/2}
  \pgfmathsetmacro{\enrichedNoVersion}{\softwareversionenrichednoversionpct}
  \pgfmathsetmacro{\enrichedMid}{\enrichedNoVersion/2}
  \pgfmathsetmacro{\enrichedStructuredEnd}{\enrichedNoVersion+\softwarewithversionsignalpercentage}
  \pgfmathsetmacro{\enrichedSegmentMid}{(\enrichedStructuredEnd+100)/2}

  % Keep the native width close to one column so the enclosing resize does not
  % shrink labels below caption size.
  \path[use as bounding box] (-1.0,-1.48) rectangle (108.0,4.35);

  \draw[->] (0,0) -- (104.0,0);
  \foreach \x in {0,20,40,60,80,100} {
    \draw[figureGrid] (\x,0) -- (\x,3.30);
    \node[below,text=figureAxis] at (\x,0) {\x};
  }

  \node[anchor=west,font=\sffamily\footnotesize\bfseries]
    at (0,3.18) {Structured fields only};
  \fill[figureGrayFill] (0,2.35) rectangle (\baselineNoVersion,2.93);
  \fill[figureGreen] (\baselineNoVersion,2.35) rectangle (100,2.93);
  \node at (\baselineMid,2.64) {\softwarenoversionnocpepercentage\%};
  \node[anchor=west] at (100.7,2.64)
    {\softwarewithversionsignalpercentage\% (\softwarewithversionsignalcount)};

  \node[anchor=west,font=\sffamily\footnotesize\bfseries]
    at (0,1.62) {After description mining};
  \fill[figureGrayFill] (0,0.79) rectangle (\enrichedNoVersion,1.37);
  \fill[figureGreen] (\enrichedNoVersion,0.79) rectangle (\enrichedStructuredEnd,1.37);
  \fill[figureOrange] (\enrichedStructuredEnd,0.79) rectangle (100,1.37);
  \node at (\enrichedMid,1.08) {\softwareversionenrichednoversionpct\%};
  \node[anchor=west] at (100.7,1.08)
    {\softwareversionenrichedtotalpct\% (\softwareversionenrichedtotal)};

  \node[anchor=east,text=figureOrange,align=right]
    at (97.0,1.82)
    {+\softwareversionenrichmentgainpp\,pp\\
     (+\softwareversionenrichmentgaincount{} objects)};
  \draw[->,figureOrange,line width=0.85pt]
    (97.5,1.69) -- (\enrichedSegmentMid,1.37);

  \node[align=center] at (50.0,-0.72)
    {Active Enterprise software objects ($N=\enterpriseactivesoftwarecount$)};
  \node[text=figureAxis,align=center] at (50.0,-1.18)
    {CPE identifiers: \softwarewithcpecount{} / \enterpriseactivesoftwarecount{}};

  \node[
    anchor=south west,
    fill=white,
    fill opacity=0.95,
    text opacity=1,
    inner sep=2.0pt
  ] at (0.2,3.62) {
    \begin{tabular}{@{}ccc@{}}
      \textcolor{figureGrayFill}{\rule{0.95em}{0.72em}}\ No version &
      \textcolor{figureGreen}{\rule{0.95em}{0.72em}}\ Structured version &
      \textcolor{figureOrange}{\rule{0.95em}{0.72em}}\ Description-mined
    \end{tabular}
  };
\end{tikzpicture}
"""


def render_tier_collapse(d):
    _ = d["campaign_tier_collapse"]
    return r"""% Campaigns meeting increasingly specific evidence tiers.
\providecolor{figureBlue}{HTML}{4477AA}
\providecolor{figureInk}{HTML}{333333}
\providecolor{figureAxis}{HTML}{667085}
\providecolor{figureNotMet}{HTML}{F2F4F7}
\providecolor{figureNotMetBorder}{HTML}{8A94A6}

\begin{tikzpicture}[x=0.064cm,y=0.88cm,font=\sffamily\footnotesize]
  \path[use as bounding box] (-0.8,-1.22) rectangle (107.0,4.68);
  \foreach \x in {0,20,40,60,80,100} {
    \draw[figureAxis!25] (\x,0.45) -- (\x,4.15);
    \node[below,text=figureAxis] at (\x,0.38) {\x};
  }
  \draw[->,figureAxis] (0,0.38) -- (103.0,0.38);

  % #1=y, #2=tier, #3=percentage, #4=count, #5=label inside bar
  \newcommand{\tierbar}[5]{%
    \node[anchor=west,font=\sffamily\footnotesize\bfseries]
      at (0,{#1+0.42}) {#2};
    \draw[fill=figureNotMet,draw=figureNotMetBorder,line width=0.55pt]
      (0,{#1-0.22}) rectangle (100,{#1+0.22});
    \fill[figureBlue] (0,{#1-0.22}) rectangle (#3,{#1+0.22});
    \ifnum#5=1
      \node[anchor=west,text=white,font=\sffamily\footnotesize\bfseries]
        at (1.2,#1) {#3\% (#4)};
    \else
      \node[anchor=west,text=figureBlue,font=\sffamily\footnotesize\bfseries]
        at ({#3+1.2},#1) {#3\% (#4)};
    \fi
  }

  \tierbar{3.55}{Coarse: OS + product family}
    {\campaignsuttiercoarsepct}{\campaignsuttiercoarsecount}{1}
  \tierbar{2.35}{Reference-enriched: version/CPE or campaign CVE}
    {\campaignsuttierreferenceenrichedpct}{\campaignsuttierreferenceenrichedcount}{0}
  \tierbar{1.15}{CVE-associated: campaign CVE + software + platform}
    {\campaignsuttiercveassociatedpct}{\campaignsuttiercveassociatedcount}{0}

  \node[text=figureAxis] at (50,-0.68)
    {Share of active Enterprise campaigns ($N=\enterpriseactivecampaigncount$)};
  \fill[figureBlue] (0.0,4.37) rectangle (3.8,4.62);
  \node[anchor=west] at (4.8,4.50) {meet tier};
  \fill[figureNotMet] (22.0,4.37) rectangle (25.8,4.62);
  \draw[figureNotMetBorder,line width=0.55pt]
    (22.0,4.37) rectangle (25.8,4.62);
  \node[anchor=west] at (26.8,4.50) {do not meet tier};
\end{tikzpicture}
"""


def render_cve_location(d):
    _ = d["cve_location"]
    _ = d["cve_operational_funnel"]
    return r"""% Canonical paper template. Values are generated in results/values.tex.
\providecolor{figureBlue}{HTML}{4477AA}
\providecolor{figureGreen}{HTML}{228833}
\providecolor{figureOrange}{HTML}{A64000}
\providecolor{figureNeutral}{HTML}{6F7782}
\providecolor{figureAxis}{HTML}{667085}
\providecolor{figureGrid}{HTML}{D9DDE2}

\begin{tikzpicture}[x=0.205cm,y=0.66cm,font=\sffamily\footnotesize]
  \pgfmathsetmacro{\cveDetected}{\cveuniquecount}
  \pgfmathsetmacro{\cveAssociated}{\cveenvironmentassociatedcount}
  \pgfmathsetmacro{\cveCampaignAssociated}{\campaignlinkedcvecount}
  \pgfmathsetmacro{\campaignsWithCve}{\entcampaignswithcvecount}

  \path[use as bounding box] (-1.0,-1.35) rectangle (40.5,10.75);

  \node[anchor=west,font=\sffamily\footnotesize\bfseries,text=figureAxis]
    at (0,10.25) {CVE-identifier counts};

  \foreach \x in {0,5,10,15,20,25,30} {
    \draw[figureGrid] (\x,0) -- (\x,9.65);
    \node[below,text=figureAxis] at (\x,0) {\x};
  }
  \draw[->] (0,0) -- (32.0,0);
  \node at (16.0,-0.92) {Count};

  \node[anchor=west] at (0,9.25) {Detected identifiers};
  \fill[figureBlue] (0,8.30) rectangle (\cveDetected,8.92);
  \node[anchor=west] at ({\cveDetected+0.7},8.61)
    {\cveuniquecount{} (100\%)};

  \node[anchor=west] at (0,7.15) {Environment-associated identifiers};
  \fill[figureGreen] (0,6.20) rectangle (\cveAssociated,6.82);
  \node[anchor=west] at ({\cveAssociated+0.7},6.51)
    {\cveenvironmentassociatedcount{} (\cveenvironmentassociatedpercentage\% of detected)};

  \node[anchor=west] at (0,5.05) {Campaign-associated identifiers};
  \fill[figureOrange] (0,4.10) rectangle (\cveCampaignAssociated,4.72);
  \node[anchor=west] at ({\cveCampaignAssociated+0.7},4.41)
    {\campaignlinkedcvecount{} (\campaignlinkedcveenvironmentpercentage\% of associated)};

  % The final row changes unit from CVE identifiers to campaigns.
  \draw[densely dashed,figureAxis!65] (0,3.28) -- (39.5,3.28);
  \node[anchor=west,font=\sffamily\footnotesize\bfseries,text=figureAxis]
    at (0,2.83) {Campaign count};
  \node[anchor=west] at (0,2.05) {Campaigns with $\geq$1 CVE};
  \fill[figureNeutral] (0,1.10) rectangle (\campaignsWithCve,1.72);
  \node[anchor=west] at ({\campaignsWithCve+0.7},1.41)
    {\entcampaignswithcvecount{} (\entcampaignswithcvepct\% of \enterpriseactivecampaigncount{})};
\end{tikzpicture}
"""


def render_jaccard(d):
    j = d["jaccard_cdf"]
    n_is = len(j["software_only_distances"])
    xs, ys_sw = cdf_points(j["software_only_distances"])
    _, ys_sc = cdf_points(j["software_cve_distances"])
    pts_sw = " -- ".join(f"({x:.2f},{y:.3f})" for x, y in zip(xs, ys_sw))
    pts_sc = " -- ".join(f"({x:.2f},{y:.3f})" for x, y in zip(xs, ys_sc))
    confused = next((y for x, y in zip(xs, ys_sc) if abs(x - j["delta_threshold"]) < 1e-9), 0.0)
    return f"""\\definecolor{{acmBlue}}{{HTML}}{{4477AA}}
\\definecolor{{acmTeal}}{{HTML}}{{228833}}
\\definecolor{{acmGrid}}{{HTML}}{{D9DDE2}}
\\definecolor{{acmGray}}{{HTML}}{{8A8F99}}
\\begin{{tikzpicture}}[x=7.94cm,y=5.15cm,font=\\footnotesize]
  \\draw[->] (0,0) -- (1.05,0);
  \\draw[->] (0,0) -- (0,1.05) node[above] {{Cumulative fraction of groups}};
  \\foreach \\x in {{0,0.2,0.4,0.6,0.8,1.0}} {{
    \\draw[acmGrid] (\\x,0) -- (\\x,1.0);
    \\node[below] at (\\x,0) {{\\x}};
  }}
  \\foreach \\y in {{0,0.2,0.4,0.6,0.8,1.0}} {{
    \\draw[acmGrid] (0,\\y) -- (1.0,\\y);
    \\node[left] at (0,\\y) {{\\y}};
  }}
  \\draw[line width=1.08pt,acmBlue] {pts_sw};
  \\draw[line width=1.08pt,acmTeal,densely dashed] {pts_sc};
  \\draw[densely dashed,line width=0.75pt,acmGray] ({j['delta_threshold']},0) -- ({j['delta_threshold']},1.0);
  \\node[anchor=south west,text=acmGray] at ({j['delta_threshold'] + 0.005:.3f},0.10) {{$\\delta={j['delta_threshold']}$}};
  \\node[anchor=north west,text=acmGray] at ({j['delta_threshold'] + 0.005:.3f},0.085) {{{round(100*confused,1)}\\% confused}};
  \\node[anchor=north west,fill=white,fill opacity=0.95,text opacity=1,inner sep=2.2pt] at (0.56,0.98) {{
    \\begin{{tabular}}{{@{{}}l@{{}}}}
      \\textcolor{{acmBlue}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ Software only\\\\[1pt]
      \\textcolor{{acmTeal}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ Software + CVE
    \\end{{tabular}}
  }};
  \\node[font=\\footnotesize] at (0.52,-0.095) {{Nearest-neighbor Jaccard distance}};
  \\node[font=\\small,text=acmGray] at (0.52,-0.175) {{$n={n_is}$ intrusion sets, $\\delta={j['delta_threshold']}$}};
\\end{{tikzpicture}}
"""


def render_ablation(d):
    _ = d["threshold_confusion"]
    return r"""% RQ3 sensitivity over nested profile subsets. Values come from results/values.tex.
\providecolor{figureBlue}{HTML}{4477AA}
\providecolor{figureInk}{HTML}{333333}
\providecolor{figureAxis}{HTML}{667085}
\providecolor{figureGrid}{HTML}{D9DDE2}

\begin{tikzpicture}[x=0.53cm,y=0.78cm,font=\sffamily\footnotesize]
  \path[use as bounding box] (-3.05,-1.35) rectangle (13.50,4.85);

  \foreach \x in {0,2,4,6,8,10} {
    \draw[figureGrid] (\x,0.25) -- (\x,4.15);
    \node[below,text=figureAxis] at (\x,0.20) {\x};
  }
  \draw[->,figureAxis,line width=0.8pt] (0,0.20) -- (10.45,0.20);
  \node[anchor=west,font=\sffamily\footnotesize\bfseries,text=figureAxis]
    at (-2.90,4.52) {Nested subset};
  \node[anchor=east,font=\sffamily\footnotesize\bfseries,text=figureAxis]
    at (13.35,4.52) {Population};

  % #1=y, #2=subset label, #3=rate, #4=population size
  \newcommand{\ablationrow}[4]{%
    \node[anchor=east] at (-0.22,#1) {#2};
    \draw[figureBlue,line width=2.0pt,line cap=round] (0,#1) -- (#3,#1);
    \fill[figureBlue] (#3,#1) circle (0.105);
    \node[anchor=east,font=\sffamily\footnotesize\bfseries]
      at (10.65,#1) {#3\%};
    \node[anchor=east,text=figureAxis] at (13.35,#1) {$n=#4$};
  }

  \ablationrow{3.70}{All active profiles}
    {\sutprofileconfusionsoftwarepercentage}{\enterpriseactiveintrusionsetcount}
  \ablationrow{2.75}{$k\geq1$}
    {\thresholdkoneconfusionpct}{\thresholdkonesample}
  \ablationrow{1.80}{$k\geq2$}
    {\thresholdktwoconfusionpct}{\thresholdktwosample}
  \ablationrow{0.85}{$k\geq3$}
    {\thresholdkthreeconfusionpct}{\thresholdkthreesample}

  \node[text=figureAxis] at (5.0,-0.46) {Nearest-neighbor confusion (\%)};
  \node[anchor=west,text=figureAxis] at (-2.90,-1.07)
    {$k$ counts linked software objects; each row recomputes neighbors.};
\end{tikzpicture}
"""


def render_compatibility_distribution(d):
    _ = d["compatibility_table"]
    return r"""% Canonical paper template. Values are generated in results/values.tex.
\providecolor{figureBlue}{HTML}{4477AA}
\providecolor{figureGreen}{HTML}{228833}
\providecolor{figureFallback}{HTML}{E6F4F1}
\providecolor{figureOrange}{HTML}{A64000}
\providecolor{figureAxis}{HTML}{667085}
\providecolor{figureGrid}{HTML}{D9DDE2}
\providecolor{figureInk}{HTML}{333333}

\begin{tikzpicture}[x=0.55cm,y=0.050cm,font=\sffamily\small]
  \path[use as bounding box] (-1.55,-22.0) rectangle (14.8,108.0);

  \draw[->] (0,0) -- (13.9,0);
  \draw[->] (0,0) -- (0,106);
  \node[rotate=90] at (-1.25,53) {Share of techniques (\%)};
  \foreach \yy in {0,20,40,60,80,100} {
    \draw[figureGrid] (0,\yy) -- (13.25,\yy);
    \node[anchor=east,text=figureAxis,inner xsep=0.8pt,inner ysep=0.2pt]
      at (-0.12,\yy) {\yy};
  }

  \fill[figureBlue] (1.2,0) rectangle (2.7,\compatibilitycontainerfeasiblepercentage);
  \fill[figureGreen]
    (3.6,0) rectangle (5.1,\compatibilityvmrexplicitpercentage);
  \fill[figureFallback,draw=figureGreen,dashed,line width=0.65pt]
    (3.6,\compatibilityvmrexplicitpercentage)
    rectangle (5.1,\compatibilityvmrequiredpercentage);
  \draw[white,line width=0.8pt]
    (3.6,\compatibilityvmrexplicitpercentage)
    -- (5.1,\compatibilityvmrexplicitpercentage);
  \fill[figureOrange]
    (6.0,0) rectangle (7.5,\compatibilityinfrastructuredependentpercentage);

  \node[above] at (1.95,\compatibilitycontainerfeasiblepercentage)
    {\compatibilitycontainerfeasiblepercentage\%};
  \node[above] at (4.35,\compatibilityvmrequiredpercentage)
    {\compatibilityvmrequiredpercentage\%};
  \node[above] at (6.75,\compatibilityinfrastructuredependentpercentage)
    {\compatibilityinfrastructuredependentpercentage\%};

  \node[text=white,font=\sffamily\small\bfseries]
    at (4.35,4.4) {\compatibilityvmrexplicitpercentage\%};
  \node[anchor=west,text=figureInk]
    at (5.35,42.45) {fallback \compatibilityvmrfallbackpercentage\%};

  \node[below,font=\sffamily\small\bfseries] at (1.95,0) {CF};
  \node[below,font=\sffamily\small\bfseries] at (4.35,0) {VMR};
  \node[below,font=\sffamily\small\bfseries] at (6.75,0) {ID};
  \node[below,text=figureAxis] at (1.95,-7.0)
    {$n=\compatibilitycontainerfeasiblecount$};
  \node[below,text=figureAxis,align=center] at (4.35,-5.5)
    {\compatibilityvmrexplicitcount{} explicit\\
     \compatibilityvmrfallbackcount{} fallback};
  \node[below,text=figureAxis] at (6.75,-7.0)
    {$n=\compatibilityinfrastructuredependentcount$};

  \draw[line width=1.15pt,figureAxis]
    (11.0,\compatibilitynoncffloorpercentage)
    -- (11.0,\compatibilitynoncfceilingpercentage);
  \fill[figureAxis] (11.0,\compatibilitynoncffloorpercentage) circle (0.09);
  \fill[figureAxis] (11.0,\compatibilitynoncfceilingpercentage) circle (0.09);
  \node[anchor=west,text=figureAxis]
    at (11.18,\compatibilitynoncfceilingpercentage)
    {ceiling \compatibilitynoncfceilingpercentage\%};
  \node[anchor=west,text=figureAxis]
    at (11.18,\compatibilitynoncffloorpercentage)
    {floor \compatibilitynoncffloorpercentage\%};
  \node[below,align=center] at (11.0,0) {non-CF\\policy range};

  \node[align=center,text=figureInk] at (10.9,14.0)
    {$N=\enterpriseactivetechniquecount$\\
     policy output\\
     not backend ground truth};
\end{tikzpicture}
"""


def render_compatibility_by_tactic(d):
    rows = d.get("compatibility_by_tactic", [])
    if not rows:
        return (
            "\\begin{tikzpicture}[font=\\footnotesize]\n"
            "  \\node {No compatibility-by-tactic data};\n"
            "\\end{tikzpicture}\n"
        )

    def short_label(tactic):
        mapping = {
            "command-and-control": "C2",
            "privilege-escalation": "priv-esc",
            "resource-development": "resource-dev",
            "lateral-movement": "lateral-mvmt",
            "credential-access": "cred-access",
        }
        return mapping.get(tactic, tactic)

    n = len(rows)
    y_top = n + 0.8
    y_axis = 0.2
    lines = [
        "\\definecolor{acmTeal}{HTML}{228833}",
        "\\definecolor{acmGray}{HTML}{8A8F99}",
        "\\definecolor{acmGrid}{HTML}{D9DDE2}",
        "\\begin{tikzpicture}[x=0.079cm,y=0.52cm,font=\\footnotesize]",
        f"  \\draw[->] (0,{y_axis:.1f}) -- (106,{y_axis:.1f}) node[right] {{non-CF share (\\%)}};",
        f"  \\draw[->] (0,{y_axis:.1f}) -- (0,{y_top + 0.2:.1f});",
    ]
    for x in [0, 20, 40, 60, 80, 100]:
        lines.append(f"  \\draw[acmGrid] ({x},{y_axis:.1f}) -- ({x},{y_top:.1f});")
        lines.append(f"  \\node[below] at ({x},{y_axis:.1f}) {{{x}}};")

    for idx, row in enumerate(rows):
        y = n - idx
        non_cf = float(row.get("non_cf_pct", 0))
        total = int(row.get("total", 0))
        label = short_label(str(row.get("tactic", "")))
        lines.append(f"  \\fill[acmGray!25] (0,{y-0.28:.2f}) rectangle (100,{y+0.28:.2f});")
        lines.append(f"  \\fill[acmTeal] (0,{y-0.28:.2f}) rectangle ({non_cf:.1f},{y+0.28:.2f});")
        lines.append(f"  \\node[anchor=east] at (-1.2,{y:.2f}) {{{label}}};")
        lines.append(
            f"  \\node[anchor=west] at ({min(non_cf + 1.0, 101.0):.1f},{y:.2f}) "
            f"{{{fmt(non_cf)}\\% (n={total})}};"
        )

    lines.append(
        "  \\node[anchor=west,font=\\small,text=acmGray] at (0.0,-0.55)"
        " {Sorted by tactic support (multi-tactic techniques counted per tactic).};"
    )
    lines.append("\\end{tikzpicture}")
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# New figures: inNervoso consolidation
# ──────────────────────────────────────────────────────────────

TACTIC_SHORT = {
    "reconnaissance": "Recon",
    "resource-development": "Res.Dev",
    "initial-access": "Init.Acc",
    "execution": "Exec",
    "persistence": "Persist",
    "privilege-escalation": "Priv.Esc",
    "defense-evasion": "Def.Eva",
    "credential-access": "Cred.Acc",
    "discovery": "Disc",
    "lateral-movement": "Lat.Mov",
    "collection": "Collect",
    "command-and-control": "C2",
    "exfiltration": "Exfil",
    "impact": "Impact",
}


def render_tactic_coverage_heatmap(d):
    """Campaign × tactic heatmap — rows=campaigns, cols=14 tactics."""
    data = d.get('campaign_tactic_coverage', {})
    campaigns = data.get('campaigns', [])
    tactic_order = data.get('tactic_order', [])

    if not campaigns or not tactic_order:
        return "% No tactic coverage data available\n"

    # Sort campaigns by tactic_count descending for visual clarity
    campaigns = sorted(campaigns, key=lambda c: -c.get('tactic_count', 0))

    n_camps = len(campaigns)
    n_tactics = len(tactic_order)

    # Cell dimensions
    cell_w = 0.55  # cm per tactic column
    cell_h = 0.18  # cm per campaign row

    lines = [
        "\\definecolor{acmBlue}{HTML}{4477AA}",
        "\\definecolor{acmGray}{HTML}{A0A0A0}",
        "\\definecolor{hmPresent}{HTML}{4477AA}",
        "\\definecolor{hmAbsent}{HTML}{F0F0F0}",
        f"\\begin{{tikzpicture}}[x={cell_w}cm,y={cell_h}cm,font=\\tiny]",
    ]

    # Column headers (tactic names)
    for j, tactic in enumerate(tactic_order):
        label = TACTIC_SHORT.get(tactic, tactic[:6])
        lines.append(
            f"  \\node[rotate=60,anchor=south west] at ({j + 0.5},{n_camps + 0.3}) "
            f"{{\\textsf{{{label}}}}};"
        )

    # Grid cells
    for i, camp in enumerate(campaigns):
        y = n_camps - 1 - i
        tactics = camp.get('tactics', {})
        # Campaign label (truncated)
        name = camp.get('name', '')[:18]
        lines.append(f"  \\node[anchor=east,font=\\tiny] at (-0.2,{y + 0.5}) {{{name}}};")

        for j, tactic in enumerate(tactic_order):
            present = tactics.get(tactic, 0)
            color = "hmPresent" if present else "hmAbsent"
            lines.append(
                f"  \\fill[{color}] ({j},{y}) rectangle ({j + 1},{y + 1});"
            )

    # Border
    lines.append(f"  \\draw (0,0) rectangle ({n_tactics},{n_camps});")

    # Annotation
    lines.append(
        f"  \\node[anchor=west,font=\\small] at (0,-1.0) "
        f"{{$N={n_camps}$ campaigns, sorted by tactic coverage.}};"
    )

    lines.append("\\end{tikzpicture}")
    lines.append("")
    return "\n".join(lines)


def render_ieir_breakdown(d):
    """IEIR stacked bar — campaign-specific vs generic-only vs no signal."""
    data = d.get('ieir_breakdown', {})
    total = data.get('total', 0)
    explicit = data.get('campaign_specific', data.get('explicit', 0))
    implicit = data.get('generic_only', data.get('implicit_only', 0))
    none_sig = data.get('no_signal', 0)

    if total == 0:
        return "% No IEIR data available\n"

    explicit_pct = data.get('campaign_specific_pct', data.get('explicit_pct', 0))
    ieir_pct = data.get('ieir_pct', 0)
    none_pct = data.get('none_pct', 0)

    bar_h = 0.8  # cm
    scale = 0.08  # cm per percentage point

    lines = [
        "\\definecolor{acmBlue}{HTML}{4477AA}",
        "\\definecolor{acmSand}{HTML}{EE7733}",
        "\\definecolor{acmGray}{HTML}{A0A0A0}",
        f"\\begin{{tikzpicture}}[y={bar_h}cm,x={scale}cm,font=\\footnotesize]",
        "  % Stacked bar",
    ]

    x = 0
    # Explicit platforms
    lines.append(f"  \\fill[acmBlue] ({x},0) rectangle ({x + explicit_pct},1);")
    if explicit_pct > 8:
        lines.append(
            f"  \\node[white,font=\\footnotesize] at ({x + explicit_pct / 2},0.5) "
            f"{{Explicit {fmt(explicit_pct)}\\%}};"
        )
    x += explicit_pct

    # Implicit only
    if ieir_pct > 0:
        lines.append(f"  \\fill[acmSand] ({x},0) rectangle ({x + ieir_pct},1);")
        if ieir_pct > 5:
            lines.append(
                f"  \\node[white] at ({x + ieir_pct / 2},0.5) "
                f"{{IEIR {fmt(ieir_pct)}\\%}};"
            )
        x += ieir_pct

    # No signal
    if none_pct > 0:
        lines.append(f"  \\fill[acmGray] ({x},0) rectangle ({x + none_pct},1);")
        x += none_pct

    # Border
    lines.append(f"  \\draw (0,0) rectangle (100,1);")

    # Legend
    lines.append(
        f"  \\node[anchor=west,font=\\small] at (0,-0.5) "
        f"{{$N={total}$ campaigns. "
        f"Explicit platform: {explicit} ({fmt(explicit_pct)}\\%), "
        f"IEIR (implicit-only): {implicit} ({fmt(ieir_pct)}\\%).}};"
    )

    # Confidence breakdown
    conf = data.get('confidence_breakdown', {})
    lines.append(
        f"  \\node[anchor=west,font=\\small,text=acmGray] at (0,-1.0) "
        f"{{Confidence: high={fmt(conf.get('high', 0))}\\%, "
        f"medium={fmt(conf.get('medium', 0))}\\%, "
        f"low={fmt(conf.get('low', 0))}\\%, "
        f"none={fmt(conf.get('none', 0))}\\%.}};"
    )

    lines.append("\\end{tikzpicture}")
    lines.append("")
    return "\n".join(lines)


def render_evidence_convergence(d):
    """Evidence convergence bar chart — convergent vs divergent."""
    data = d.get('evidence_convergence', {})
    total = data.get('total', 0)
    convergent = data.get('convergent', 0)
    divergent = data.get('divergent', 0)
    rate_pct = data.get('convergence_rate_pct', 0)

    if total == 0:
        return "% No convergence data available\n"

    convergent_pct = 100 * convergent / total
    divergent_pct = 100 * divergent / total

    lines = [
        "\\definecolor{acmBlue}{HTML}{4477AA}",
        "\\definecolor{acmSand}{HTML}{EE7733}",
        "\\definecolor{acmGrid}{HTML}{D9DDE2}",
        "\\definecolor{acmAxis}{HTML}{555555}",
        "\\begin{tikzpicture}[x=0.075cm,y=0.82cm,font=\\footnotesize]",
        f"  \\path[use as bounding box] (-13.5,-0.82) rectangle ({total + 3},2.25);",
        f"  \\draw[->,acmAxis] (0,0) -- ({total + 2},0);",
        f"  \\node[font=\\small,text=acmAxis] at ({total / 2},-0.62) {{Campaign count}};",
        "  \\node[anchor=west,font=\\small,text=acmAxis] at (-13.2,2.02) {Agreement outcome};",
    ]

    # Grid
    for y in range(0, total + 1, 10):
        lines.append(f"  \\draw[acmGrid] ({y},0) -- ({y},1.75);")
        lines.append(f"  \\node[below,font=\\small] at ({y},-0.08) {{{y}}};")

    # Convergent bar
    lines.append("  \\node[anchor=east] at (-1.2,1.40) {Convergent};")
    lines.append(f"  \\fill[acmBlue] (0,1.18) rectangle ({convergent},1.62);")
    lines.append(f"  \\node[anchor=west,font=\\small] at ({convergent + 1},1.40) {{{convergent} ({fmt(convergent_pct)}\\%)}};")

    # Divergent bar
    lines.append("  \\node[anchor=east] at (-1.2,0.55) {Divergent};")
    lines.append(f"  \\fill[acmSand] (0,0.33) rectangle ({divergent},0.77);")
    lines.append(f"  \\node[anchor=west,font=\\small] at ({divergent + 1},0.55) {{{divergent} ({fmt(divergent_pct)}\\%)}};")

    lines.append("\\end{tikzpicture}")
    lines.append("")
    return "\n".join(lines)


def main():
    d = json.loads((RESULTS / "figures_data.json").read_text(encoding="utf-8"))
    FIGS.mkdir(parents=True, exist_ok=True)

    # ── Original 8 figures ──
    (FIGS / "coverage_template.tex").write_text(render_coverage(d), encoding="utf-8")
    (FIGS / "tier_collapse_template.tex").write_text(render_tier_collapse(d), encoding="utf-8")
    (FIGS / "software_specificity_template.tex").write_text(render_software_specificity(d), encoding="utf-8")
    (FIGS / "cve_location_template.tex").write_text(render_cve_location(d), encoding="utf-8")
    (FIGS / "jaccard_cdf_template.tex").write_text(render_jaccard(d), encoding="utf-8")
    (FIGS / "ablation_template.tex").write_text(render_ablation(d), encoding="utf-8")
    (FIGS / "compatibility_distribution_template.tex").write_text(
        render_compatibility_distribution(d),
        encoding="utf-8",
    )
    (FIGS / "compatibility_by_tactic_template.tex").write_text(
        render_compatibility_by_tactic(d),
        encoding="utf-8",
    )

    # ── New figures: inNervoso consolidation ──
    n_new = 0
    if 'campaign_tactic_coverage' in d:
        (FIGS / "tactic_coverage_heatmap_template.tex").write_text(
            render_tactic_coverage_heatmap(d), encoding="utf-8"
        )
        n_new += 1

    if 'ieir_breakdown' in d:
        (FIGS / "ieir_breakdown_template.tex").write_text(
            render_ieir_breakdown(d), encoding="utf-8"
        )
        n_new += 1

    if 'evidence_convergence' in d:
        (FIGS / "evidence_convergence_template.tex").write_text(
            render_evidence_convergence(d), encoding="utf-8"
        )
        n_new += 1

    print(f"Rendered {8 + n_new} figure templates ({n_new} new) from measured JSON.")


if __name__ == "__main__":
    main()
