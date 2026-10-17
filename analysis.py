#!/usr/bin/env python3
"""Rebuild CSV summaries and monochrome vector figures from pytest JUnit XML.

Usage (from project root):
  .venv/Scripts/python.exe analysis.py --junit docs/pytest-results-current.xml

Requires only the standard library and ReportLab (already declared in requirements.txt).
The plots describe regression-test outcomes and harness times, not security efficacy
or production request latency.
"""
from __future__ import annotations

import argparse
import random
import csv
import json
import math
import statistics
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

from reportlab.lib import colors
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parent


def extract(junit: Path) -> tuple[list[dict], float, str]:
    root = ET.parse(junit).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    rows: list[dict] = []
    elapsed = 0.0
    timestamp = ""
    for suite in suites:
        if suite.get("time"):
            elapsed = max(elapsed, float(suite.get("time", "0")))
        timestamp = timestamp or suite.get("timestamp", "")
        for case in suite.findall("testcase"):
            fail = case.find("failure")
            error = case.find("error")
            skip = case.find("skipped")
            outcome = "fail" if fail is not None or error is not None else "skip" if skip is not None else "pass"
            issue = fail if fail is not None else error if error is not None else skip
            cls = case.get("classname", "unknown")
            rows.append({
                "run_timestamp": timestamp,
                "test_module": ".".join(cls.split(".")[:2]) if cls.startswith("tests.") else cls.rsplit(".", 1)[0],
                "test_class": cls,
                "test_name": case.get("name", "unknown"),
                "outcome": outcome,
                "duration_seconds": f"{float(case.get('time', '0')):.6f}",
                "failure_or_skip_message": " ".join((issue.get("message", "") + " " + (issue.text or "")).split()) if issue is not None else "",
            })
    return rows, elapsed, timestamp


def save_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["run_timestamp", "test_module", "test_class", "test_name", "outcome", "duration_seconds", "failure_or_skip_message"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def outcome_figure(counts: Counter, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out), pagesize=(460, 280), pageCompression=1)
    c.setTitle("Observed pytest outcomes")
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold", 13)
    c.drawString(46, 246, "Observed regression-test outcomes")
    c.setFont("Helvetica", 8); c.drawString(46, 231, f"Source: current JUnit XML; n={sum(counts.values())} parametrized cases")
    x0, y0, chart_h, bar_w, gap = 78, 65, 140, 58, 42
    maxv = max(counts.values(), default=1) or 1
    c.setStrokeColor(colors.black); c.setLineWidth(.7)
    c.line(x0, y0, 400, y0); c.line(x0, y0, x0, y0+chart_h)
    c.setFont("Helvetica", 8)
    for tick in range(0, maxv+1, max(1, math.ceil(maxv/5))):
        y=y0 + chart_h*tick/maxv
        c.setStrokeColor(colors.lightgrey); c.line(x0, y, 400, y)
        c.setFillColor(colors.black); c.drawRightString(x0-7, y-3, str(tick))
    names=[("pass", "Passed"), ("skip", "Skipped"), ("fail", "Failed")]
    for i,(key,label) in enumerate(names):
        value=counts.get(key,0); x=x0+38+i*(bar_w+gap); h=chart_h*value/maxv
        c.setFillColor(colors.black if key=="pass" else colors.HexColor("#888888") if key=="skip" else colors.white)
        c.setStrokeColor(colors.black); c.rect(x,y0,bar_w,h,fill=1,stroke=1)
        if key=="fail":
            c.setLineWidth(.6)
            for yy in range(int(y0),int(y0+h),7): c.line(x,yy,min(x+bar_w,x+bar_w),min(yy+7,y0+h))
        c.setFillColor(colors.black); c.setFont("Helvetica-Bold",9); c.drawCentredString(x+bar_w/2,y0+h+5,str(value))
        c.setFont("Helvetica",8); c.drawCentredString(x+bar_w/2,y0-14,label)
    c.saveState(); c.translate(29,y0+chart_h/2); c.rotate(90); c.setFont("Helvetica",7); c.drawCentredString(0,0,"Test-case count"); c.restoreState()
    c.setFont("Helvetica",7); c.drawCentredString(248,35,"Observed outcome")
    c.drawString(46, 16, "Counts are test assertions, not attack attempts, labeled detections, or a security pass rate.")
    c.save()


def runtime_figure(rows: list[dict], out: Path) -> None:
    totals=defaultdict(float)
    for row in rows: totals[row["test_module"]]+=float(row["duration_seconds"])
    items=sorted(totals.items(), key=lambda item:item[1], reverse=True)
    height=max(300, 95+len(items)*24)
    c=canvas.Canvas(str(out), pagesize=(600,height), pageCompression=1)
    c.setTitle("Pytest elapsed time by module")
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold",13); c.drawString(42,height-32,"Measured pytest elapsed time by module")
    c.setFont("Helvetica",8); c.drawString(42,height-48,"Per-test JUnit durations summed by module; seconds; harness time, not endpoint latency")
    label_w=170; x0=label_w+42; x1=560; maxv=max((v for _,v in items),default=1) or 1
    top=height-77; rowh=22
    for i,(name,val) in enumerate(items):
        y=top-i*rowh
        c.setFillColor(colors.black); c.setFont("Helvetica",7.5); c.drawRightString(label_w+35,y+3,name.replace("tests.",""))
        w=(x1-x0)*val/maxv
        c.setFillColor(colors.HexColor("#777777") if i%2 else colors.black); c.rect(x0,y,w,12,fill=1,stroke=0)
        c.setFillColor(colors.black); c.setFont("Helvetica",7); c.drawString(x0+w+4,y+2,f"{val:.2f}")
    axis_y=max(42,top-(len(items)-1)*rowh-13)
    c.setStrokeColor(colors.black); c.line(x0,axis_y,x1,axis_y)
    c.setFont("Helvetica",6.5)
    for tick in range(6):
        value=maxv*tick/5; xx=x0+(x1-x0)*tick/5
        c.line(xx,axis_y-2,xx,axis_y+2); c.drawCentredString(xx,axis_y-11,f"{value:.0f}")
    c.drawCentredString((x0+x1)/2,axis_y-21,"Summed test-case time (seconds)")
    c.setFont("Helvetica",7); c.drawString(42,10,"Variation reflects test fixtures, hashing and module composition; do not compare as service performance.")
    c.save()


def crypto_stats(path: Path) -> list[dict]:
    grouped=defaultdict(list)
    with path.open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            grouped[(row["operation"],int(row["payload_bytes"]),row["mode"])].append(int(row["duration_ns"]))
    output=[]
    for (op,size,mode),values in sorted(grouped.items()):
        vals=sorted(values); rng=random.Random(f"{op}:{size}:{mode}:20261017")
        boot=[]
        for _ in range(2000):
            sample=[vals[rng.randrange(len(vals))] for _ in vals]
            boot.append(statistics.median(sample))
        boot.sort()
        output.append({"operation":op,"payload_bytes":size,"mode":mode,"n":len(vals),
            "mean_ns":statistics.mean(vals),"median_ns":statistics.median(vals),
            "sample_sd_ns":statistics.stdev(vals) if len(vals)>1 else 0,
            "p95_ns":vals[math.ceil(.95*len(vals))-1],
            "median_ci95_low_ns":boot[49],"median_ci95_high_ns":boot[1949]})
    return output


def crypto_figure(stats: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True,exist_ok=True)
    c=canvas.Canvas(str(out),pagesize=(620,340),pageCompression=1); c.setTitle("CNS envelope cryptographic microbenchmark")
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold",13); c.drawString(38,316,"CNS message cryptographic microbenchmark")
    c.setFont("Helvetica",8); c.drawString(38,302,"Median elapsed time with bootstrap 95% CI; n=100 per size and mode; measured locally")
    sizes=sorted({r["payload_bytes"] for r in stats})
    modes=[("aesgcm_only","AES-GCM only",False),("full_envelope","Full envelope",True)]
    panels=[("encrypt",38,"Encrypt / sign"),("decrypt",336,"Verify / decrypt")]
    for operation,x,title in panels:
        pw,ph=245,165; y0=84; x0=x+38; y1=y0+ph; x1=x+pw
        subset=[r for r in stats if r["operation"]==operation]
        ymax=max((r["median_ci95_high_ns"] for r in subset),default=1)/1000*1.15 or 1
        c.setFillColor(colors.black); c.setFont("Helvetica-Bold",9); c.drawString(x,y1+8,title)
        c.setStrokeColor(colors.black); c.setLineWidth(.65); c.line(x0,y0,x1,y0); c.line(x0,y0,x0,y1)
        c.setFont("Helvetica",6.5)
        for tick in range(0,5):
            val=ymax*tick/4; yy=y0+ph*tick/4
            c.setStrokeColor(colors.lightgrey); c.line(x0,yy,x1,yy)
            c.setFillColor(colors.black); c.drawRightString(x0-4,yy-2,f"{val:.0f}")
        xpos={size:x0+18+i*(pw-66)/max(1,len(sizes)-1) for i,size in enumerate(sizes)}
        for key,label,dashed in modes:
            seq=[next(r for r in subset if r["payload_bytes"]==size and r["mode"]==key) for size in sizes]
            c.setStrokeColor(colors.black); c.setFillColor(colors.black); c.setLineWidth(1)
            c.setDash(4,2) if dashed else c.setDash()
            pts=[]
            for item in seq:
                med=item["median_ns"]/1000; lo=item["median_ci95_low_ns"]/1000; hi=item["median_ci95_high_ns"]/1000
                px=xpos[item["payload_bytes"]]; py=y0+ph*med/ymax; pyl=y0+ph*lo/ymax; pyh=y0+ph*hi/ymax
                c.line(px,pyl,px,pyh); c.line(px-2,pyl,px+2,pyl); c.line(px-2,pyh,px+2,pyh)
                pts.append((px,py))
            for (a,b) in zip(pts,pts[1:]): c.line(a[0],a[1],b[0],b[1])
            c.setDash()
            for px,py in pts:
                if dashed: c.circle(px,py,2.5,fill=1,stroke=1)
                else: c.rect(px-2,py-2,4,4,fill=1,stroke=1)
            c.setFont("Helvetica",6.5); c.drawString(x+8+(0 if key=="aesgcm_only" else 100),43,label+" (n=100)")
            c.setStrokeColor(colors.black); c.setDash(4,2) if dashed else c.setDash(); c.line(x+8+(0 if key=="aesgcm_only" else 100),39,x+28+(0 if key=="aesgcm_only" else 100),39); c.setDash()
        for size in sizes:
            c.setFillColor(colors.black); c.setFont("Helvetica",6.5); c.drawCentredString(xpos[size],y0-12,str(size))
        c.saveState(); c.translate(x+9,y0+ph/2); c.rotate(90); c.setFont("Helvetica",6.5); c.drawCentredString(0,0,"Elapsed time (microseconds)"); c.restoreState()
        c.setFont("Helvetica",6.5); c.drawCentredString(x0+pw/2,y0-25,"Payload size (bytes)")
    c.setFont("Helvetica",7); c.drawString(38,18,"Baseline times are primitive-only. Full-envelope timings include metadata/signature work; neither includes HTTP, DB, or browser transport.")
    c.save()


def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--junit",type=Path,default=ROOT/"docs/pytest-results-current.xml")
    p.add_argument("--csv",type=Path,default=ROOT/"experimental_data.csv")
    p.add_argument("--figures",type=Path,default=ROOT/"figures")
    p.add_argument("--summary",type=Path,default=ROOT/"analysis_summary.json")
    p.add_argument("--crypto",type=Path,default=ROOT/"crypto_benchmark.csv")
    args=p.parse_args()
    rows,suite_seconds,timestamp=extract(args.junit)
    if not rows: raise SystemExit("JUnit XML contains no test cases")
    save_csv(rows,args.csv)
    counts=Counter(row["outcome"] for row in rows)
    durations=[float(row["duration_seconds"]) for row in rows]
    by_module=defaultdict(Counter)
    for row in rows: by_module[row["test_module"]][row["outcome"]]+=1
    summary={
        "source":str(args.junit.relative_to(ROOT) if args.junit.is_relative_to(ROOT) else args.junit),
        "run_timestamp":timestamp,"test_case_count":len(rows),"outcomes":dict(counts),
        "suite_reported_seconds":suite_seconds,
        "per_case_duration_seconds":{"sum":sum(durations),"mean":statistics.mean(durations),
            "median":statistics.median(durations),"sample_sd":statistics.stdev(durations) if len(durations)>1 else None,
            "p95_nearest_rank":sorted(durations)[math.ceil(.95*len(durations))-1]},
        "module_outcomes":{k:dict(v) for k,v in sorted(by_module.items())},
        "interpretation":"Functional-test evidence only. Per-test durations are harness timings; no endpoint latency, scanner precision/recall, or attack-blocking rate is inferred."
    }
    args.summary.parent.mkdir(parents=True,exist_ok=True)
    args.summary.write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    outcome_figure(counts,args.figures/"test_outcomes.pdf")
    runtime_figure(rows,args.figures/"test_runtime_by_module.pdf")
    crypto=crypto_stats(args.crypto)
    with (ROOT/"crypto_benchmark_summary.csv").open("w",newline="",encoding="utf-8") as f:
        fields=list(crypto[0].keys()) if crypto else []
        writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader(); writer.writerows(crypto)
    crypto_figure(crypto,args.figures/"crypto_overhead.pdf")
    print(json.dumps({"tests":len(rows),"outcomes":dict(counts),"suite_seconds":suite_seconds,"csv":str(args.csv),"figures":str(args.figures)},indent=2))


if __name__=="__main__": main()
