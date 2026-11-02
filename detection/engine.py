from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Configurable Parameters
CONFIG = {
    "variance_factor": 0.2,
    "min_packet_count": 10,
    "size_std_dev_threshold": 10.0,
    "min_session_duration": 10.0,
    "cv_threshold": 0.5,
    "unique_destinations_max": 1,
    "score_high": 9,
    "score_medium": 5
}

def evaluate_flow(f, debug=False):
    score = 0
    reasons = []
    
    if debug:
        console.print(f"[dim]Debug: Evaluating flow {f['flow']} with packet_count={f['packet_count']}, avg_interval={f['avg_interval']:.3f}, var={f['variance']:.3f}, cv={f['cv']:.3f}[/dim]")
    
    has_enough_packets = f["packet_count"] >= 5

    # 1. Variance Check
    if has_enough_packets and f["variance"] < (CONFIG["variance_factor"] * f["avg_interval"]):
        score += 3
        reasons.append(f"Low Variance (+3) [var={f['variance']:.4f} < {CONFIG['variance_factor'] * f['avg_interval']:.4f}]")
        
    # 2. Packet Count Check
    if f["packet_count"] >= CONFIG["min_packet_count"]:
        score += 3
        reasons.append(f"High Repetition (+3) [{f['packet_count']} pkts]")
        
    # 3. Packet Size Consistency
    if has_enough_packets and f["size_std_dev"] < CONFIG["size_std_dev_threshold"]:
        score += 2
        reasons.append(f"Consistent Pkt Size (+2) [stddev={f['size_std_dev']:.2f}]")
        
    # 4. Session Persistence
    if f["session_duration"] > CONFIG["min_session_duration"]:
        score += 2
        reasons.append(f"Long Session (+2) [{f['session_duration']:.2f}s]")
        
    # 5. Destination Diversity Feature
    if f["unique_destinations"] == CONFIG["unique_destinations_max"]:
        score += 2
        reasons.append(f"Single Destination (+2) [unique={f['unique_destinations']}]")
        
    # 6. Coefficient of Variation
    if has_enough_packets and f["cv"] < CONFIG["cv_threshold"]:
        score += 2
        reasons.append(f"Low CV (+2) [cv={f['cv']:.4f}]")
        
    if debug:
        console.print(f"[dim]Debug: Flow {f['flow']} received raw score {score}[/dim]")

    # Classification mapped directly to user specs
    if score >= CONFIG["score_high"]:
        alert_label = "Likely C2 Beacon"
        color = "red"
        level = "HIGH"
        summary = "This flow is classified as HIGH because multiple behavioral indicators (low variance, high repetition, single destination) match beaconing patterns."
    elif CONFIG["score_medium"] <= score < CONFIG["score_high"]:
        alert_label = "Suspicious Automated Traffic"
        color = "yellow"
        level = "MEDIUM"
        summary = "This flow is classified as MEDIUM due to some automated characteristics, but lacks strong periodic consistency."
    else:
        alert_label = "Normal Traffic"
        color = "green"
        level = "LOW"
        summary = "This flow is classified as LOW, showing high variability typical of normal background traffic or browsing."
        
    return {
        "score": score,
        "level": level,
        "label": alert_label,
        "color": color,
        "reasons": reasons,
        "summary": summary
    }

def print_limitations():
    limitation_text = (
        "[bold]Baseline vs Beacon Comparison:[/bold]\n"
        "[green]Normal Traffic:[/green] High variability, multiple destinations, bursty behavior.\n"
        "[red]Beacon Traffic:[/red] Low variability, single destination, consistent intervals.\n\n"
        "[bold]Detection Limitations:[/bold]\n"
        "- Encrypted traffic hides payload\n"
        "- High-randomness beaconing may evade detection\n"
        "- Legitimate automated services may resemble beaconing"
    )
    console.print(Panel(limitation_text, title="Baseline Comparison & Limitations", border_style="dim"))

def run_detection(features_list, debug=False):
    console.print()
    console.print("[bold cyan]=== BEHAVIORAL C2 DETECTION ENGINE ===[/bold cyan]")
    console.print("[italic]This system detects C2 beaconing using flow-based statistical analysis without inspecting payload content.[/italic]\n")
    
    if not features_list:
        console.print("[yellow]No analyzable flows found. Ensure captured traffic fits required ports and rules.[/yellow]")
        return
    
    for f in features_list:
        res = evaluate_flow(f, debug=debug)
        
        table = Table(title=f"Flow: {f['flow']} | Score: {res['score']}/14", show_header=False, box=None)
        table.add_column("Key", style="bold")
        table.add_column("Value")
        
        table.add_row("Classification", f"[{res['color']}]{res['level']} -> {res['label']}[/{res['color']}]")
        table.add_row("Avg Interval", f"{f['avg_interval']:.4f} sec")
        table.add_row("Variance", f"{f['variance']:.4f}")
        table.add_row("Std. Dev Interval", f"{f['std_dev']:.4f}")
        table.add_row("CV (Coef of Var)", f"{f['cv']:.4f}")
        table.add_row("Pkt Size StdDev", f"{f['size_std_dev']:.4f} bytes")
        table.add_row("Packets", str(f['packet_count']))
        table.add_row("Session Duration", f"{f['session_duration']:.2f} sec")
        table.add_row("Unique Destinations", str(f['unique_destinations']))
        
        rule_list = "\n".join([f"- {r}" for r in res["reasons"]])
        if not rule_list:
            rule_list = "No anomalies detected."
            
        panel = Panel(
            table, 
            subtitle=f"[bold]Summary:[/bold] {res['summary']}\n\n[bold]Rules Triggered:[/bold]\n{rule_list}", 
            subtitle_align="left",
            border_style=res["color"]
        )
        
        if res['level'] == 'HIGH':
            console.print("[bold red]⚠️ DETECTION TRIGGERED: Behavioral pattern matches beaconing characteristics ⚠️[/bold red]")
            
        console.print(panel)
        console.print()
        
    print_limitations()
