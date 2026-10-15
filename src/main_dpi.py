"""
CLI Entry Point for the Multi-Threaded DPI Engine Orchestrator.
File: src/main_dpi.py
"""
import sys
from dpi_engine import DPIEngine, EngineConfig


def print_usage(prog_name: str) -> None:
    print(f"""
+--------------------------------------------------------------+
|                    DPI ENGINE v1.0                           |
|             Deep Packet Inspection System                    |
+--------------------------------------------------------------+

Usage: python {prog_name} <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP (e.g. 192.168.1.50)
  --block-app <app>      Block application (e.g. YouTube, Facebook, Netflix)
  --block-domain <dom>   Block domain (e.g. *.facebook.com, google.com)
  --rules <file>         Load blocking rules from text configuration file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP worker threads per LB (default: 2)
  --verbose              Enable verbose logging
""")


def main():
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    config = EngineConfig()
    block_ips = []
    block_apps = []
    block_domains = []
    rules_file = ""

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            block_ips.append(sys.argv[i + 1])
            i += 2
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            block_apps.append(sys.argv[i + 1])
            i += 2
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            block_domains.append(sys.argv[i + 1])
            i += 2
        elif arg == "--rules" and i + 1 < len(sys.argv):
            rules_file = sys.argv[i + 1]
            i += 2
        elif arg == "--lbs" and i + 1 < len(sys.argv):
            config.num_load_balancers = int(sys.argv[i + 1])
            i += 2
        elif arg == "--fps" and i + 1 < len(sys.argv):
            config.fps_per_lb = int(sys.argv[i + 1])
            i += 2
        elif arg == "--verbose":
            config.verbose = True
            i += 1
        elif arg in ("--help", "-h"):
            print_usage(sys.argv[0])
            sys.exit(0)
        else:
            i += 1

    config.rules_file = rules_file
    engine = DPIEngine(config)

    if not engine.initialize():
        print("Failed to initialize DPI engine", file=sys.stderr)
        sys.exit(1)

    for ip in block_ips:
        engine.block_ip(ip)
    for app in block_apps:
        engine.block_app(app)
    for dom in block_domains:
        engine.block_domain(dom)

    if not engine.process_file(input_file, output_file):
        print("Failed to process file", file=sys.stderr)
        sys.exit(1)

    print("\nProcessing complete!")
    print(f"Sanitized output written to: {output_file}\n")


if __name__ == "__main__":
    main()