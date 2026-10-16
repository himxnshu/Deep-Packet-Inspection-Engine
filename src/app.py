"""
Kraken DPI Engine — Deep Packet Inspection & Traffic Policy Studio.
File: src/app.py

A handcrafted, beginner-friendly yet technically deep network traffic analyzer.
Inspired by the 'Stand Out' artistic theme: reaching deep beneath the surface
to unmask Layer-7 protocols, stream signatures, and network threats.
"""

import base64
import io
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

import altair as alt
import pandas as pd
import streamlit as st

from dpi_engine import DPIEngine, EngineConfig
from packet_parser import PacketParser
from pcap_reader import PcapReader
from types_dpi import (
    AppType,
    ConnectionState,
    PacketAction,
    app_type_to_string,
    ip_to_str,
    string_to_app_type,
)


# ============================================================================
# 1. PAGE CONFIGURATION & THEME ASSETS
# ============================================================================

st.set_page_config(
    page_title="Kraken DPI — Deep Packet Inspection",
    page_icon="🐙",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load user's artwork from assets
HERO_BG_PATH = os.path.join(os.path.dirname(__file__), "assets", "hero_tentacle_bg.jpg")
hero_bg_base64 = ""
if os.path.exists(HERO_BG_PATH):
    try:
        with open(HERO_BG_PATH, "rb") as img_file:
            hero_bg_base64 = base64.b64encode(img_file.read()).decode("utf-8")
    except Exception:
        pass


# ============================================================================
# 2. ARTISTIC, BESPOKE DESIGN SYSTEM (CSS)
# ============================================================================

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Fraunces:ital,opsz,wght@0,9..144,600;0,9..144,700;1,9..144,400&family=JetBrains+Mono:wght@400;500&display=swap');

    /* Global Typography & Atmospheric Background */
    html, body, [class*="css"] {{
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
        color: #F4EFE6;
    }}

    /* Full-Site Atmospheric Background with User's Tree Artwork */
    .stApp {{
        background: linear-gradient(180deg, 
            rgba(16, 23, 19, 0.78) 0%, 
            rgba(14, 21, 17, 0.88) 35%, 
            rgba(12, 18, 15, 0.95) 70%, 
            rgba(10, 15, 12, 0.98) 100%
        ),
        {f'url("data:image/jpeg;base64,{hero_bg_base64}")' if hero_bg_base64 else '#101613'} no-repeat center top fixed !important;
        background-size: cover !important;
    }}

    header[data-testid="stHeader"] {{
        background: transparent !important;
    }}

    [data-testid="stSidebar"] {{
        background: rgba(14, 21, 17, 0.92) !important;
        backdrop-filter: blur(20px) !important;
        -webkit-backdrop-filter: blur(20px) !important;
        border-right: 1px solid rgba(142, 168, 149, 0.22) !important;
    }}

    /* Frosted glass effects for cards so the trees show through softly */
    div[data-testid="stMetric"], .art-card, .story-box, .hero-banner {{
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
    }}

    code, pre, .mono {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    /* Main Content Container padding */
    .block-container {{
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1250px;
    }}

    /* Hero Banner with User Artwork */
    .hero-banner {{
        position: relative;
        border-radius: 22px;
        overflow: hidden;
        border: 1px solid rgba(217, 91, 61, 0.35);
        box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.6);
        background: rgba(22, 32, 26, 0.70);
        margin-bottom: 2rem;
    }}

    .hero-overlay {{
        background: linear-gradient(90deg, 
            rgba(16, 22, 19, 0.92) 0%, 
            rgba(16, 22, 19, 0.82) 45%, 
            rgba(16, 22, 19, 0.40) 80%, 
            rgba(16, 22, 19, 0.15) 100%
        );
        padding: 2.8rem 3rem;
        min-height: 240px;
    }}

    .hero-badge {{
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        background: rgba(217, 91, 61, 0.20);
        border: 1px solid rgba(217, 91, 61, 0.45);
        color: #E87A5D;
        font-weight: 600;
        font-size: 0.8rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 4px 14px;
        border-radius: 9999px;
        margin-bottom: 1rem;
    }}

    .hero-title {{
        font-family: 'Fraunces', Georgia, serif;
        font-size: 2.7rem;
        font-weight: 700;
        line-height: 1.15;
        color: #FBF8F3;
        margin-bottom: 0.8rem;
        letter-spacing: -0.02em;
    }}

    .hero-subtitle {{
        font-size: 1.08rem;
        line-height: 1.6;
        color: #B5C4BB;
        max-width: 650px;
        margin: 0;
    }}

    /* Card Containers - Fixed Uniform Height & Baseline Alignment */
    .art-card {{
        background: #17211C;
        border: 1px solid rgba(142, 168, 149, 0.16);
        border-radius: 16px;
        padding: 1.35rem 1.3rem;
        height: 185px;                     /* Uniform height across all 4 cards */
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        margin-bottom: 0.85rem;            /* Uniform spacing before the button */
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    }}
    .art-card:hover {{
        border-color: rgba(217, 91, 61, 0.5);
        box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.4);
    }}
    .art-card-active {{
        border-color: #D95B3D !important;
        background: #1D2A22 !important;
        box-shadow: 0 0 0 1px rgba(217, 91, 61, 0.4), 0 8px 20px -4px rgba(0, 0, 0, 0.4) !important;
    }}

    .art-card-header {{
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 0.4rem;
        height: 52px;                      /* Uniform title height across all cards */
        margin-bottom: 0.4rem;
    }}

    .art-card-title {{
        color: #FAF6EF;
        font-family: 'Fraunces', Georgia, serif;
        font-size: 1.10rem;
        font-weight: 700;
        margin: 0;
        line-height: 1.3;
        display: block;
        flex: 1;
        word-break: normal;
        white-space: normal;
    }}

    .art-card-active-pill {{
        background: rgba(217, 91, 61, 0.25);
        color: #E87A5D;
        border: 1px solid rgba(217, 91, 61, 0.45);
        padding: 2px 7px;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        white-space: nowrap;
    }}

    .art-card-desc {{
        color: #B2C2B8;
        font-size: 0.88rem;
        line-height: 1.5;
        margin: 0;
        height: 75px;                      /* Uniform description height across all cards */
        overflow: hidden;
        word-break: normal;
        white-space: normal;
    }}

    /* Metric Cards */
    div[data-testid="stMetric"] {{
        background: #17211C !important;
        border: 1px solid rgba(142, 168, 149, 0.18) !important;
        border-radius: 16px !important;
        padding: 1.2rem 1.4rem !important;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25) !important;
    }}
    div[data-testid="stMetric"]:hover {{
        border-color: #D95B3D !important;
    }}
    div[data-testid="stMetric"] label {{
        color: #9FB2A6 !important;
        font-size: 0.88rem !important;
        font-weight: 500 !important;
    }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{
        color: #FAF6EF !important;
        font-family: 'Fraunces', Georgia, serif !important;
        font-size: 2.0rem !important;
        font-weight: 700 !important;
    }}

    /* Plain-English Story Callout */
    .story-box {{
        background: linear-gradient(135deg, rgba(217, 91, 61, 0.12) 0%, rgba(30, 43, 36, 0.4) 100%);
        border-left: 4px solid #D95B3D;
        border-radius: 0 14px 14px 0;
        padding: 1.2rem 1.5rem;
        margin-bottom: 1.8rem;
        color: #EFE9DE;
        font-size: 1.02rem;
        line-height: 1.6;
    }}

    /* Pill Badges */
    .badge-allowed {{
        background: rgba(94, 158, 117, 0.16);
        color: #6EB887;
        padding: 3px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.78rem;
        border: 1px solid rgba(94, 158, 117, 0.3);
    }}
    .badge-blocked {{
        background: rgba(217, 91, 61, 0.18);
        color: #E87A5D;
        padding: 3px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.78rem;
        border: 1px solid rgba(217, 91, 61, 0.35);
    }}

    /* Buttons */
    div.stButton > button:first-child {{
        background: #D95B3D;
        color: #FFFFFF;
        border: none;
        border-radius: 10px;
        padding: 0.65rem 1.4rem;
        font-weight: 600;
        font-size: 0.95rem;
        box-shadow: 0 4px 12px rgba(217, 91, 61, 0.3);
        transition: all 0.2s ease;
    }}
    div.stButton > button:first-child:hover {{
        background: #E86D50;
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(217, 91, 61, 0.45);
        color: #FFFFFF;
    }}

    /* Secondary / Ghost button */
    div.stButton > button.secondary {{
        background: transparent !important;
        border: 1px solid #36483E !important;
        color: #B5C4BB !important;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 1.2rem;
        border-bottom: 1px solid #233129;
    }}
    .stTabs [data-baseweb="tab"] {{
        font-family: 'Plus Jakarta Sans', sans-serif;
        font-size: 0.96rem;
        font-weight: 600;
        padding: 0.75rem 1rem;
        color: #8CA093;
    }}
    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        color: #E87A5D !important;
        border-bottom-color: #E87A5D !important;
    }}
</style>
""", unsafe_allow_html=True)


# ============================================================================
# 3. SESSION STATE MANAGEMENT
# ============================================================================

if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None

if "filtered_pcap_bytes" not in st.session_state:
    st.session_state.filtered_pcap_bytes = None

if "current_pcap_name" not in st.session_state:
    st.session_state.current_pcap_name = None

if "raw_pcap_bytes" not in st.session_state:
    st.session_state.raw_pcap_bytes = None

if "scenario_name" not in st.session_state:
    st.session_state.scenario_name = "Custom Configuration"


# ============================================================================
# 4. PIPELINE EXECUTION ENGINE
# ============================================================================

def execute_pipeline(
    pcap_bytes: bytes,
    file_label: str,
    scenario_label: str = "Custom Run",
    block_ips: List[str] = None,
    block_domains: List[str] = None,
    block_apps: List[str] = None,
    lbs: int = 2,
    fps: int = 2,
) -> None:
    """Run multi-threaded inspection and store all analytical state in memory."""
    block_ips = block_ips or []
    block_domains = block_domains or []
    block_apps = block_apps or []

    temp_input = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    temp_output = tempfile.NamedTemporaryFile(delete=False, suffix="_filtered.pcap")

    try:
        temp_input.write(pcap_bytes)
        temp_input.close()
        temp_output.close()

        config = EngineConfig(num_load_balancers=lbs, fps_per_lb=fps)
        engine = DPIEngine(config)
        engine.initialize()

        # Enforce rules
        for ip in block_ips:
            engine.block_ip(ip)
        for dom in block_domains:
            engine.block_domain(dom)
        for app in block_apps:
            engine.block_app(app)

        start_time = time.time()
        success = engine.process_file(temp_input.name, temp_output.name)
        elapsed_sec = time.time() - start_time

        if not success:
            st.error("Inspection engine encountered an error parsing the PCAP file.")
            return

        with open(temp_output.name, "rb") as f:
            sanitized_bytes = f.read()

        global_stats = engine.global_conn_table.get_global_stats()

        # Build Flow records
        flow_records = []
        for fp in engine.fp_manager.fps:
            for conn in fp.conn_tracker.get_all_connections():
                flow_records.append({
                    "Source": f"{conn.tuple.src_ip_str}:{conn.tuple.src_port}",
                    "Destination": f"{conn.tuple.dst_ip_str}:{conn.tuple.dst_port}",
                    "Protocol": conn.tuple.protocol_name,
                    "Application": app_type_to_string(conn.app_type),
                    "Host / SNI": conn.sni if conn.sni else "-",
                    "Status": "BLOCKED" if conn.state == ConnectionState.BLOCKED else "ALLOWED",
                    "Packets Out": conn.packets_out,
                    "Packets In": conn.packets_in,
                    "Total Bytes": conn.total_bytes,
                    "Worker Core": f"Core-{fp.fp_id}",
                })

        # Build Worker records
        lb_records = []
        for lb in engine.lb_manager.lbs:
            stats = lb.get_stats()
            lb_records.append({
                "Load Balancer": f"LB-{lb.lb_id}",
                "Packets Dispatched": stats.packets_dispatched,
            })

        fp_records = []
        for fp in engine.fp_manager.fps:
            stats = fp.get_stats()
            fp_records.append({
                "Worker Core": f"Core-{fp.fp_id}",
                "Processed": stats.packets_processed,
                "Forwarded": stats.packets_forwarded,
                "Dropped": stats.packets_dropped,
                "SNI Extracted": stats.sni_extractions,
            })

        st.session_state.pipeline_results = {
            "elapsed_ms": elapsed_sec * 1000,
            "total_packets": engine.stats.total_packets,
            "forwarded_packets": engine.stats.forwarded_packets,
            "dropped_packets": engine.stats.dropped_packets,
            "total_bytes": engine.stats.total_bytes,
            "tcp_packets": engine.stats.tcp_packets,
            "udp_packets": engine.stats.udp_packets,
            "active_flows": global_stats.total_active_connections,
            "app_distribution": global_stats.app_distribution,
            "top_domains": global_stats.top_domains,
            "flow_records": flow_records,
            "lb_records": lb_records,
            "fp_records": fp_records,
            "rule_stats": engine.rule_manager.get_stats(),
            "blocked_ips": engine.rule_manager.get_blocked_ips(),
            "blocked_domains": engine.rule_manager.get_blocked_domains(),
            "blocked_apps": [app_type_to_string(a) for a in engine.rule_manager.get_blocked_apps()],
            "blocked_ports": engine.rule_manager.get_blocked_ports(),
        }
        st.session_state.filtered_pcap_bytes = sanitized_bytes
        st.session_state.current_pcap_name = file_label
        st.session_state.raw_pcap_bytes = pcap_bytes
        st.session_state.scenario_name = scenario_label

    finally:
        if os.path.exists(temp_input.name):
            try: os.remove(temp_input.name)
            except Exception: pass
        if os.path.exists(temp_output.name):
            try: os.remove(temp_output.name)
            except Exception: pass


# ============================================================================
# 5. SIDEBAR: ADVANCED TUNING & CUSTOM POLICY
# ============================================================================

with st.sidebar:
    st.markdown("### ⚙️ Deep Controls")
    st.caption("Custom policy definitions & multi-core worker tuning.")
    st.markdown("---")

    st.subheader("⚡ Concurrency Threads")
    sb_num_lbs = st.slider("Load Balancers (LB)", min_value=1, max_value=8, value=2, step=1)
    sb_fps_per_lb = st.slider("Cores per LB (FP)", min_value=1, max_value=8, value=2, step=1)
    sb_total_fps = sb_num_lbs * sb_fps_per_lb
    st.caption(f"Total Inspection Worker Threads: **{sb_total_fps}**")

    st.markdown("---")
    st.subheader("🎯 Custom Filter Rules")

    custom_ips = st.text_input("Block IP Addresses", "192.168.1.50", help="Comma-separated IPs to drop")
    custom_domains = st.text_input("Block Domains", "*.facebook.com", help="Wildcards supported (e.g. *.google.com)")

    available_apps = [
        "YouTube", "Netflix", "Facebook", "Instagram", "Twitter",
        "TikTok", "Amazon", "Google", "Discord", "Spotify", "GitHub", "Zoom", "Apple"
    ]
    custom_apps = st.multiselect("Block Applications", available_apps, default=["YouTube"])

    if st.button("Apply Custom Filter", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                raw_bytes = f.read()
            ips = [x.strip() for x in custom_ips.split(",") if x.strip()]
            doms = [x.strip() for x in custom_domains.split(",") if x.strip()]
            execute_pipeline(
                raw_bytes,
                "test_dpi.pcap",
                scenario_label="Custom User Policy",
                block_ips=ips,
                block_domains=doms,
                block_apps=custom_apps,
                lbs=sb_num_lbs,
                fps=sb_fps_per_lb,
            )
            st.rerun()

    st.markdown("---")
    if st.button("🧹 Reset Dashboard", use_container_width=True):
        st.session_state.pipeline_results = None
        st.session_state.filtered_pcap_bytes = None
        st.session_state.current_pcap_name = None
        st.session_state.raw_pcap_bytes = None
        st.rerun()


# ============================================================================
# 6. HERO BANNER (ARTWORK EMBEDDED)
# ============================================================================

st.markdown("""
<div class="hero-banner">
    <div class="hero-overlay">
        <div class="hero-badge">🐙 Deep Packet Inspection Engine</div>
        <div class="hero-title">Reach Deep into Network Traffic</div>
        <p class="hero-subtitle">
            Ordinary firewalls only skim the surface (IP and Port). 
            Our multi-threaded engine dives deep into packet payloads — extracting TLS Server Name Indications (SNI), 
            HTTP hosts, and DNS queries to enforce application-level policy in real-time.
        </p>
    </div>
</div>
""", unsafe_allow_html=True)


# ============================================================================
# 7. BEGINNER ONBOARDING & GUIDED EXPERIMENT PLAYGROUND
# ============================================================================

# Quick 30-Second Explainer Accordion
with st.expander("🌱 **New to Network Analysis? Read the 30-Second Guide**", expanded=(st.session_state.pipeline_results is None)):
    st.markdown("""
    Networking jargon can sound intimidating, but the concept is simple:
    
    1. **Packets are like sealed envelopes** flying across internet cables millions of times per second.
    2. **Traditional Firewalls only look at the outside address** (Source IP & Port). If an envelope is addressed to Port 443 (HTTPS), they let it pass — without knowing if it's work-related Google Docs or 4K YouTube streaming.
    3. **Deep Packet Inspection (DPI) opens the envelope.** It peeks at the unencrypted TLS handshake (*Server Name Indication / SNI*) to identify the exact website or service inside.
    4. **Smart Enforcement:** If YouTube is blocked by policy, our worker threads drop the packet immediately. If safe, it's forwarded to its destination.
    """)

st.markdown("### 🧪 Choose an Experiment Scenario")
st.caption("Click any scenario below to see how the DPI engine inspects and filters traffic in real-time:")

def make_card_html(title: str, desc: str, is_active: bool) -> str:
    cls_name = "art-card art-card-active" if is_active else "art-card"
    pill_html = '<span class="art-card-active-pill">ACTIVE</span>' if is_active else ''
    return (
        f'<div class="{cls_name}">'
        f'<div class="art-card-header">'
        f'<div class="art-card-title">{title}</div>'
        f'{pill_html}'
        f'</div>'
        f'<div class="art-card-desc">{desc}</div>'
        f'</div>'
    )

exp1, exp2, exp3, exp4 = st.columns(4)

# Determine currently active scenario for visual indicators
curr_scen = st.session_state.scenario_name or ""
is_act1 = "Office Focus" in curr_scen
is_act2 = "Social Media" in curr_scen or "Cafe Social" in curr_scen
is_act3 = "Threat Quarantine" in curr_scen
is_act4 = "Deep Ocean" in curr_scen

# Scenario 1: Office Hours
with exp1:
    st.markdown(
        make_card_html(
            "🏢 Office Focus Mode",
            "Block bandwidth-heavy video streaming like YouTube and Netflix during working hours.",
            is_act1,
        ),
        unsafe_allow_html=True,
    )
    btn_label_1 = "● Active (Re-run 🚀)" if is_act1 else "Run Office Mode 🚀"
    if st.button(btn_label_1, key="btn_office", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                data = f.read()
            execute_pipeline(
                data,
                "test_dpi.pcap",
                scenario_label="🏢 Office Focus (Block Video Streaming)",
                block_apps=["YouTube", "Netflix"],
                block_domains=["*.googlevideo.com", "*.nflxvideo.net"],
            )
            st.rerun()

# Scenario 2: Social Media Shield
with exp2:
    st.markdown(
        make_card_html(
            "☕ Cafe Social Shield",
            "Filter distracting social media apps including Facebook, Instagram, Twitter/X, and TikTok.",
            is_act2,
        ),
        unsafe_allow_html=True,
    )
    btn_label_2 = "● Active (Re-run 🚀)" if is_act2 else "Block Social Apps 🚀"
    if st.button(btn_label_2, key="btn_social", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                data = f.read()
            execute_pipeline(
                data,
                "test_dpi.pcap",
                scenario_label="☕ Cafe Social Shield",
                block_apps=["Facebook", "Instagram", "Twitter", "TikTok"],
                block_domains=["*.facebook.com", "*.instagram.com"],
            )
            st.rerun()

# Scenario 3: Malware Threat Hunter
with exp3:
    st.markdown(
        make_card_html(
            "🛡️ Threat Quarantine",
            "Neutralize compromised host at IP 192.168.1.50 and drop all its suspicious network packets.",
            is_act3,
        ),
        unsafe_allow_html=True,
    )
    btn_label_3 = "● Active (Re-run 🚀)" if is_act3 else "Quarantine IP 🚀"
    if st.button(btn_label_3, key="btn_threat", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                data = f.read()
            execute_pipeline(
                data,
                "test_dpi.pcap",
                scenario_label="🛡️ Threat Quarantine (Rogue IP 192.168.1.50)",
                block_ips=["192.168.1.50"],
            )
            st.rerun()

# Scenario 4: Deep Sea Observer
with exp4:
    st.markdown(
        make_card_html(
            "🌊 Deep Ocean Scan",
            "Permit all network traffic while deeply mapping every hidden application, domain, and flow.",
            is_act4,
        ),
        unsafe_allow_html=True,
    )
    btn_label_4 = "● Active (Re-run 🚀)" if is_act4 else "Observe All 🚀"
    if st.button(btn_label_4, key="btn_observe", use_container_width=True):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        if os.path.exists(sample_path):
            with open(sample_path, "rb") as f:
                data = f.read()
            execute_pipeline(
                data,
                "test_dpi.pcap",
                scenario_label="🌊 Deep Ocean Scan (Observe & Map All)",
                block_apps=[],
                block_ips=[],
                block_domains=[],
            )
            st.rerun()

st.markdown("---")


# ============================================================================
# 8. OR UPLOAD CUSTOM PCAP
# ============================================================================

with st.expander("📁 **Or Upload Your Own Custom Capture File (.pcap)**"):
    uploaded_file = st.file_uploader("Upload a capture from Wireshark or tcpdump:", type=["pcap"])
    if uploaded_file is not None:
        if (
            st.session_state.current_pcap_name != uploaded_file.name
            or st.session_state.pipeline_results is None
        ):
            file_bytes = uploaded_file.read()
            with st.spinner("Analyzing Uploaded PCAP..."):
                execute_pipeline(
                    file_bytes,
                    uploaded_file.name,
                    scenario_label=f"User Upload ({uploaded_file.name})",
                    block_ips=[x.strip() for x in custom_ips.split(",") if x.strip()],
                    block_domains=[x.strip() for x in custom_domains.split(",") if x.strip()],
                    block_apps=custom_apps,
                )
            st.rerun()


# ============================================================================
# 9. RESULTS VIEW & STORY REPORT
# ============================================================================

results = st.session_state.pipeline_results

if results:
    total_pkts = results['total_packets']
    dropped_pkts = results['dropped_packets']
    forwarded_pkts = results['forwarded_packets']
    drop_pct = (100.0 * dropped_pkts / total_pkts) if total_pkts > 0 else 0.0

    # Plain-English Story Summary
    st.markdown(f"""
    <div class="story-box">
        <strong>🐙 Scenario Report: {st.session_state.scenario_name}</strong><br>
        The Kraken DPI engine intercepted <strong>{total_pkts:,} network packets</strong> across <strong>{results['active_flows']} distinct conversations</strong> in <strong>{results['elapsed_ms']:.2f} ms</strong>.<br>
        • <strong>{dropped_pkts:,} packets ({drop_pct:.1f}%)</strong> were <span class="badge-blocked">BLOCKED</span> because they violated active filtering policies.<br>
        • <strong>{forwarded_pkts:,} safe packets</strong> were <span class="badge-allowed">FORWARDED</span> cleanly to their internet destinations.
    </div>
    """, unsafe_allow_html=True)

    # Core Metrics
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Packets Intercepted", f"{total_pkts:,}")
    m2.metric("Safe Packets Allowed", f"{forwarded_pkts:,}")
    m3.metric("Threats / Drops", f"{dropped_pkts:,}", delta=f"{drop_pct:.1f}% drop rate", delta_color="inverse")
    m4.metric("Active Conversations", f"{results['active_flows']:,}")
    m5.metric("Data Examined", f"{results['total_bytes'] / 1024:.1f} KB")

    st.markdown("---")

    # Analytical Views
    tab_story, tab_flows, tab_engine, tab_tester, tab_download = st.tabs([
        "📊 Applications & Domains",
        "🌐 Flow Explorer (Conversations)",
        "⚡ Multi-Core Engine Stats",
        "🧪 Interactive Rule Sandbox",
        "💾 Download Clean PCAP",
    ])

    # ------------------------------------------------------------------------
    # TAB 1: APPLICATIONS & DOMAINS
    # ------------------------------------------------------------------------
    with tab_story:
        col_chart, col_domains = st.columns([3, 2])

        app_dist = results["app_distribution"]
        if app_dist:
            df_apps = pd.DataFrame([
                {"Application": app_type_to_string(app), "Conversations": count}
                for app, count in app_dist.items()
            ]).sort_values(by="Conversations", ascending=False)

            with col_chart:
                st.subheader("Identified Apps & Protocols")
                st.caption("Extracted from unencrypted TLS Server Name Indications (SNI) and HTTP Host headers.")

                chart = alt.Chart(df_apps).mark_bar(cornerRadius=6, color="#D95B3D").encode(
                    x=alt.X("Conversations:Q", title="Number of Connections"),
                    y=alt.Y("Application:N", sort="-x", title="Service"),
                    tooltip=["Application", "Conversations"]
                ).properties(height=340)
                st.altair_chart(chart, use_container_width=True)

            with col_domains:
                st.subheader("Top Intercepted Hostnames")
                st.caption("Exact domains extracted from packet payloads:")
                if results["top_domains"]:
                    df_domains = pd.DataFrame(results["top_domains"], columns=["Domain / Host", "Hit Count"])
                    st.dataframe(df_domains, use_container_width=True, hide_index=True, height=340)
                else:
                    st.info("No hostnames extracted in this traffic.")
        else:
            st.info("No connections were classified in this traffic.")

    # ------------------------------------------------------------------------
    # TAB 2: FLOW EXPLORER
    # ------------------------------------------------------------------------
    with tab_flows:
        st.subheader("Active Network Conversations (Flows)")
        st.caption("A flow is a conversation between two devices identified by its 5-tuple: (Source IP, Dest IP, Source Port, Dest Port, Protocol).")

        flows = results["flow_records"]
        if flows:
            df_flows = pd.DataFrame(flows)

            fc1, fc2, fc3 = st.columns([2, 2, 2])
            with fc1:
                search_q = st.text_input("🔍 Search IP, Domain, Port", "")
            with fc2:
                status_filter = st.selectbox("Filter Status", ["All", "ALLOWED", "BLOCKED"], index=0)
            with fc3:
                app_options = ["All"] + sorted(list(df_flows["Application"].unique()))
                selected_app = st.selectbox("Filter Application", app_options, index=0)

            filtered = df_flows
            if search_q:
                q = search_q.lower()
                filtered = filtered[
                    filtered["Source"].str.lower().str.contains(q)
                    | filtered["Destination"].str.lower().str.contains(q)
                    | filtered["Host / SNI"].str.lower().str.contains(q)
                ]
            if status_filter != "All":
                filtered = filtered[filtered["Status"] == status_filter]
            if selected_app != "All":
                filtered = filtered[filtered["Application"] == selected_app]

            st.caption(f"Showing **{len(filtered)}** of **{len(df_flows)}** conversations.")
            st.dataframe(filtered, use_container_width=True, hide_index=True, height=450)
        else:
            st.info("No flow records available.")

    # ------------------------------------------------------------------------
    # TAB 3: MULTI-CORE ENGINE STATS
    # ------------------------------------------------------------------------
    with tab_engine:
        st.subheader("Multi-Core Concurrency & Flow Hashing")
        st.caption(
            "Packets are assigned to worker threads using **Consistent 5-Tuple Canonical Hashing**.\n"
            "This guarantees all packets in both directions of a conversation reach the same worker thread without cross-thread lock contention."
        )

        col_lbs, col_fps = st.columns(2)

        with col_lbs:
            st.markdown("#### ⚡ Load Balancer Dispatchers")
            df_lbs = pd.DataFrame(results["lb_records"])
            st.dataframe(df_lbs, use_container_width=True, hide_index=True)

        with col_fps:
            st.markdown("#### 🛡️ Fast Path Inspection Cores")
            df_fps = pd.DataFrame(results["fp_records"])
            st.dataframe(df_fps, use_container_width=True, hide_index=True)

    # ------------------------------------------------------------------------
    # TAB 4: INTERACTIVE RULE SANDBOX
    # ------------------------------------------------------------------------
    with tab_tester:
        st.subheader("🧪 Interactive Policy Sandbox")
        st.caption("Test how current filtering rules would react to any theoretical packet attributes.")

        t_col1, t_col2 = st.columns(2)

        with t_col1:
            st.markdown("#### Active Rule List")
            st.write("**Blocked IPs:**", results["blocked_ips"] or "*(None)*")
            st.write("**Blocked Domains:**", results["blocked_domains"] or "*(None)*")
            st.write("**Blocked Apps:**", results["blocked_apps"] or "*(None)*")

        with t_col2:
            st.markdown("#### Test Packet Input")
            test_ip = st.text_input("Source IP to test", "192.168.1.50")
            test_dom = st.text_input("Domain to test", "www.facebook.com")
            test_app = st.selectbox("App to test", ["None"] + available_apps)

            if st.button("Evaluate Test Packet ⚡"):
                drop = False
                reasons = []

                if test_ip.strip() in results["blocked_ips"]:
                    drop = True
                    reasons.append(f"IP `{test_ip}` is in the blocked IP list.")

                clean_dom = test_dom.strip().lower()
                for pat in results["blocked_domains"]:
                    cp = pat.replace("*.", "").lower()
                    if cp in clean_dom or clean_dom.endswith(cp):
                        drop = True
                        reasons.append(f"Domain `{test_dom}` matches pattern `{pat}`.")

                if test_app in results["blocked_apps"]:
                    drop = True
                    reasons.append(f"Application `{test_app}` is in the blocked application list.")

                if drop:
                    st.error("🛑 **DECISION: DROP PACKET**")
                    for r in reasons:
                        st.markdown(f"- {r}")
                else:
                    st.success("✅ **DECISION: PERMIT PACKET** (No policy violations)")

    # ------------------------------------------------------------------------
    # TAB 5: DOWNLOAD SANITIZED PCAP
    # ------------------------------------------------------------------------
    with tab_download:
        st.subheader("💾 Download Sanitized Network Capture")
        st.markdown(
            "Every packet that violated your policy has been stripped out. "
            "You can download the resulting clean PCAP to inspect in Wireshark or replay into your network."
        )

        out_data = st.session_state.filtered_pcap_bytes
        if out_data:
            col_d1, col_d2 = st.columns([2, 1])
            with col_d1:
                st.markdown(f"""
                - **File:** `sanitized_{st.session_state.current_pcap_name}`
                - **Packets Preserved:** `{forwarded_pkts:,}` of `{total_pkts:,}`
                - **Packets Dropped:** `{dropped_pkts:,}` ({drop_pct:.1f}%)
                - **File Size:** `{len(out_data):,} bytes`
                """)
            with col_d2:
                st.download_button(
                    label="📥 Download Clean PCAP",
                    data=out_data,
                    file_name=f"sanitized_{st.session_state.current_pcap_name or 'traffic.pcap'}",
                    mime="application/vnd.tcpdump.pcap",
                    use_container_width=True,
                )


# ============================================================================
# VERCEL COMPATIBILITY EXPORTS (Fallback WSGI / ASGI handler)
# ============================================================================
def app(environ, start_response):
    status = "200 OK"
    headers = [("Content-Type", "text/html; charset=utf-8")]
    start_response(status, headers)
    return [b"<h1>Kraken DPI Engine</h1><p>Interactive dashboard requires persistent WebSockets. Please run: streamlit run src/app.py</p>"]

application = app
handler = app