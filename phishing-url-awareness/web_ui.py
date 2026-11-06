#!/usr/bin/env python3
"""
Web UI Server for Phishing URL Awareness Checker
-------------------------------------------------------------------------
Author: Cybersecurity Student / Project Developer
Project: EWB Edutech Cybersecurity Mini Project
Technology: Python 3.10+ (Standard Library: http.server, urllib, json)

This module provides a modern, responsive, cyber-themed browser interface
for the Phishing URL Awareness Checker without requiring external frameworks
(like Flask or Django) or GUI bindings (like Tkinter/PyQt).

Features:
  - 100% Offline (Self-contained CSS/JS/SVG, zero external CDN dependencies)
  - Multi-factor Intelligent Risk Scoring (0-100 pts)
  - Trusted Domain Recognition (Official domain matching vs spoofing)
  - Single URL Analysis with risk meter, metrics, and educational cards
  - Batch URL Inspector with comprehensive summary table
  - Automated Realistic & Workbook Test Suite (15 live verification tests)
  - Strict local execution (zero network requests to target URLs)
-------------------------------------------------------------------------
"""

import sys
import json
import socket
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Import core detection logic and test suite from phishing_checker
from phishing_checker import analyze_url, SAMPLE_TEST_CASES


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing URL Awareness Checker</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-hover: #162032;
      --border: #1f2937;
      --border-focus: #38bdf8;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #0284c7;
      --primary-hover: #0369a1;
      --cyan: #38bdf8;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --dark-red: #be123c;
      --slate: #64748b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.5;
    }

    /* Header & Navigation */
    header {
      background: linear-gradient(180deg, #111827 0%, rgba(17, 24, 39, 0.8) 100%);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(8px);
    }

    .header-container {
      max-width: 1100px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand-icon {
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      width: 42px;
      height: 42px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.35);
    }

    .brand-icon svg {
      width: 24px;
      height: 24px;
      fill: none;
      stroke: white;
      stroke-width: 2;
    }

    .brand-text h1 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      color: #ffffff;
    }

    .brand-text p {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--emerald);
      padding: 0.3rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--emerald);
      box-shadow: 0 0 8px var(--emerald);
    }

    /* Main Container */
    main {
      flex: 1;
      max-width: 1100px;
      width: 100%;
      margin: 2rem auto;
      padding: 0 1.5rem;
    }

    /* Tabs */
    .tabs-bar {
      display: flex;
      gap: 0.5rem;
      background: rgba(17, 24, 39, 0.7);
      border: 1px solid var(--border);
      padding: 0.35rem;
      border-radius: 12px;
      margin-bottom: 1.75rem;
      overflow-x: auto;
    }

    .tab-btn {
      flex: 1;
      min-width: 160px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.65rem 1rem;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    .tab-btn.active {
      background: var(--primary);
      color: #ffffff;
      box-shadow: 0 2px 8px rgba(2, 132, 199, 0.4);
    }

    .tab-btn:hover:not(.active) {
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
    }

    .tab-content {
      display: none;
    }

    .tab-content.active {
      display: block;
      animation: fadeIn 0.25s ease-in-out;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Card Panels */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }

    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: #ffffff;
    }

    .card-desc {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 1.25rem;
    }

    /* Input Controls */
    .input-group {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }

    .url-input {
      flex: 1;
      min-width: 280px;
      background: #090d16;
      border: 1px solid var(--border);
      color: #ffffff;
      padding: 0.85rem 1.15rem;
      border-radius: 10px;
      font-size: 0.95rem;
      font-family: monospace;
      outline: none;
      transition: all 0.2s ease;
    }

    .url-input:focus {
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }

    .btn {
      background: var(--primary);
      color: #ffffff;
      border: none;
      padding: 0.85rem 1.5rem;
      border-radius: 10px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    .btn:hover {
      background: var(--primary-hover);
      box-shadow: 0 0 15px rgba(2, 132, 199, 0.4);
    }

    .btn-secondary {
      background: #1f2937;
      color: var(--text-muted);
    }

    .btn-secondary:hover {
      background: #374151;
      color: #ffffff;
      box-shadow: none;
    }

    /* Quick Samples Pill Row */
    .samples-row {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
    }

    .samples-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-right: 0.25rem;
    }

    .sample-pill {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      color: var(--cyan);
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-family: monospace;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .sample-pill:hover {
      background: rgba(56, 189, 248, 0.15);
      border-color: var(--cyan);
      color: #ffffff;
    }

    .sample-pill.pill-verified {
      color: var(--emerald);
      border-color: rgba(16, 185, 129, 0.3);
    }
    .sample-pill.pill-verified:hover {
      background: rgba(16, 185, 129, 0.15);
      border-color: var(--emerald);
    }

    /* Result Banner & Stats */
    .results-container {
      display: none;
      animation: fadeIn 0.3s ease;
    }

    .risk-banner {
      padding: 1.25rem 1.5rem;
      border-radius: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 1rem;
      border: 1px solid transparent;
    }

    .risk-banner.safe {
      background: rgba(16, 185, 129, 0.12);
      border-color: rgba(16, 185, 129, 0.35);
      color: var(--emerald);
    }

    .risk-banner.moderate {
      background: rgba(245, 158, 11, 0.12);
      border-color: rgba(245, 158, 11, 0.35);
      color: var(--amber);
    }

    .risk-banner.high {
      background: rgba(244, 63, 94, 0.15);
      border-color: rgba(244, 63, 94, 0.4);
      color: var(--rose);
    }

    .risk-banner.critical {
      background: rgba(190, 18, 60, 0.2);
      border-color: rgba(244, 63, 94, 0.6);
      color: #fda4af;
      box-shadow: 0 0 20px rgba(190, 18, 60, 0.25);
    }

    .risk-title-box h3 {
      font-size: 1.35rem;
      font-weight: 800;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .risk-title-box p {
      font-size: 0.85rem;
      opacity: 0.85;
      margin-top: 0.2rem;
    }

    .risk-badge-box {
      font-size: 0.85rem;
      font-weight: 700;
      padding: 0.4rem 1rem;
      border-radius: 9999px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid currentColor;
      text-align: right;
    }

    /* Action Banner */
    .action-box {
      background: #0d131f;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .action-box.act-safe { border-left: 4px solid var(--emerald); }
    .action-box.act-moderate { border-left: 4px solid var(--amber); }
    .action-box.act-high { border-left: 4px solid var(--rose); }
    .action-box.act-critical { border-left: 4px solid var(--dark-red); }

    .action-label {
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .action-text {
      font-size: 0.9rem;
      font-weight: 600;
      color: #ffffff;
    }

    /* Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }

    .metric-card {
      background: #0d131f;
      border: 1px solid var(--border);
      padding: 1rem;
      border-radius: 10px;
    }

    .metric-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.3rem;
    }

    .metric-value {
      font-size: 1.05rem;
      font-weight: 700;
      color: #ffffff;
      font-family: monospace;
      word-break: break-all;
    }

    /* Warning Signs List */
    .warnings-header {
      font-size: 1rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .warning-card {
      background: #0d131f;
      border: 1px solid var(--border);
      border-left: 4px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      margin-bottom: 0.85rem;
      transition: all 0.2s ease;
    }

    .warning-card.sev-CRITICAL {
      border-left-color: var(--dark-red);
      background: linear-gradient(90deg, rgba(190, 18, 60, 0.1) 0%, #0d131f 100%);
    }

    .warning-card.sev-HIGH {
      border-left-color: var(--rose);
      background: linear-gradient(90deg, rgba(244, 63, 94, 0.05) 0%, #0d131f 100%);
    }

    .warning-card.sev-MODERATE {
      border-left-color: var(--amber);
      background: linear-gradient(90deg, rgba(245, 158, 11, 0.05) 0%, #0d131f 100%);
    }

    .warning-card.sev-LOW {
      border-left-color: var(--cyan);
      background: linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, #0d131f 100%);
    }

    .warning-card.sev-INFORMATIONAL {
      border-left-color: var(--slate);
      background: linear-gradient(90deg, rgba(100, 116, 139, 0.05) 0%, #0d131f 100%);
    }

    .warning-title {
      font-weight: 700;
      font-size: 0.95rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.4rem;
      color: #ffffff;
    }

    .sev-pill {
      font-size: 0.65rem;
      font-weight: 800;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
    }

    .sev-CRITICAL .sev-pill {
      background: rgba(190, 18, 60, 0.3);
      color: #fda4af;
      border: 1px solid var(--rose);
    }

    .sev-HIGH .sev-pill {
      background: rgba(244, 63, 94, 0.2);
      color: var(--rose);
      border: 1px solid var(--rose);
    }

    .sev-MODERATE .sev-pill {
      background: rgba(245, 158, 11, 0.2);
      color: var(--amber);
      border: 1px solid var(--amber);
    }

    .sev-LOW .sev-pill {
      background: rgba(56, 189, 248, 0.2);
      color: var(--cyan);
      border: 1px solid var(--cyan);
    }

    .sev-INFORMATIONAL .sev-pill {
      background: rgba(100, 116, 139, 0.2);
      color: #cbd5e1;
      border: 1px solid var(--slate);
    }

    .warning-finding {
      font-size: 0.85rem;
      color: #e2e8f0;
      margin-bottom: 0.5rem;
    }

    .warning-explanation {
      font-size: 0.8rem;
      color: var(--text-muted);
      background: rgba(0, 0, 0, 0.3);
      padding: 0.6rem 0.85rem;
      border-radius: 6px;
      border-left: 2px solid var(--slate);
    }

    .clean-state {
      padding: 2rem;
      text-align: center;
      background: rgba(16, 185, 129, 0.05);
      border: 1px dashed rgba(16, 185, 129, 0.3);
      border-radius: 10px;
    }

    .clean-state h4 {
      color: var(--emerald);
      font-size: 1.1rem;
      margin-bottom: 0.35rem;
    }

    .clean-state p {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    /* Security Advisory Notice */
    .advisory-box {
      margin-top: 1.5rem;
      background: rgba(245, 158, 11, 0.07);
      border: 1px solid rgba(245, 158, 11, 0.25);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      display: flex;
      gap: 0.75rem;
      align-items: flex-start;
    }

    .advisory-box svg {
      width: 22px;
      height: 22px;
      stroke: var(--amber);
      flex-shrink: 0;
      margin-top: 2px;
    }

    .advisory-text h5 {
      color: var(--amber);
      font-size: 0.85rem;
      font-weight: 700;
      margin-bottom: 0.2rem;
    }

    .advisory-text p {
      font-size: 0.8rem;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Batch Analysis View */
    .textarea-input {
      width: 100%;
      height: 150px;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 10px;
      color: #ffffff;
      padding: 0.85rem;
      font-family: monospace;
      font-size: 0.85rem;
      resize: vertical;
      margin-bottom: 1rem;
      outline: none;
    }

    .textarea-input:focus {
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }

    /* Tables */
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #0d131f;
      margin-top: 1rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }

    th {
      background: #111827;
      padding: 0.75rem 1rem;
      color: var(--text-muted);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text);
    }

    tr:last-child td {
      border-bottom: none;
    }

    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .tag {
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.2rem 0.5rem;
      border-radius: 9999px;
      display: inline-block;
      white-space: nowrap;
    }

    .tag.pass {
      background: rgba(16, 185, 129, 0.2);
      color: var(--emerald);
      border: 1px solid var(--emerald);
    }

    .tag.critical {
      background: rgba(190, 18, 60, 0.3);
      color: #fda4af;
      border: 1px solid var(--rose);
    }

    .tag.high {
      background: rgba(244, 63, 94, 0.2);
      color: var(--rose);
      border: 1px solid var(--rose);
    }

    .tag.moderate {
      background: rgba(245, 158, 11, 0.2);
      color: var(--amber);
      border: 1px solid var(--amber);
    }

    .tag.safe {
      background: rgba(16, 185, 129, 0.2);
      color: var(--emerald);
      border: 1px solid var(--emerald);
    }

    /* Footer */
    footer {
      border-top: 1px solid var(--border);
      padding: 1.5rem 2rem;
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: auto;
    }
  </style>
</head>
<body>

  <!-- Top Header -->
  <header>
    <div class="header-container">
      <div class="brand">
        <div class="brand-icon">
          <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="brand-text">
          <h1>Phishing URL Awareness Checker</h1>
          <p>EWB Edutech Cybersecurity Mini Project • Intelligent Multi-Factor Analysis</p>
        </div>
      </div>
      <div class="status-badge">
        <span class="status-dot"></span>
        <span>Local Detection Engine Active</span>
      </div>
    </div>
  </header>

  <!-- Main Workspace -->
  <main>
    <!-- Navigation Tabs -->
    <div class="tabs-bar">
      <button class="tab-btn active" onclick="switchTab('single')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        Single URL Analyzer
      </button>
      <button class="tab-btn" onclick="switchTab('batch')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
        Batch URL Inspector
      </button>
      <button class="tab-btn" onclick="switchTab('workbook')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        Realistic Test Suite (15 Tests)
      </button>
    </div>

    <!-- TAB 1: SINGLE URL ANALYZER -->
    <div id="tab-single" class="tab-content active">
      <div class="card">
        <div class="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
          Inspect Target URL
        </div>
        <p class="card-desc">Inspect URL text locally for structural deception, brand spoofing, typosquatting, userinfo tricks, and IP hostnames with weighted risk scoring.</p>

        <div class="input-group">
          <input type="text" id="targetUrl" class="url-input" placeholder="e.g. https://blog.google/innovation-and-ai/models-and-research/google-research/" autofocus>
          <button class="btn" onclick="analyzeSingleUrl()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            Analyze URL
          </button>
          <button class="btn btn-secondary" onclick="clearSingleInput()">Clear</button>
        </div>

        <!-- 1-Click Samples -->
        <div class="samples-row">
          <span class="samples-label">Quick Test Samples:</span>
          <span class="sample-pill pill-verified" onclick="loadSample('https://blog.google/innovation-and-ai/models-and-research/google-research/')">Google Blog (111 chars)</span>
          <span class="sample-pill pill-verified" onclick="loadSample('https://www.example.com/login')">Workbook: Benign</span>
          <span class="sample-pill" onclick="loadSample('http://192.0.2.10/account')">Workbook: Raw IP</span>
          <span class="sample-pill" onclick="loadSample('http://example.com@sample.invalid/login')">Workbook: @ Spoofing</span>
          <span class="sample-pill" onclick="loadSample('https://a.b.c.d.e.example.invalid/path')">Workbook: Subdomains</span>
          <span class="sample-pill" onclick="loadSample('https://xn--example.invalid/')">Workbook: Punycode</span>
          <span class="sample-pill" onclick="loadSample('https://google.com.fake-example.com/login')">Fake Google Domain</span>
          <span class="sample-pill" onclick="loadSample('https://www.g00gle-security.com/login')">Typosquatting</span>
        </div>
      </div>

      <!-- Analysis Results View -->
      <div id="resultsContainer" class="results-container">
        <div class="card">
          <!-- Risk Banner -->
          <div id="riskBanner" class="risk-banner">
            <div class="risk-title-box">
              <h3 id="riskTitle">Analyzing...</h3>
              <p id="riskSubtitle">Evaluating heuristic signals</p>
            </div>
            <div style="text-align:right;">
              <div id="riskScoreBadge" style="font-size:1.4rem; font-weight:800; font-family:monospace;">0 / 100</div>
              <div id="riskBadge" class="risk-badge-box">ASSESSMENT</div>
            </div>
          </div>

          <!-- Action Recommendation Box -->
          <div id="actionBox" class="action-box">
            <div style="font-size:1.5rem;" id="actionIcon">🛡️</div>
            <div>
              <div class="action-label">Recommended Action</div>
              <div id="actionText" class="action-text">-</div>
            </div>
          </div>

          <!-- Metrics Grid -->
          <div class="metrics-grid">
            <div class="metric-card">
              <div class="metric-label">Protocol</div>
              <div id="metricProtocol" class="metric-value">-</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Extracted Hostname</div>
              <div id="metricHost" class="metric-value">-</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Registered Domain</div>
              <div id="metricRegDomain" class="metric-value">-</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Recognized Organization</div>
              <div id="metricOrg" class="metric-value" style="color:var(--emerald);">-</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">URL Length</div>
              <div id="metricLength" class="metric-value">-</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Risk Points</div>
              <div id="metricScore" class="metric-value">-</div>
            </div>
          </div>

          <!-- Warnings List -->
          <div class="warnings-header">
            <span>Detection Findings & Educational Explanations</span>
            <span id="warningsSummaryCount" style="font-size:0.8rem; color:var(--text-muted);">0 found</span>
          </div>

          <div id="warningsList"></div>

          <!-- Security Advisory Box -->
          <div class="advisory-box">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            <div class="advisory-text">
              <h5>DEFENSIVE SECURITY ADVISORY</h5>
              <p>The absence of warning signs does <strong>NOT</strong> guarantee that a URL is safe. Phishers frequently purchase genuine TLS/SSL certificates and standard domains. Always inspect links carefully and verify destinations via official bookmarks.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: BATCH URL INSPECTOR -->
    <div id="tab-batch" class="tab-content">
      <div class="card">
        <div class="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
          Batch URL Analysis
        </div>
        <p class="card-desc">Paste multiple URLs (one per line) to scan and compare them in a unified summary table with intelligent risk scoring.</p>

        <textarea id="batchInput" class="textarea-input" placeholder="https://blog.google/innovation-and-ai/models-and-research/google-research/&#10;https://www.example.com/login&#10;http://192.0.2.10/account&#10;http://example.com@sample.invalid/login&#10;https://google.com.fake-example.com/login"></textarea>

        <div style="display:flex; gap:0.75rem; flex-wrap:wrap;">
          <button class="btn" onclick="runBatchAnalysis()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            Analyze Batch List
          </button>
          <button class="btn btn-secondary" onclick="loadRealisticSamplesIntoBatch()">Insert Test Samples</button>
          <button class="btn btn-secondary" onclick="document.getElementById('batchInput').value=''">Clear</button>
        </div>

        <div id="batchResultsTableContainer" style="display:none; margin-top:1.5rem;">
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Target URL</th>
                  <th>Domain / Organization</th>
                  <th>Score</th>
                  <th>Risk Level</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody id="batchTableBody"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: REALISTIC TEST SUITE -->
    <div id="tab-workbook" class="tab-content">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; margin-bottom:1rem;">
          <div>
            <div class="card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
              Comprehensive Test Evidence Suite (15 Test Scenarios)
            </div>
            <p class="card-desc" style="margin-bottom:0;">Live verification across benign domains, deep research links (>100 chars), IP portals, typosquatting, and brand spoofing.</p>
          </div>
          <button class="btn" onclick="runWorkbookSuite()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
            Run All 15 Tests
          </button>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Test #</th>
                <th>Category</th>
                <th>Sample URL</th>
                <th>Expected Level</th>
                <th>Actual Score & Classification</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="workbookTableBody">
              <tr>
                <td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">
                  Click <strong>"Run All 15 Tests"</strong> above to perform live verification.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>

  <!-- Footer -->
  <footer>
    <p>Phishing URL Awareness Checker • EWB Edutech Cybersecurity Mini Project • Developed with Python 3.10+</p>
  </footer>

  <script>
    // Tab switching logic
    function switchTab(tabName) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      
      const buttons = document.querySelectorAll('.tab-btn');
      if (tabName === 'single') buttons[0].classList.add('active');
      if (tabName === 'batch') buttons[1].classList.add('active');
      if (tabName === 'workbook') {
        buttons[2].classList.add('active');
        runWorkbookSuite();
      }

      document.getElementById('tab-' + tabName).classList.add('active');
    }

    function loadSample(url) {
      document.getElementById('targetUrl').value = url;
      analyzeSingleUrl();
    }

    function clearSingleInput() {
      document.getElementById('targetUrl').value = '';
      document.getElementById('resultsContainer').style.display = 'none';
      document.getElementById('targetUrl').focus();
    }

    // Single URL Analysis
    async function analyzeSingleUrl() {
      const urlInput = document.getElementById('targetUrl').value.trim();
      if (!urlInput) {
        alert('Please enter a URL to analyze.');
        return;
      }

      try {
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        renderSingleResults(data);
      } catch (err) {
        alert('Analysis error: ' + err.message);
      }
    }

    function renderSingleResults(data) {
      const container = document.getElementById('resultsContainer');
      container.style.display = 'block';

      if (!data.valid) {
        document.getElementById('riskBanner').className = 'risk-banner high';
        document.getElementById('riskTitle').textContent = 'Input Error';
        document.getElementById('riskSubtitle').textContent = data.error;
        document.getElementById('riskScoreBadge').textContent = '0 / 100';
        document.getElementById('riskBadge').textContent = 'INVALID INPUT';
        document.getElementById('actionBox').style.display = 'none';
        document.getElementById('warningsList').innerHTML = `<div class="clean-state"><h4 style="color:var(--rose);">Error</h4><p>${data.error}</p></div>`;
        return;
      }

      const warnings = data.warnings || [];
      const details = data.parsed_details;
      const count = warnings.length;
      const level = data.risk_level;
      const score = data.risk_score;

      // Banner styling based on backend risk classification
      let bannerClass = 'risk-banner safe';
      let actionClass = 'act-safe';
      let actionIcon = '🛡️';

      if (level === 'CRITICAL RISK') {
        bannerClass = 'risk-banner critical';
        actionClass = 'act-critical';
        actionIcon = '⛔';
      } else if (level === 'HIGH RISK') {
        bannerClass = 'risk-banner high';
        actionClass = 'act-high';
        actionIcon = '⚠️';
      } else if (level === 'MODERATE RISK') {
        bannerClass = 'risk-banner moderate';
        actionClass = 'act-moderate';
        actionIcon = '🔍';
      }

      const banner = document.getElementById('riskBanner');
      banner.className = bannerClass;
      document.getElementById('riskTitle').textContent = `[ ${level} ]`;
      document.getElementById('riskSubtitle').textContent = data.risk_message;
      document.getElementById('riskScoreBadge').textContent = `${score} / 100`;
      document.getElementById('riskBadge').textContent = level;

      // Action Box
      const actionBox = document.getElementById('actionBox');
      actionBox.style.display = 'flex';
      actionBox.className = 'action-box ' + actionClass;
      document.getElementById('actionIcon').textContent = actionIcon;
      document.getElementById('actionText').textContent = data.recommended_action;

      // Metrics
      document.getElementById('metricProtocol').textContent = (details.scheme || 'none') + '://';
      document.getElementById('metricHost').textContent = details.hostname || '(None Extracted)';
      document.getElementById('metricRegDomain').textContent = details.registered_domain || details.hostname;
      document.getElementById('metricOrg').textContent = details.recognized_organization || 'Standard Domain';
      document.getElementById('metricLength').textContent = details.length + ' chars';
      document.getElementById('metricScore').textContent = `${score} pts`;
      document.getElementById('warningsSummaryCount').textContent = `${count} warning sign(s)`;

      // Warnings List
      const warningsDiv = document.getElementById('warningsList');
      if (warnings.length === 0) {
        warningsDiv.innerHTML = `
          <div class="clean-state">
            <h4>No Suspicious Structural Phishing Patterns</h4>
            <p>This URL follows authentic HTTPS naming conventions, reasonable domain structure, and verified domain ownership.</p>
          </div>
        `;
      } else {
        warningsDiv.innerHTML = warnings.map((w, i) => {
          const ptsText = (w.points && w.points > 0) ? `(+${w.points} pts)` : `(0 pts)`;
          return `
            <div class="warning-card sev-${w.severity}">
              <div class="warning-title">
                <span>${i + 1}. ${w.rule} <span style="font-size:0.75rem; color:var(--text-muted);">${ptsText}</span></span>
                <span class="sev-pill">${w.severity}</span>
              </div>
              <div class="warning-finding"><strong>Finding:</strong> ${w.finding}</div>
              <div class="warning-explanation"><strong>Security Threat Vector:</strong> ${w.explanation}</div>
            </div>
          `;
        }).join('');
      }

      container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Batch Analysis
    function loadRealisticSamplesIntoBatch() {
      document.getElementById('batchInput').value = [
        'https://blog.google/innovation-and-ai/models-and-research/google-research/',
        'https://www.example.com/login',
        'http://192.0.2.10/account',
        'http://example.com@sample.invalid/login',
        'https://a.b.c.d.e.example.invalid/path',
        'https://xn--example.invalid/',
        'https://google.com.fake-example.com/login',
        'https://www.g00gle-security.com/login'
      ].join('\\n');
    }

    async function runBatchAnalysis() {
      const text = document.getElementById('batchInput').value.trim();
      if (!text) {
        alert('Please enter at least one URL.');
        return;
      }

      const urls = text.split('\\n').map(u => u.trim()).filter(u => u.length > 0);
      try {
        const response = await fetch('/api/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls: urls })
        });
        const results = await response.json();
        renderBatchTable(results);
      } catch (err) {
        alert('Batch analysis error: ' + err.message);
      }
    }

    function renderBatchTable(results) {
      const container = document.getElementById('batchResultsTableContainer');
      const tbody = document.getElementById('batchTableBody');
      container.style.display = 'block';

      tbody.innerHTML = results.map((r, idx) => {
        let tagClass = 'tag safe';
        const level = r.risk_level || 'LOW RISK';

        if (level === 'CRITICAL RISK') tagClass = 'tag critical';
        else if (level === 'HIGH RISK') tagClass = 'tag high';
        else if (level === 'MODERATE RISK') tagClass = 'tag moderate';

        const warningRules = r.valid ? (r.warnings.map(w => w.rule).join(', ') || 'No suspicious patterns') : r.error;
        const org = (r.parsed_details && r.parsed_details.recognized_organization) ? r.parsed_details.recognized_organization : '-';
        const score = r.risk_score !== undefined ? `${r.risk_score}/100` : '-';

        return `
          <tr>
            <td><strong>#${idx + 1}</strong></td>
            <td style="font-family:monospace; word-break:break-all;">${r.url}</td>
            <td><span style="font-size:0.8rem; color:var(--text-muted);">${org}</span></td>
            <td style="font-weight:700; font-family:monospace;">${score}</td>
            <td><span class="${tagClass}">${level}</span></td>
            <td>${warningRules}</td>
          </tr>
        `;
      }).join('');
    }

    // Realistic & Workbook Automated Test Suite
    async function runWorkbookSuite() {
      const tbody = document.getElementById('workbookTableBody');
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--cyan);">Running automated test suite (15 tests)...</td></tr>`;

      try {
        const response = await fetch('/api/sample_tests');
        const data = await response.json();

        tbody.innerHTML = data.map((t, idx) => `
          <tr>
            <td><strong>TC-${idx < 9 ? '0' : ''}${idx + 1}</strong></td>
            <td><span style="font-size:0.75rem; color:var(--cyan);">${t.category}</span></td>
            <td style="font-family:monospace; word-break:break-all;">${t.url}</td>
            <td><span class="tag ${t.expected.includes('HIGH') || t.expected.includes('CRITICAL') ? 'high' : (t.expected.includes('MODERATE') ? 'moderate' : 'safe')}">${t.expected}</span></td>
            <td><strong>Score: ${t.score}/100</strong> • <span style="font-size:0.8rem;">${t.actual}</span></td>
            <td><span class="tag pass">${t.status}</span></td>
          </tr>
        `).join('');
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--rose); padding:1rem;">Failed to load test suite: ${err.message}</td></tr>`;
      }
    }

    // Enter key triggers analysis
    document.getElementById('targetUrl').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') analyzeSingleUrl();
    });
  </script>
</body>
</html>
"""


class PhishingUIRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler serving the Web UI and JSON API endpoints."""

    def log_message(self, format, *args):
        # Keep terminal output clean
        pass

    def send_json_response(self, status_code: int, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            content = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        elif parsed.path == "/api/sample_tests":
            # Run all 15 tests from SAMPLE_TEST_CASES
            results = []
            for item in SAMPLE_TEST_CASES:
                res = analyze_url(item["url"])
                actual_level = res["risk_level"]
                actual_score = res["risk_score"]
                exp = item["expected"]

                is_pass = (actual_level == exp) or (exp in ("HIGH RISK", "CRITICAL RISK") and actual_level in ("HIGH RISK", "CRITICAL RISK"))
                results.append({
                    "category": item["category"],
                    "url": item["url"],
                    "expected": item["expected"],
                    "actual": actual_level,
                    "score": actual_score,
                    "status": "PASS" if is_pass else "FAIL"
                })

            self.send_json_response(200, results)

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            self.send_json_response(400, {"error": "Invalid JSON payload"})
            return

        if parsed.path == "/api/analyze":
            target_url = payload.get("url", "")
            result = analyze_url(target_url)
            self.send_json_response(200, result)

        elif parsed.path == "/api/batch":
            urls = payload.get("urls", [])
            batch_results = [analyze_url(u) for u in urls if isinstance(u, str)]
            self.send_json_response(200, batch_results)

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Endpoint Not Found")


def find_available_port(start_port=5000, max_attempts=10) -> int:
    """Find a free TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


def start_server(port: int = 5000, open_browser: bool = True):
    """
    Launch the local UI server and open the browser.
    """
    actual_port = find_available_port(port)
    server_address = ("127.0.0.1", actual_port)
    httpd = HTTPServer(server_address, PhishingUIRequestHandler)
    url = f"http://127.0.0.1:{actual_port}"

    print("\n" + "=" * 75)
    print("       🛡️  PHISHING URL AWARENESS CHECKER - GRAPHICAL WEB UI  🛡️")
    print("=" * 75)
    print(f"  • Status:       [ONLINE & READY]")
    print(f"  • Interface:    {url}")
    print(f"  • Security:     100% Localhost Execution (No external network traffic)")
    print(f"  • Engine:       Intelligent Weighted Risk Scoring (0-100 pts)")
    print(f"  • Architecture: Python Standard Library (Zero dependencies)")
    print("=" * 75)
    print("  Press Ctrl+C in this terminal anytime to stop the server.\n")

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down UI server safely. Goodbye!")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    start_server()
