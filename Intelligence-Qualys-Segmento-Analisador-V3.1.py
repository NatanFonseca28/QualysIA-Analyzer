import customtkinter as ctk
from tkinter import messagebox, filedialog
import requests
import time
import os
import xml.etree.ElementTree as ET 
import csv
import re
from io import StringIO
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
import pandas as pd
import google.generativeai as genai
from groq import Groq
import sys
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np
from docx import Document
from docx.shared import Inches, Pt, RGBColor
# --- NOVAS IMPORTAÇÕES PARA FORMATAÇÃO DO WORD ---
from docx.enum.text import WD_ALIGN_PARAGRAPH
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
from dataclasses import dataclass
from typing import Dict, List, Optional
import glob
import webbrowser
from itertools import cycle

# --- NOVAS IMPORTAÇÕES PARA O DASHBOARD WEB ---
from flask import Flask, render_template_string, jsonify
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import sqlite3 # Adicionado para o Cache Persistente

# --- CONFIGURAÇÃO INICIAL ---
load_dotenv()
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Configuração Matplotlib para Threads (Sem GUI para evitar crash)
matplotlib.use('Agg') 

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

# --- LÓGICA DE CARREGAMENTO DE MÚLTIPLAS CHAVES NVD ---
# Tenta carregar lista separada por vírgula, senão carrega a única, senão lista vazia
nvd_keys_env = os.getenv("NVD_API_KEYS")
if nvd_keys_env:
    NVD_API_KEYS = [k.strip() for k in nvd_keys_env.split(',') if k.strip()]
else:
    single_key = os.getenv("NVD_API_KEY")
    NVD_API_KEYS = [single_key] if single_key else []

AI_AVAILABLE = False
if GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)
    AI_AVAILABLE = True

# --- GLOBAL SHARED DATA (Ponte entre GUI e Flask) ---
class SharedData:
    dataframe = pd.DataFrame()
    client_name = "Nenhum Cliente Carregado"
    updated_at = datetime.now()

shared_data = SharedData()

# --- INTEGRAÇÃO NVD / THREAT INTEL (COM ROUND ROBIN E SMART TTL) ---

class PersistentNVDCache:
    def __init__(self, db_path="nvd_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Inicializa o banco de dados SQLite para cache."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cves (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT,
                    updated_at TEXT
                )
            """)

    def save_cve(self, cve_id: str, data: dict):
        """Salva ou atualiza um CVE no cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO nvd_cves (cve_id, data, updated_at) VALUES (?, ?, ?)",
                    (cve_id, json.dumps(data), datetime.now().isoformat())
                )
        except Exception as e:
            print(f"Erro ao salvar cache SQLite: {e}")

    def get_cve(self, cve_id):
        """Recupera um CVE usando a estratégia Smart TTL."""
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT data, updated_at FROM nvd_cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                data_json, updated_at_str = row
                data_dict = json.loads(data_json)
                updated_at = datetime.fromisoformat(updated_at_str)
                age = datetime.now() - updated_at

                # --- LÓGICA INTELIGENTE (SMART TTL) ---
                # O NVD retorna esse campo. Se não existir, assume vazio.
                vuln_status = data_dict.get('vulnStatus', '') 
                
                # Se ainda não foi analisada, validade curta (1 dia)
                if 'AWAITING' in vuln_status.upper() or 'UNDERGOING' in vuln_status.upper():
                    limit = timedelta(days=1)
                else:
                    # Se já foi analisada ou rejeitada, validade longa (5 dias) e.g., 'ANALYZED'
                    limit = timedelta(days=5) 

                if age < limit:
                    return data_dict
                
                # Se expirou, retorna None e força nova busca (a API NVDIntegration fará o update)
                return None
            return None
        except Exception as e:
            # print(f"Erro ao ler cache SQLite: {e}")
            return None

class NVDIntegration:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_keys: List[str]):
        self.api_keys = api_keys
        self.lock = threading.Lock()
        
        # Inicializa o Cache Persistente Inteligente
        self.cache = PersistentNVDCache()
        
        # Se não houver chaves, usamos um slot "None" para o modo público (lento)
        if not self.api_keys:
            self.key_pool = [{'key': None, 'history': [], 'limit': 5}]
        else:
            # Configura pool para cada chave (50 reqs / 30s)
            self.key_pool = [{'key': k, 'history': [], 'limit': 50} for k in self.api_keys]
            
        self.window_seconds = 30
        # Ciclo infinito para iterar sobre as chaves (Round Robin básico)
        self.pool_cycle = cycle(self.key_pool)

    def _get_valid_header_and_wait(self):
        """
        Rotaciona entre as chaves disponíveis. 
        Se a chave atual estourou o limite, tenta a próxima.
        Se TODAS estouraram, espera e tenta novamente.
        """
        while True:
            with self.lock:
                now = time.time()
                
                # Tenta encontrar uma chave livre em uma passagem completa pelo pool
                # Para evitar loop infinito travado no lock, tentamos len(pool) vezes
                best_sleep_time = float('inf')
                
                for _ in range(len(self.key_pool)):
                    key_obj = next(self.pool_cycle)
                    
                    # Limpa histórico antigo (janela deslizante)
                    key_obj['history'] = [t for t in key_obj['history'] if now - t < self.window_seconds]
                    
                    # Verifica disponibilidade
                    if len(key_obj['history']) < key_obj['limit']:
                        # BINGO! Chave disponível.
                        key_obj['history'].append(now)
                        headers = {}
                        if key_obj['key']:
                            headers['apiKey'] = key_obj['key']
                        return headers
                    
                    # Se cheia, calcula quanto tempo falta para a mais antiga expirar (para caso precisemos dormir)
                    if key_obj['history']:
                        wait = self.window_seconds - (now - key_obj['history'][0])
                        if wait < best_sleep_time:
                            best_sleep_time = wait
                
            # Se saiu do for loop (dentro do lock), significa que NENHUMA chave estava livre.
            # Dorme um pouco fora do lock para liberar threads e tenta de novo.
            # Adiciona um pequeno jitter para evitar colisão
            sleep_needed = max(0.1, min(best_sleep_time, 1.0)) + random.uniform(0.1, 0.5)
            time.sleep(sleep_needed)

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        # 1. TENTA BUSCAR DO CACHE PERSISTENTE (Smart TTL)
        cached_data = self.cache.get_cve(cve_id)
        if cached_data:
            return cached_data

        # 2. SE NÃO ESTIVER NO CACHE (OU EXPIROU), BUSCA NA API
        try:
            # Obtém headers de uma chave válida (pode bloquear se todas estiverem cheias)
            headers = self._get_valid_header_and_wait()
            
            response = requests.get(self.BASE_URL, params={'cveId': cve_id}, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    parsed_data = self._parse_cve(data['vulnerabilities'][0])
                    # Salva no cache para uso futuro
                    self.cache.save_cve(cve_id, parsed_data)
                    return parsed_data
            
            elif response.status_code == 429: # Too Many Requests (mesmo com nossa lógica, o servidor pode rejeitar)
                time.sleep(2)
                return self.get_cve_details(cve_id)
                
            elif response.status_code == 503:
                time.sleep(2)
                return self.get_cve_details(cve_id)
                
            return None
        except Exception as e:
            # print(f"Erro ao buscar CVE {cve_id}: {e}") # Silent error para não poluir log
            return None

    def _parse_cve(self, cve_data: dict) -> dict:
        cve = cve_data.get('cve', {})
        metrics = cve.get('metrics', {})
        cvss_v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if 'cvssMetricV31' in metrics else {}
        cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}) if 'cvssMetricV2' in metrics else {}
        
        has_exploit = any('Exploit' in ref.get('tags', []) for ref in cve.get('references', []))
        cisa_kev = cve.get('cisaExploitAdd') is not None
        
        # IMPORTANTE: Captura o status da vulnerabilidade para o Smart TTL
        vuln_status = cve.get('vulnStatus', 'UNKNOWN')

        return {
            'cve_id': cve.get('id'),
            'vulnStatus': vuln_status, # Campo necessário para a lógica Smart TTL
            'cvss_v31': {'score': cvss_v31.get('baseScore', 0), 'severity': cvss_v31.get('baseSeverity', 'UNKNOWN'), 'vector': cvss_v31.get('vectorString', '')},
            'cvss_v2': {'score': cvss_v2.get('baseScore', 0), 'vector': cvss_v2.get('vectorString', '')},
            'has_known_exploit': has_exploit,
            'cisa_kev': cisa_kev
        }

class ThreatIntelligenceEnricher:
    def __init__(self, nvd: NVDIntegration):
        self.nvd = nvd
        # O Cache principal agora é gerenciado pela classe NVDIntegration via SQLite
        # Mantemos um cache local efêmero apenas para evitar chamadas de método repetidas na mesma execução de lote
        self.local_mem_cache = {} 
        self.cache_lock = threading.Lock()

    def enrich_vulnerability(self, vuln_data: dict) -> dict:
        cve_ids = vuln_data.get('CVE_IDS', [])
        if isinstance(cve_ids, str):
            cve_ids = [c.strip() for c in cve_ids.split(',') if c.strip()]
            
        enriched_intel = {'max_cvss': 0.0, 'has_exploit': False, 'cisa_kev': False, 'cvss_vector': '', 'risk_factors': []}
        
        # Analisa até 3 CVEs por QID para não sobrecarregar
        for cve_id in cve_ids[:3]: 
            cve_data = None
            
            # Verifica memória local rápida primeiro
            with self.cache_lock:
                cve_data = self.local_mem_cache.get(cve_id)

            # Se não estiver na memória local, chama o NVDIntegration (que verifica SQLite Smart TTL)
            if not cve_data:
                cve_data = self.nvd.get_cve_details(cve_id)
                if cve_data:
                    with self.cache_lock:
                        self.local_mem_cache[cve_id] = cve_data
            
            if cve_data:
                score = max(cve_data['cvss_v31']['score'], cve_data['cvss_v2']['score'])
                if score > enriched_intel['max_cvss']:
                    enriched_intel['max_cvss'] = score
                    enriched_intel['cvss_vector'] = cve_data['cvss_v31']['vector'] or cve_data['cvss_v2']['vector']
                
                if cve_data['has_known_exploit']:
                    enriched_intel['has_exploit'] = True
                if cve_data['cisa_kev']:
                    enriched_intel['cisa_kev'] = True
                    
        return enriched_intel

# --- FLASK APP SETUP ---
flask_app = Flask(__name__)

# HTML Template (Embutido para manter arquivo único)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnManager AI | Dashboard Executivo</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-nav: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-primary: #38bdf8;
            --accent-secondary: #818cf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #0ea5e9;
        }
        
        body { 
            background-color: var(--bg-main); 
            color: var(--text-primary); 
            font-family: 'Inter', sans-serif;
            letter-spacing: -0.01em;
        }
        
        .navbar { 
            background-color: var(--bg-nav) !important; 
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
        }
        
        .navbar-brand { font-weight: 700; color: var(--accent-primary) !important; font-size: 1.25rem; }
        
        .card { 
            background-color: var(--bg-card); 
            border: 1px solid var(--border-color); 
            border-radius: 12px;
            margin-bottom: 24px; 
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            overflow: hidden;
        }
        
        .card-header { 
            background-color: rgba(255, 255, 255, 0.02); 
            border-bottom: 1px solid var(--border-color); 
            font-weight: 600; 
            color: var(--text-primary);
            padding: 1rem 1.25rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-header i { color: var(--accent-primary); }
        
        /* Métricas */
        .metric-box { 
            text-align: left; 
            padding: 1.5rem; 
            background: var(--bg-card); 
            border-radius: 12px; 
            border: 1px solid var(--border-color);
            position: relative;
            transition: transform 0.2s ease;
        }
        
        .metric-box:hover { transform: translateY(-2px); }
        
        .metric-icon {
            position: absolute;
            right: 1.5rem;
            top: 1.5rem;
            font-size: 1.5rem;
            opacity: 0.2;
        }
        
        .metric-value { font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
        .metric-label { font-size: 0.75rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; color: var(--text-secondary); }
        
        /* Tabela */
        .table-custom { color: var(--text-primary); font-size: 0.875rem; }
        .table-custom thead th { 
            border-bottom: 1px solid var(--border-color); 
            color: var(--text-secondary); 
            background-color: rgba(255, 255, 255, 0.03);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.05em;
            padding: 0.75rem 1.25rem;
        }
        .table-custom td { border-color: var(--border-color); vertical-align: middle; padding: 0.75rem 1.25rem; }
        .table-custom tr:hover td { background-color: rgba(255, 255, 255, 0.02); }
        .scrollable-table { max-height: 380px; overflow-y: auto; }
        
        /* Badges */
        .badge-crit-10 { background-color: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
        .badge-crit-5 { background-color: rgba(245, 158, 11, 0.1); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.2); padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; }
        .badge-crit-1 { background-color: rgba(16, 185, 129, 0.1); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; }

        .risk-calc-box {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-primary);
            padding: 1.5rem;
            border-radius: 12px;
        }

        .debug-info { font-size: 0.7rem; color: var(--text-secondary); text-align: center; margin-top: 3rem; padding-bottom: 2rem; }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-main); }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1"><i class="fas fa-shield-halved me-2"></i>VulnManager AI | {{ client }}</span>
            <span class="text-secondary small" id="last-update"><i class="far fa-clock me-1"></i>Sincronizado: {{ updated_at }}</span>
        </div>
    </nav>

    <div class="container-fluid px-4">
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="metric-box">
                    <i class="fas fa-bug metric-icon text-danger"></i>
                    <div class="metric-label">Vulnerabilidades Ativas</div>
                    <div class="metric-value text-danger" id="total-vulns">...</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-box">
                    <i class="fas fa-radiation metric-icon text-warning"></i>
                    <div class="metric-label">Risco Médio (Business)</div>
                    <div class="metric-value text-warning" id="avg-risk">...</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-box">
                    <i class="fas fa-server metric-icon text-info"></i>
                    <div class="metric-label">Hosts Afetados</div>
                    <div class="metric-value text-info" id="hosts-count">...</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-box">
                    <i class="fas fa-check-circle metric-icon text-success"></i>
                    <div class="metric-label">Corrigidas (Período)</div>
                    <div class="metric-value text-success" id="fixed-count">...</div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header"><i class="fas fa-chart-pie"></i>Distribuição por Severidade</div>
                    <div class="card-body">
                        <div id="severity-chart" style="height: 300px;"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header"><i class="fas fa-list-ol"></i>Top 10 Mais Frequentes</div>
                    <div class="card-body p-0">
                        <div id="top-freq-table" class="scrollable-table"></div>
                    </div>
                </div>
            </div>
             <div class="col-md-4">
                <div class="card">
                    <div class="card-header"><i class="fas fa-hourglass-half"></i>Envelhecimento (Aging)</div>
                    <div class="card-body">
                        <div id="aging-chart" style="height: 300px;"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header"><i class="fas fa-laptop-code"></i>Sistemas Operacionais</div>
                    <div class="card-body">
                        <div id="os-chart" style="height: 350px;"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header"><i class="fas fa-exclamation-triangle"></i>Top 10 Ativos Críticos</div>
                    <div class="card-body p-0">
                        <div id="risky-assets-table" class="scrollable-table"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-2 mb-4">
            <div class="col-12">
                 <div class="risk-calc-box">
                    <h5 class="text-white mb-3"><i class="fas fa-calculator me-2 text-accent"></i>Cálculo de Risco Avançado</h5>
                    <div class="row">
                        <div class="col-md-8">
                            <p class="text-secondary small mb-0">
                                O <strong>Risco Total</strong> é calculado através da soma exponencial das vulnerabilidades: <code>Σ 4<sup>Severidade</sup></code>, 
                                ponderado pela <strong>Criticalidade do Ativo</strong>. Isso garante que ativos de produção com vulnerabilidades críticas 
                                tenham prioridade máxima de remediação.
                            </p>
                        </div>
                        <div class="col-md-4 text-end">
                            <span class="badge-crit-10 me-2">Produção x10</span>
                            <span class="badge-crit-5 me-2">Padrão x5</span>
                            <span class="badge-crit-1">Workstation x1</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="debug-info">
            <i class="fas fa-microchip me-1"></i> Engine: Qualys API Snapshot + NVD Intel (Multi-Key) | 
            <i class="fas fa-code-branch ms-2 me-1"></i> Versão: 3.0.0
        </div>
    </div>

    <script>
        function renderTable(elementId, headers, rows) {
            let html = '<table class="table table-custom mb-0">';
            html += '<thead><tr>';
            headers.forEach(h => html += `<th>${h}</th>`);
            html += '</tr></thead><tbody>';
            if (!rows || rows.length === 0) {
                html += `<tr><td colspan="${headers.length}" class="text-center text-muted py-4">Sem dados para exibir</td></tr>`;
            } else {
                rows.forEach(row => {
                    html += '<tr>';
                    row.forEach((cell, idx) => {
                        let content = cell;
                        if (headers[idx] === 'Risco Total') {
                            content = `<span class="fw-bold text-accent">${cell}</span>`;
                        }
                        html += `<td>${content}</td>`;
                    });
                    html += '</tr>';
                });
            }
            html += '</tbody></table>';
            document.getElementById(elementId).innerHTML = html;
        }

        async function fetchData(type, elementId) {
            try {
                const r = await fetch(`/api/charts/${type}?t=` + new Date().getTime());
                const d = await r.json();
                if (d.error) { document.getElementById(elementId).innerHTML = `<div class="p-4 text-center text-muted">${d.error}</div>`; return; }
                
                if (d.type === 'table') renderTable(elementId, d.headers, d.rows);
                else {
                    // Customização do Layout Plotly para o tema Dark
                    const layout = d.layout || {};
                    layout.paper_bgcolor = 'rgba(0,0,0,0)';
                    layout.plot_bgcolor = 'rgba(0,0,0,0)';
                    layout.font = { family: 'Inter, sans-serif', color: '#94a3b8', size: 11 };
                    if (layout.xaxis) { layout.xaxis.gridcolor = '#334155'; layout.xaxis.zerolinecolor = '#334155'; }
                    if (layout.yaxis) { layout.yaxis.gridcolor = '#334155'; layout.yaxis.zerolinecolor = '#334155'; }
                    if (layout.margin) { layout.margin = { t: 30, b: 30, l: 30, r: 30 }; }
                    
                    Plotly.newPlot(elementId, d.data, layout, {responsive: true, displayModeBar: false});
                }
            } catch (e) { console.error(e); }
        }

        async function fetchMetrics() {
            try {
                const r = await fetch('/api/metrics?t=' + new Date().getTime());
                const d = await r.json();
                document.getElementById('total-vulns').innerText = d.active.toLocaleString();
                document.getElementById('avg-risk').innerText = d.risk.toLocaleString();
                document.getElementById('hosts-count').innerText = d.hosts.toLocaleString();
                document.getElementById('fixed-count').innerText = d.fixed.toLocaleString();
            } catch (e) { console.error(e); }
        }

        document.addEventListener('DOMContentLoaded', () => {
            fetchMetrics();
            fetchData('severity', 'severity-chart');
            fetchData('top_freq', 'top-freq-table');
            fetchData('aging', 'aging-chart');
            fetchData('os', 'os-chart');
            fetchData('risky_assets', 'risky-assets-table');
            setInterval(fetchMetrics, 30000);
        });
    </script>
</body>
</html>
"""


class DashboardGenerator:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        
        # Mapeamento de Colunas
        self.col_sev = self._find_col(['Severity', 'Sev', 'Severidade', 'MAX_SEV'])
        self.col_title = self._find_col(['Vuln_TITLE', 'Title', 'VULN_TITLE', 'QID Title'])
        self.col_status = self._find_col(['Status', 'STATUS', 'Vuln Status', 'State'])
        self.col_os = self._find_col(['Operating System', 'OS', 'OPERATING SYSTEM', 'Asset OS'])
        self.col_ip = self._find_col(['IP', 'IP Address', 'IP_ADDRESS'])
        self.col_dns = self._find_col(['DNS', 'DNS Name', 'FQDN'])
        self.col_tags = self._find_col(['Tags', 'ASSET_TAGS', 'TAGS'])
        
        # Sanitização e Cálculos
        if not self.df.empty:
            if self.col_sev:
                self.df[self.col_sev] = pd.to_numeric(self.df[self.col_sev], errors='coerce').fillna(0).astype(int)
            if self.col_status:
                self.df[self.col_status] = self.df[self.col_status].astype(str).str.strip()

            # ---------------------------------------------------------
            # CÁLCULO DE RISCO EXPONENCIAL (Técnico)
            # ---------------------------------------------------------
            # 4 elevado à severidade (Sev 3=64, Sev 4=256, Sev 5=1024)
            if self.col_sev:
                self.df['Tech_Risk'] = 4 ** self.df[self.col_sev]
            else:
                self.df['Tech_Risk'] = 0

            # ---------------------------------------------------------
            # CÁLCULO DE CRITICALIDADE DO ATIVO (1, 5 ou 10)
            # ---------------------------------------------------------
            self.df['Asset_Criticality'] = self.df.apply(self._calculate_criticality, axis=1)

            # Aging (Cálculo auxiliar)
            col_ff = self._find_col(['First Found', 'FIRST FOUND', 'First Detected'])
            if col_ff and 'Age_Days' not in self.df.columns:
                 self.df['First_Found_Temp'] = pd.to_datetime(self.df[col_ff], errors='coerce', utc=True)
                 self.df['Age_Days'] = (pd.Timestamp.now(timezone.utc) - self.df['First_Found_Temp']).dt.days.fillna(0)

    def _find_col(self, possibilities):
        if self.df.empty: return None
        for p in possibilities:
            if p in self.df.columns: return p
        cols_upper = {c.upper(): c for c in self.df.columns}
        for p in possibilities:
            if p.upper() in cols_upper: return cols_upper[p.upper()]
        return None

    def _calculate_criticality(self, row):
        """Define peso de 1 a 10 baseado em palavras-chave no Host/OS."""
        score = 5 # Padrão (Médio)
        
        # Concatena dados para buscar palavras-chave
        text_data = ""
        if self.col_os: text_data += str(row[self.col_os]).upper() + " "
        if self.col_dns: text_data += str(row[self.col_dns]).upper() + " "
        if self.col_tags: text_data += str(row[self.col_tags]).upper() + " "
        
        # 1. Regras de Alta Criticalidade (10)
        high_keywords = ['PROD', 'DATABASE', 'ORACLE', 'SQL', 'SERVER', 'PAYMENT', 'PCI', 'DMZ', 'AWS', 'AZURE', 'LINUX', 'DC']
        if any(kw in text_data for kw in high_keywords):
            score = 10
            
        # 2. Regras de Baixa Criticalidade (1)
        low_keywords = ['LAPTOP', 'DESKTOP', 'NOTEBOOK', 'WORKSTATION', 'WIN10', 'WIN11', 'WINDOWS 10', 'WINDOWS 11', 'TEST', 'DEV', 'LAB']
        if any(kw in text_data for kw in low_keywords):
            # Se tiver 'Server' no nome mas for 'Test', deve cair? 
            # Neste modelo, 'Server' força 10, a menos que seja explicitamente workstation
            if score != 10: 
                score = 1
        
        # 3. Refinamento Windows Server (Garante 10)
        if 'WINDOWS SERVER' in text_data:
            score = 10

        return score

    def get_metrics(self):
        if self.df.empty: return {"active": 0, "risk": 0, "hosts": 0, "fixed": 0}
        
        if self.col_status:
            active_mask = ~self.df[self.col_status].str.upper().str.contains('FIXED', na=False)
            fixed_mask = self.df[self.col_status].str.upper().str.contains('FIXED', na=False)
            
            # Cálculo do Risco Médio do Negócio
            active_df = self.df[active_mask].copy()
            if not active_df.empty and self.col_ip:
                # Agrupa por host para somar risco técnico
                host_risk = active_df.groupby(self.col_ip).agg({
                    'Tech_Risk': 'sum',
                    'Asset_Criticality': 'max'
                })
                # Multiplica pela criticalidade
                host_risk['Business_Risk'] = host_risk['Tech_Risk'] * host_risk['Asset_Criticality']
                avg_risk = int(host_risk['Business_Risk'].mean())
            else:
                avg_risk = 0
            
            active_count = int(self.df[active_mask].shape[0])
            fixed_count = int(self.df[fixed_mask].shape[0])
        else:
            active_count = len(self.df)
            fixed_count = 0
            avg_risk = 0

        hosts = self.df[self.col_ip].nunique() if self.col_ip else 0
        return {"active": active_count, "risk": avg_risk, "hosts": hosts, "fixed": fixed_count}

    def create_severity_distribution_chart(self) -> str:
        if self.df.empty or not self.col_sev: return json.dumps({"error": "Sem dados"})
        if self.col_status: df_chart = self.df[~self.df[self.col_status].str.upper().str.contains('FIXED', na=False)]
        else: df_chart = self.df
        data = df_chart[self.col_sev].value_counts().sort_index(ascending=False)
        colors = {5: '#ef4444', 4: '#f97316', 3: '#f59e0b', 2: '#eab308', 1: '#10b981'}
        labels = [f'Sev {i}' for i in data.index]; values = data.values.tolist()
        marker_colors = [colors.get(i, '#333') for i in data.index]
        fig = go.Figure(data=[go.Pie(labels=labels, values=values, marker_colors=marker_colors, hole=0.6, textinfo='label+percent')])
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#e0e0e0'), showlegend=False)
        return fig.to_json()

    def create_aging_chart(self) -> str:
        if self.df.empty or 'Age_Days' not in self.df.columns: return json.dumps({"error": "N/A"})
        if self.col_status: active_df = self.df[~self.df[self.col_status].str.upper().str.contains('FIXED', na=False)].copy()
        else: active_df = self.df.copy()
        active_df['Age_Days'] = pd.to_numeric(active_df['Age_Days'], errors='coerce').fillna(0)
        bins = [-1, 30, 60, 90, 180, 9999]
        active_df['Aging_Bucket'] = pd.cut(active_df['Age_Days'], bins=bins, labels=['0-30', '31-60', '61-90', '91-180', '180+'])
        counts = active_df['Aging_Bucket'].value_counts().sort_index()
        fig = go.Figure(data=[go.Bar(x=counts.index.astype(str), y=counts.values, marker_color=['#38bdf8', '#818cf8', '#fbbf24', '#f87171', '#ef4444'], text=counts.values, textposition='auto')])
        fig.update_layout(margin=dict(t=20, b=30, l=30, r=30), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#e0e0e0'), yaxis=dict(showgrid=True, gridcolor='#333'))
        return fig.to_json()

    def create_os_distribution(self) -> str:
        if self.df.empty or not self.col_os or not self.col_ip: return json.dumps({"error": "N/A"})
        hosts_df = self.df[[self.col_ip, self.col_os]].drop_duplicates(subset=[self.col_ip]).copy()
        def clean_os(s):
            s = str(s).upper()
            if 'WINDOWS' in s: return 'Windows Server' if 'SERVER' in s else 'Windows Workstation'
            if 'UBUNTU' in s or 'DEBIAN' in s or 'CENTOS' in s or 'RED HAT' in s or 'LINUX' in s: return 'Linux/Unix'
            if 'CISCO' in s: return 'Cisco/Network'
            return 'Outros'
        hosts_df['OS_N'] = hosts_df[self.col_os].apply(clean_os)
        counts = hosts_df['OS_N'].value_counts()
        fig = px.pie(values=counts.values, names=counts.index, hole=0.4, color_discrete_sequence=px.colors.qualitative.Prism)
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#e0e0e0'), annotations=[dict(text=f"{counts.sum()}", x=0.5, y=0.5, font_size=20, showarrow=False, font_color='white')])
        return fig.to_json()

    def get_top_frequent_data(self) -> str:
        if self.df.empty or not self.col_title or not self.col_ip: return json.dumps({"error": "Dados insuficientes"})
        if self.col_status: df_active = self.df[~self.df[self.col_status].str.upper().str.contains('FIXED', na=False)]
        else: df_active = self.df
        top = df_active.groupby(self.col_title)[self.col_ip].nunique().sort_values(ascending=False).head(10)
        headers = ["Vulnerabilidade", "Hosts Afetados"]
        rows = [[str(title)[:60] + "..." if len(str(title))>60 else title, int(count)] for title, count in top.items()]
        return json.dumps({"type": "table", "headers": headers, "rows": rows})

    # ------------------------------------------------------------------
    # TABELA PRINCIPAL COM NOVO CÁLCULO
    # ------------------------------------------------------------------
    def get_risky_assets_data(self) -> str:
        """
        Retorna Tabela HTML com Business Risk = Tech Risk (Exponencial) x Criticality
        """
        if self.df.empty or not self.col_ip: return json.dumps({"error": "Dados insuficientes"})
        
        # Filtra apenas ativas
        if self.col_status:
            df_active = self.df[~self.df[self.col_status].str.upper().str.contains('FIXED', na=False)].copy()
        else:
            df_active = self.df.copy()
            
        group_cols = [self.col_ip]
        if self.col_dns: group_cols.append(self.col_dns)
        
        # Agrupa por Host: Soma o Risco Técnico e pega a Criticalidade Máxima
        risky = df_active.groupby(group_cols).agg({
            'Tech_Risk': 'sum',
            'Asset_Criticality': 'max'
        }).reset_index()

        # Aplica a fórmula final do Negócio
        risky['Business_Risk'] = risky['Tech_Risk'] * risky['Asset_Criticality']

        # Ordena e pega Top 10
        risky = risky.sort_values('Business_Risk', ascending=False).head(10)
        
        headers = ["Ativo (Host)", "Fator Crít.", "Risco Total"]
        rows = []
        
        for _, row in risky.iterrows():
            # Formata Nome
            ip = str(row[self.col_ip])
            dns = str(row[self.col_dns]) if self.col_dns and pd.notnull(row[self.col_dns]) else ""
            label = f"{ip}<br><small class='text-muted'>{dns}</small>" if dns and dns != 'nan' else ip
            
            # Formata Badge (HTML)
            crit_val = int(row['Asset_Criticality'])
            badge_class = "badge-crit-10" if crit_val == 10 else "badge-crit-5" if crit_val == 5 else "badge-crit-1"
            crit_html = f"<span class='{badge_class}'>x{crit_val}</span>"
            
            # Formata Score (12.340)
            score_fmt = f"{int(row['Business_Risk']):,}".replace(",", ".")
            
            rows.append([label, crit_html, score_fmt])
            
        return json.dumps({"type": "table", "headers": headers, "rows": rows})


# --- ROTAS FLASK ---
@flask_app.route('/')
def dashboard_index():
    return render_template_string(DASHBOARD_HTML, client=shared_data.client_name, updated_at=shared_data.updated_at.strftime("%d/%m/%Y %H:%M"))

@flask_app.route('/api/metrics')
def api_metrics():
    dash = DashboardGenerator(shared_data.dataframe)
    return jsonify(dash.get_metrics())

@flask_app.route('/api/charts/<chart_type>')
def get_chart(chart_type):
    dash = DashboardGenerator(shared_data.dataframe)
    
    methods = {
        'severity': dash.create_severity_distribution_chart,
        'top_freq': dash.get_top_frequent_data,    # Retorna JSON Tabela
        'aging': dash.create_aging_chart,
        'os': dash.create_os_distribution,
        'risky_assets': dash.get_risky_assets_data # Retorna JSON Tabela
    }
    
    if chart_type in methods:
        # Nota: as funções novas já retornam string json.dumps, 
        # as antigas retornam fig.to_json() que também é string.
        # Então loadamos e jsonificamos novamente para o Flask enviar o header correto
        return jsonify(json.loads(methods[chart_type]()))
    
    return jsonify({'error': 'Chart type not found'}), 404

def run_flask():
    flask_app.run(port=5000, debug=False, use_reloader=False)

# Iniciando Flask em Daemon Thread
threading.Thread(target=run_flask, daemon=True).start()


# --- 1. CLASSES DE ENGENHARIA DE PROMPT (COMPLETA) ---

@dataclass
class SegmentContext:
    name: str
    regulations: list
    critical_assets: list
    business_impact_examples: list
    risk_tolerance: str
    key_concerns: list

class PromptEngineer:
    def __init__(self):
        self.segment_contexts = self._load_segment_contexts()

    def _load_segment_contexts(self) -> Dict[str, SegmentContext]:
        return {
            # --- CONTEXTOS JÁ EXISTENTES ---
            'financeiro': SegmentContext(
                name="Setor Financeiro & Bancário",
                regulations=['PCI DSS 4.0', 'Resolução BCB 4.893', 'LGPD', 'SOX', 'Swift CSP'],
                critical_assets=['Core Banking', 'Chaves PIX', 'Internet Banking', 'Mobile Banking', 'Gateways de Pagamento', 'Dados de Cartão (PAN)'],
                business_impact_examples=['Fraude financeira direta e perda de liquidez', 'Vazamento de dados sigilosos e quebra de sigilo bancário', 'Indisponibilidade de transações (PIX/TED) e multas do BACEN', 'Danos reputacionais irreversíveis no mercado'],
                risk_tolerance='Crítica (Zero Trust)',
                key_concerns=['Fraude', 'Compliance Regulatório', 'Disponibilidade 24x7', 'Segurança de Transações']
            ),
            'saude': SegmentContext(
                name="Setor de Saúde & Life Sciences",
                regulations=['LGPD', 'HIPAA', 'Resoluções CFM/Anvisa'],
                critical_assets=['Prontuário Eletrônico (PEP)', 'PACS/RIS (Imagens)', 'Equipamentos Médicos (IoMT)', 'Dados Laboratoriais', 'Fórmulas Farmacêuticas'],
                business_impact_examples=['Vazamento de dados sensíveis de pacientes (PHI)', 'Sequestro de dados (Ransomware) paralisando triagem', 'Risco direto à vida por falha em equipamentos conectados', 'Processos éticos e judiciais'],
                risk_tolerance='Muito Baixa',
                key_concerns=['Privacidade do Paciente', 'Segurança Hospitalar', 'Disponibilidade de Sistemas Críticos']
            ),
            'varejo': SegmentContext(
                name="Setor de Varejo & E-commerce",
                regulations=['PCI DSS', 'LGPD', 'CDC (Código de Defesa do Consumidor)'],
                critical_assets=['Plataforma E-commerce', 'PDV (Ponto de Venda)', 'ERP', 'Banco de Dados CRM', 'Gateway de Frete'],
                business_impact_examples=['Skimming de cartão de crédito no checkout', 'Indisponibilidade do site em datas sazonais (Black Friday)', 'Vazamento de base de clientes para concorrentes', 'Perda imediata de receita por hora parada'],
                risk_tolerance='Média',
                key_concerns=['Uptime em alta demanda', 'Proteção de dados de cartão', 'Experiência do Cliente']
            ),
            'industria': SegmentContext(
                name="Setor Industrial & Manufatura",
                regulations=['NR-12', 'ISO 27001', 'IEC 62443 (Segurança em Automação)'],
                critical_assets=['Sistemas SCADA', 'PLCs', 'Redes OT', 'Sistemas MES', 'Historiadores de Dados', 'Robôs Industriais'],
                business_impact_examples=['Parada não planejada da linha de produção', 'Alteração de parâmetros de qualidade do produto', 'Danos físicos a equipamentos ou colaboradores', 'Espionagem industrial e roubo de propriedade intelectual'],
                risk_tolerance='Baixa',
                key_concerns=['Convergência IT/OT', 'Segurança Física', 'Continuidade Operacional']
            ),
            'energia': SegmentContext(
                name="Setor de Energia & Utilities",
                regulations=['Resoluções ANEEL/ANP', 'ONS (Procedimentos de Rede)', 'Lei de Infraestrutura Crítica'],
                critical_assets=['Centros de Operação (COS)', 'Sistemas de Supervisão', 'Relés de Proteção', 'Medidores Inteligentes', 'Rede de Distribuição'],
                business_impact_examples=['Blackout ou interrupção de fornecimento', 'Danos à infraestrutura crítica nacional', 'Impacto ambiental por falha de controle', 'Terrorismo cibernético'],
                risk_tolerance='Zero',
                key_concerns=['Segurança Nacional', 'Alta Disponibilidade', 'Sistemas Legados']
            ),
            'governo': SegmentContext(
                name="Setor Público & Governo",
                regulations=['LGPD', 'LAI (Lei de Acesso à Informação)', 'Normativas GSI/NC', 'Lei de Segurança Nacional'],
                critical_assets=['Bases de Dados do Cidadão', 'Portais de Serviços (Gov.br)', 'Sistemas de Arrecadação', 'Infraestrutura de Cidades Inteligentes'],
                business_impact_examples=['Exposição massiva de dados de cidadãos', 'Interrupção de serviços públicos essenciais', 'Perda de confiança nas instituições', 'Ataques de Hacktivismo'],
                risk_tolerance='Baixa',
                key_concerns=['Soberania Digital', 'Privacidade do Cidadão', 'Resiliência']
            ),
            'tecnologia': SegmentContext(
                name="Setor de Tecnologia & Telecom",
                regulations=['ISO 27001', 'SOC 2', 'GDPR/LGPD', 'Marco Civil da Internet'],
                critical_assets=['Código Fonte (IP)', 'Pipelines CI/CD', 'Infraestrutura Cloud', 'Dados de Assinantes', 'Backbones de Rede'],
                business_impact_examples=['Ataques de Supply Chain afetando clientes', 'Vazamento de credenciais de acesso privilegiado', 'DDoS massivo contra infraestrutura', 'Comprometimento de propriedade intelectual'],
                risk_tolerance='Média-Baixa',
                key_concerns=['Segurança de Aplicação', 'Cloud Security', 'Gerenciamento de Identidade']
            ),
            
            # --- NOVOS CONTEXTOS ADICIONADOS PARA COBRIR SUA LISTA ---
            'logistica': SegmentContext(
                name="Setor de Logística & Transportes",
                regulations=['LGPD', 'Normas ANTT/ANAC', 'AEO (Operador Econômico Autorizado)'],
                critical_assets=['Sistemas de Rastreamento', 'Gestão de Frota', 'WMS (Warehouse Management)', 'Manifestos de Carga'],
                business_impact_examples=['Interrupção da cadeia de suprimentos', 'Roubo de carga facilitado por dados vazados', 'Atrasos críticos em entregas', 'Perda de visibilidade da frota'],
                risk_tolerance='Média',
                key_concerns=['Integridade da Cadeia', 'IoT/Rastreamento', 'Disponibilidade']
            ),
            'educacao': SegmentContext(
                name="Setor de Educação & Ensino",
                regulations=['LGPD (Dados de Menores)', 'MEC (Portarias de Segurança Acadêmica)'],
                critical_assets=['Plataformas EAD/LMS', 'Dados Acadêmicos e Financeiros de Alunos', 'Propriedade Intelectual de Pesquisas'],
                business_impact_examples=['Vazamento de dados de menores de idade', 'Interrupção de aulas e provas online', 'Perda de pesquisas científicas não publicadas', 'Danos à reputação institucional'],
                risk_tolerance='Média',
                key_concerns=['Privacidade de Alunos', 'Continuidade de Aulas', 'Segurança de Dados de Pesquisa']
            ),
            'juridico': SegmentContext(
                name="Setor Jurídico & Consultoria",
                regulations=['LGPD', 'Estatuto da Advocacia (Sigilo)', 'ISO 27001'],
                critical_assets=['Dossiês de Clientes', 'E-mails e Comunicações Sigilosas', 'Sistemas de Gestão de Processos', 'Propriedade Intelectual'],
                business_impact_examples=['Quebra de sigilo advogado-cliente', 'Espionagem industrial contra clientes', 'Perda de credibilidade e processos disciplinares', 'Ransomware em dados de litígio'],
                risk_tolerance='Baixa',
                key_concerns=['Confidencialidade Extrema', 'Controle de Acesso', 'Prevenção de Vazamento (DLP)']
            ),
            'midia': SegmentContext(
                name="Setor de Mídia & Entretenimento",
                regulations=['LGPD', 'Direitos Autorais', 'Classificação Indicativa'],
                critical_assets=['Conteúdo Inédito (Masters)', 'Plataformas de Streaming', 'Dados de Assinantes', 'Canais de Transmissão ao Vivo'],
                business_impact_examples=['Vazamento de conteúdo antes do lançamento (Spoilers/Pirataria)', 'Interrupção de transmissões ao vivo', 'Sequestro de canais sociais', 'DDoS em estreias'],
                risk_tolerance='Média',
                key_concerns=['Proteção de Conteúdo (DRM)', 'Alta Disponibilidade', 'Segurança de Contas']
            )
    }
        
    def _identify_segment(self, segment_selection: str) -> str:
        """
        Mapeia a seleção exata da UI (self.lista_segmentos) para as chaves do dicionário de contextos.
        """
        # Mapeamento Direto: UI String -> Chave do Contexto
        mapping = {
            # Financeiro
            "Financeiro - Bancos & Investimentos": "financeiro",
            "Financeiro - Meios de Pagamento & Fintechs": "financeiro",
            "Financeiro - Seguradoras": "financeiro",
            
            # Varejo
            "Varejo - E-commerce (Comércio Eletrônico)": "varejo",
            "Varejo - Redes de Lojas Físicas & Supermercados": "varejo",
            
            # Saúde
            "Saúde - Hospitais & Clínicas": "saude",
            "Saúde - Laboratórios de Diagnóstico": "saude",
            "Saúde - Indústria Farmacêutica": "saude",
            
            # Tecnologia
            "Tecnologia - Desenvolvimento de Software (SaaS)": "tecnologia",
            "Tecnologia - Data Centers & Cloud Providers": "tecnologia",
            "Tecnologia - Telecomunicações & ISP": "tecnologia",
            
            # Indústria
            "Indústria - Manufatura & Fábricas": "industria",
            "Indústria - Automotiva": "industria",
            "Indústria - Agronegócio": "industria",
            
            # Energia
            "Energia - Geração & Distribuição Elétrica": "energia",
            "Energia - Óleo, Gás & Petroquímica": "energia",
            
            # Logística
            "Logística - Transporte & Portos": "logistica",
            
            # Governo
            "Governo - Federal/Estadual (Dados Cidadão)": "governo",
            
            # Educação
            "Educação - Universidades & Ensino a Distância": "educacao",
            
            # Serviços
            "Serviços Jurídicos & Advocacia": "juridico",
            "Consultoria & Auditoria": "juridico", # Mapeado para jurídico/consultoria pela similaridade de risco (confidencialidade)
            
            # Mídia
            "Mídia, Entretenimento & Streaming": "midia"
        }
        
        # Retorna a chave correspondente ou 'varejo' como fallback de segurança
        return mapping.get(segment_selection, 'varejo')




    def _format_candidates(self, candidates: list) -> str:
        if not candidates:
            return "Nenhuma vulnerabilidade crítica detectada."
        
        lines = []
        for i, v in enumerate(candidates[:20], 1):
            title = v.get('Vuln_TITLE', 'N/A')
            hosts = v.get('Hosts_Count', 0)
            sev = v.get('Max_Sev', 0)
            risk = v.get('Risk_Sum', 0)
            solution = v.get('Vuln_SOLUTION', 'Consulte o vendor.')[:100] + "..."
            
            lines.append(f"{i}. **{title}**")
            lines.append(f"   - Hosts Afetados: {hosts} | Severidade: {sev} | Risk Score: {risk:.0f}")
            lines.append(f"   - Resumo Solução: {solution}")
            lines.append("")
            
        return '\n'.join(lines)

    def generate_analysis_prompt(self, summary: dict, segment: str, period: str, start_date_str: str = "") -> str:
        segment_key = self._identify_segment(segment)
        context = self.segment_contexts.get(segment_key, self.segment_contexts['varejo'])
        
        status = summary['status_counts']
        active = status['Active'] + status['New'] + status['Re-Opened']
        candidates_str = self._format_candidates(summary.get('top_remediation', []))
        
        # Formatando listas para inserção limpa no prompt
        crit_assets_str = "\n".join([f"- {asset}" for asset in context.critical_assets])
        regs_str = ", ".join(context.regulations)

        # Lógica de Maturidade Baseada na Data de Início
        maturity_context = ""
        if start_date_str:
            try:
                start_dt = datetime.strptime(start_date_str, "%d/%m/%Y")
                months_diff = (datetime.now() - start_dt).days // 30
                
                maturity_context = f"\nIMPORTANTE: A operação de Gestão de Vulnerabilidades iniciou em {start_date_str} (aprox. {months_diff} meses de operação)."
                if months_diff < 3:
                    maturity_context += " Considere que estamos em fase inicial (cleanup inicial), então um alto volume de legado é esperado."
                elif months_diff > 12:
                    maturity_context += " Já somos uma operação madura. A presença de vulnerabilidades antigas deve ser criticada de forma mais severa."
            except:
                maturity_context = f"\nIMPORTANTE: A operação iniciou em {start_date_str}."

        prompt = f"""
        ATUE COMO UM CISO SÊNIOR ESPECIALIZADO NO: {context.name}. (Porém utilize linguagem simples, não seja tão engessado, não precisa parecer um documento ou e-mail, porém não tão coloquial)
        
        ## 1. CONTEXTO DO NEGÓCIO E REGULATÓRIO
        - **Regulamentações Chave**: {regs_str}
        - **Tolerância a Risco**: {context.risk_tolerance}
        - **Maiores Preocupações**: {', '.join(context.key_concerns)}
        {maturity_context}
        
        ## 2. ATIVOS CRÍTICOS (O QUE DEVEMOS PROTEGER A TODO CUSTO)
        {crit_assets_str}
        
        ## 3. DADOS TÉCNICOS DO RELATÓRIO ({period})
        - **Total Ativas**: {active} (Novas + Reabertas + Ativas)
        - **Total Corrigidas**: {status['Fixed']}
        - **Legado Crítico (>90 dias)**: {summary['smart_insights']['old_crit_count']} ativos vulneráveis.
        
        ## 4. TOP VULNERABILIDADES DETECTADAS (CANDIDATAS)
        {candidates_str}

        ## SUA MISSÃO (RELATÓRIO ESTRATÉGICO)
        
        ### A. ANÁLISE DE RISCO CONTEXTUALIZADA
        Analise os dados acima considerando o **impacto de negócio** específico para {context.name}.
        Cite exemplos reais de como essas falhas poderiam afetar os **Ativos Críticos** listados (Ex: {context.business_impact_examples[0]}).
        
        ### B. PRIORIZAÇÃO DE ELITE (TOP 5)
        Das candidatas listadas, selecione APENAS AS 5 MAIS PERIGOSAS para este setor específico.
        Formato Obrigatório para cada uma das 5:
        1. **[Nome da Vuln]** (QID: Se houver) - (Hosts afetados)
           - **Impacto no Negócio**: [Explique em 1 frase por que isso para o setor {segment_key}]
           - **Conformidade**: [Violação potencial de qual norma? Ex: {context.regulations[0]}]
           - **Ação Imediata**: [Ação técnica resumida]

        ### C. CONCLUSÃO EXECUTIVA
        Escreva um parágrafo final para o Board de analistas. Seja direto sobre o nível de exposição, se estamos em conformidade com as regulações citadas e qual o prazo ideal para remediar o Top 5.
        """
        return prompt

# --- 2. CLASSE DE GERAÇÃO DE GRÁFICOS (AVANÇADA) ---

class ReportChartGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        try:
            plt.style.use('seaborn-v0_8-whitegrid')
        except:
            plt.style.use('ggplot')

    def create_executive_summary_chart(self, summary: dict) -> str:
        fig = plt.figure(figsize=(16, 12))
        gs = GridSpec(3, 3, figure=fig, hspace=0.4, wspace=0.3)

        # 1. Gauge de Risco Geral
        ax1 = fig.add_subplot(gs[0, 0])
        risk_norm = min(summary.get('risk_score_norm', 50), 100)
        self._draw_risk_gauge(ax1, risk_norm)

        # 2. Pizza de Status
        ax2 = fig.add_subplot(gs[0, 1])
        status = summary['status_counts']
        sizes = [status.get('Active', 0), status.get('Fixed', 0), status.get('New', 0), status.get('Re-Opened', 0)]
        labels = ['Ativas', 'Corrigidas', 'Novas', 'Reabertas']
        pie_data = [(s, l) for s, l in zip(sizes, labels) if s > 0]
        if pie_data:
            sizes_f, labels_f = zip(*pie_data)
            colors = ['#FF6B6B', '#4ECDC4', '#FFE66D', '#95E1D3']
            ax2.pie(sizes_f, labels=labels_f, colors=colors[:len(sizes_f)], autopct='%1.1f%%', startangle=90, explode=[0.05]*len(sizes_f))
        ax2.set_title('Distribuição por Status', fontweight='bold')

        # 3. Barras de Severidade
        ax3 = fig.add_subplot(gs[0, 2])
        severities = summary.get('severity_counts', {})
        sev_labels = ['Crítico (5)', 'Alto (4)', 'Médio (3)', 'Baixo (2)', 'Info (1)']
        sev_values = [severities.get(5, 0), severities.get(4, 0), severities.get(3, 0), severities.get(2, 0), severities.get(1, 0)]
        sev_colors = ['#8B0000', '#FF4500', '#FFA500', '#FFD700', '#90EE90']
        bars = ax3.barh(sev_labels[::-1], sev_values[::-1], color=sev_colors[::-1])
        ax3.bar_label(bars)
        ax3.set_title('Vulns por Severidade', fontweight='bold')

        # 4. Histograma de Envelhecimento (Aging)
        ax4 = fig.add_subplot(gs[1, :2])
        aging = summary.get('aging_buckets', {})
        buckets = ['0-30 Dias', '31-60 Dias', '61-90 Dias', '90+ Dias (Legado)']
        vals = [aging.get('0-30', 0), aging.get('31-60', 0), aging.get('61-90', 0), aging.get('90+', 0)]
        colors_age = ['#4ECDC4', '#FFE66D', '#FF6B6B', '#2C3E50']
        ax4.bar(buckets, vals, color=colors_age, alpha=0.8)
        ax4.set_title('Envelhecimento das Vulnerabilidades (Aging)', fontweight='bold')
        ax4.grid(axis='y', linestyle='--', alpha=0.7)

        # 5. MTTR por Severidade
        ax5 = fig.add_subplot(gs[1, 2])
        mttr = summary.get('avg_time_to_fix', {})
        if mttr:
            mttr_labels = [f'S{k}' for k in sorted(mttr.keys(), reverse=True)]
            mttr_values = [mttr[k] for k in sorted(mttr.keys(), reverse=True)]
            ax5.bar(mttr_labels, mttr_values, color='steelblue')
            ax5.axhline(y=30, color='red', linestyle='--', linewidth=1, label='SLA 30d')
            ax5.legend(fontsize=8)
        else:
            ax5.text(0.5, 0.5, "Sem dados de correção", ha='center')
        ax5.set_title('MTTR Médio (Dias)', fontweight='bold')

        # 6. Top 10 Vulnerabilidades
        ax6 = fig.add_subplot(gs[2, :])
        top_vulns = summary.get('top_remediation', [])[:10]
        if top_vulns:
            titles = [v['Vuln_TITLE'][:60] + '...' for v in top_vulns]
            risks = [v['Risk_Sum'] for v in top_vulns]
            y_pos = np.arange(len(titles))
            ax6.barh(y_pos, risks, align='center', color='#C0392B')
            ax6.set_yticks(y_pos)
            ax6.set_yticklabels(titles, fontsize=9)
            ax6.invert_yaxis()
            ax6.set_xlabel('Risk Score Acumulado')
            ax6.set_title('Top 10 Vulnerabilidades Críticas (Prioridade de Remediação)', fontweight='bold')
        else:
            ax6.text(0.5, 0.5, "Nenhuma vulnerabilidade crítica encontrada", ha='center')

        plt.suptitle(f'Panorama de Segurança Cibernética\nGerado em: {datetime.now().strftime("%d/%m/%Y")}', fontsize=16, fontweight='bold', y=0.95)

        path = os.path.join(self.output_dir, 'executive_dashboard_v2.png')
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        return path

    def _draw_risk_gauge(self, ax, score):
        ax.set_xlim(-1.5, 1.5)
        ax.set_ylim(-0.5, 1.5)
        ax.axis('off')
        theta = np.linspace(np.pi, 0, 100)
        r = 1
        x = r * np.cos(theta)
        y = r * np.sin(theta)
        colors = [('green', 0, 33), ('gold', 33, 66), ('red', 66, 100)]
        for color, start_p, end_p in colors:
            start_idx = int(start_p * len(theta) / 100)
            end_idx = int(end_p * len(theta) / 100)
            if end_idx >= len(theta): end_idx = len(theta) -1
            ax.plot(x[start_idx:end_idx], y[start_idx:end_idx], color=color, linewidth=25, solid_capstyle='butt')
        angle = np.pi - (score / 100) * np.pi
        ax.arrow(0, 0, 0.8 * np.cos(angle), 0.8 * np.sin(angle), head_width=0.1, head_length=0.1, fc='black', ec='black', width=0.02)
        circle = mpatches.Circle((0, 0), 0.1, color='black')
        ax.add_patch(circle)
        ax.text(0, -0.4, f'{score:.0f}/100', ha='center', va='center', fontsize=20, fontweight='bold', color='#333')
        status_text = "CRÍTICO" if score > 75 else "ALTO" if score > 50 else "MÉDIO" if score > 25 else "BAIXO"
        color_text = "red" if score > 75 else "orange" if score > 50 else "gold" if score > 25 else "green"
        ax.text(0, 0.5, status_text, ha='center', va='center', fontsize=10, fontweight='bold', color='white', bbox=dict(facecolor=color_text, edgecolor='none', alpha=0.7, boxstyle='round'))
        ax.set_title('Índice de Risco do Ambiente', fontsize=11, y=-0.1)


# --- 3. APLICAÇÃO PRINCIPAL (UI + LÓGICA COMPLETA) ---

class ModernQualysApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VulnManager AI")
        self.geometry("1280x900")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Dados da UI
        self.lista_segmentos = [
            "Financeiro - Bancos & Investimentos",
            "Financeiro - Meios de Pagamento & Fintechs",
            "Financeiro - Seguradoras",
            "Varejo - E-commerce (Comércio Eletrônico)",
            "Varejo - Redes de Lojas Físicas & Supermercados",
            "Saúde - Hospitais & Clínicas",
            "Saúde - Laboratórios de Diagnóstico",
            "Saúde - Indústria Farmacêutica",
            "Tecnologia - Desenvolvimento de Software (SaaS)",
            "Tecnologia - Data Centers & Cloud Providers",
            "Tecnologia - Telecomunicações & ISP",
            "Indústria - Manufatura & Fábricas",
            "Indústria - Automotiva",
            "Indústria - Agronegócio",
            "Energia - Geração & Distribuição Elétrica",
            "Energia - Óleo, Gás & Petroquímica",
            "Logística - Transporte & Portos",
            "Governo - Federal/Estadual (Dados Cidadão)",
            "Educação - Universidades & Ensino a Distância",
            "Serviços Jurídicos & Advocacia",
            "Consultoria & Auditoria",
            "Mídia, Entretenimento & Streaming"
        ]
        
        self.lista_periodos = ["Todo período", "90 dias", "45 dias", "30 dias", "15 dias", "7 dias"]
        self.clientes_encontrados = self.buscar_clientes_env()

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ VulnManager AI", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        self.btn_dashboard = ctk.CTkButton(self.sidebar, text="📊 Dashboard", command=self.show_dashboard, fg_color="transparent", border_width=1, text_color=("gray10", "#DCE4EE"), anchor="w")
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=5, sticky="ew")

        self.btn_scan = ctk.CTkButton(self.sidebar, text="🔍 Novo Scan & Report", command=self.show_scan_config, fg_color="transparent", border_width=1, text_color=("gray10", "#DCE4EE"), anchor="w")
        self.btn_scan.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
        
        # --- NOVO BOTÃO DE WEB DASHBOARD ---
        self.btn_web = ctk.CTkButton(self.sidebar, text="🌐 Abrir Dashboard Web", command=self.open_web_dashboard, fg_color="#1F6AA5", text_color="white", hover_color="#144870", anchor="w")
        self.btn_web.grid(row=3, column=0, padx=20, pady=5, sticky="ew")

        self.appearance_mode = ctk.CTkOptionMenu(self.sidebar, values=["Dark", "Light", "System"], command=self.change_appearance)
        self.appearance_mode.grid(row=11, column=0, padx=20, pady=20)

        # --- ÁREA PRINCIPAL ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.show_dashboard()

    # --- MÉTODOS DE UI ---

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def change_appearance(self, mode):
        ctk.set_appearance_mode(mode.lower())

    def open_web_dashboard(self):
        # Abre o navegador padrão na porta do Flask
        webbrowser.open("http://127.0.0.1:5000")

    def show_dashboard(self):
        self.clear_main_frame()
        
        title = ctk.CTkLabel(self.main_frame, text="Dashboard Executivo", font=ctk.CTkFont(size=28, weight="bold"))
        title.grid(row=0, column=0, padx=10, pady=(10, 20), sticky="w")

        kpi_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        kpi_frame.grid(row=1, column=0, sticky="nsew")

        kpis = [
            ("Status API IA", "Online" if AI_AVAILABLE else "OFFLINE", "#10b981" if AI_AVAILABLE else "#ef4444"),
            ("Status Key NVD", "Online" if NVD_API_KEYS else "OFFLINE", "#10b981" if NVD_API_KEYS else "#ef4444"),
            ("Clientes Ativos", str(len(self.clientes_encontrados)), "#0ea5e9"),
            ("Versão Engine", "3.0.0", "#6366f1"),
        ]

        for i, (label, value, color) in enumerate(kpis):
            card = ctk.CTkFrame(kpi_frame, fg_color=color, corner_radius=12)
            card.grid(row=0, column=i, padx=8, pady=10, sticky="nsew")
            kpi_frame.grid_columnconfigure(i, weight=1)
            
            ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=28, weight="bold"), text_color="white").pack(pady=(25, 2))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=12, weight="normal"), text_color="white").pack(pady=(0, 25))
        
        info = ctk.CTkLabel(self.main_frame, text="Selecione 'Novo Scan' no menu lateral para iniciar uma nova análise completa.\nApós o scan, clique em 'Abrir Dashboard Web' para visualizar os dados interativos.", font=ctk.CTkFont(size=14))
        info.grid(row=2, column=0, pady=40)

    def show_scan_config(self):
        self.clear_main_frame()

        title = ctk.CTkLabel(self.main_frame, text="Configuração de Scan & Relatório", font=ctk.CTkFont(size=24, weight="bold"))
        title.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        config_frame = ctk.CTkFrame(self.main_frame)
        config_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        config_frame.grid_columnconfigure(1, weight=1)

        # 1. Cliente
        ctk.CTkLabel(config_frame, text="Cliente (Env):", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=15, pady=15, sticky="w")
        self.client_combo = ctk.CTkComboBox(config_frame, values=self.clientes_encontrados, width=300)
        self.client_combo.grid(row=0, column=1, padx=15, pady=15, sticky="w")
        if self.clientes_encontrados: self.client_combo.set(self.clientes_encontrados[0])

        # 2. Segmento
        ctk.CTkLabel(config_frame, text="Segmento de Negócio:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=15, pady=15, sticky="w")
        self.segment_combo = ctk.CTkComboBox(config_frame, values=self.lista_segmentos, width=300)
        self.segment_combo.grid(row=1, column=1, padx=15, pady=15, sticky="w")
        self.segment_combo.set(self.lista_segmentos[0])

        # 3. Período
        ctk.CTkLabel(config_frame, text="Filtro de Período:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=15, pady=15, sticky="w")
        self.period_combo = ctk.CTkComboBox(config_frame, values=self.lista_periodos, width=300)
        self.period_combo.grid(row=2, column=1, padx=15, pady=15, sticky="w")
        self.period_combo.set(self.lista_periodos[0])
        
        # NOVO CAMPO: Data de Início da Operação
        ctk.CTkLabel(config_frame, text="Início da Gestão (Opcional):", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=15, pady=15, sticky="w")
        self.start_date_entry = ctk.CTkEntry(config_frame, width=300, placeholder_text="DD/MM/AAAA (Para cálculo de maturidade)")
        self.start_date_entry.grid(row=3, column=1, padx=15, pady=15, sticky="w")

        # 4. Checkboxes
        ctk.CTkLabel(config_frame, text="Status das Vulns:", font=ctk.CTkFont(weight="bold")).grid(row=4, column=0, padx=15, pady=15, sticky="w")
        chk_frame = ctk.CTkFrame(config_frame, fg_color="transparent")
        chk_frame.grid(row=4, column=1, padx=15, pady=15, sticky="w")
        
        self.chk_new = ctk.CTkCheckBox(chk_frame, text="New"); self.chk_new.pack(side="left", padx=5); self.chk_new.select()
        self.chk_active = ctk.CTkCheckBox(chk_frame, text="Active"); self.chk_active.pack(side="left", padx=5); self.chk_active.select()
        self.chk_reopened = ctk.CTkCheckBox(chk_frame, text="Re-Opened"); self.chk_reopened.pack(side="left", padx=5); self.chk_reopened.select()
        self.chk_fixed = ctk.CTkCheckBox(chk_frame, text="Fixed"); self.chk_fixed.pack(side="left", padx=5); self.chk_fixed.select()

        # 5. IA Toggle
        ctk.CTkLabel(config_frame, text="Inteligência Artificial:", font=ctk.CTkFont(weight="bold")).grid(row=5, column=0, padx=15, pady=15, sticky="w")
        self.ai_switch = ctk.CTkSwitch(config_frame, text="Gerar Análise Executiva (Gemini/Groq)")
        self.ai_switch.grid(row=5, column=1, padx=15, pady=15, sticky="w")
        if AI_AVAILABLE: self.ai_switch.select()

        # 6. NVD Toggle (NOVO)
        ctk.CTkLabel(config_frame, text="Threat Intelligence:", font=ctk.CTkFont(weight="bold")).grid(row=6, column=0, padx=15, pady=15, sticky="w")
        self.nvd_switch = ctk.CTkSwitch(config_frame, text="Ativar Enriquecimento NVD (CVE/Exploit)")
        self.nvd_switch.grid(row=6, column=1, padx=15, pady=15, sticky="w")
        if NVD_API_KEYS: self.nvd_switch.select()

        # Botão Executar
        self.btn_execute = ctk.CTkButton(config_frame, text="🚀 INICIAR GERAÇÃO DE RELATÓRIO", font=ctk.CTkFont(size=15, weight="bold"), height=50, corner_radius=10, fg_color="#1F6AA5", hover_color="#144870", command=self.iniciar_thread)
        self.btn_execute.grid(row=7, column=0, columnspan=2, padx=30, pady=30, sticky="ew")

        # LOG BOX
        log_label = ctk.CTkLabel(self.main_frame, text="Console de Execução:", font=ctk.CTkFont(weight="bold"))
        log_label.grid(row=2, column=0, padx=10, pady=(20,0), sticky="w")

        self.log_box = ctk.CTkTextbox(self.main_frame, height=250, font=("Consolas", 12), border_width=1, border_color="#334155")
        self.log_box.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.log_box.configure(state="disabled")

    # --- MÉTODOS DE BACKEND/LOGIC ---

    def buscar_clientes_env(self):
        clientes = []
        for key in os.environ.keys():
            if key.startswith("QUALYS_USER_"):
                clientes.append(key.replace("QUALYS_USER_", ""))
        return clientes

    def log(self, msg):
        try:
            timestamp = datetime.now().strftime("[%H:%M:%S]")
            full_msg = f"{timestamp} {msg}\n"
            print(full_msg.strip())
            
            def _update():
                if hasattr(self, 'log_box'):
                    self.log_box.configure(state="normal")
                    self.log_box.insert("end", full_msg)
                    self.log_box.see("end")
                    self.log_box.configure(state="disabled")
            
            self.after(0, _update)
        except: pass

    def iniciar_thread(self):
        cliente = self.client_combo.get()
        segmento = self.segment_combo.get()
        periodo = self.period_combo.get()
        usar_ia = bool(self.ai_switch.get())
        usar_nvd = bool(self.nvd_switch.get()) # NOVO: Captura estado do botão NVD
        start_date_str = self.start_date_entry.get() 

        if not cliente:
            messagebox.showerror("Erro", "Selecione um cliente.")
            return

        lista_status = []
        if self.chk_new.get(): lista_status.append("New")
        if self.chk_active.get(): lista_status.append("Active")
        if self.chk_reopened.get(): lista_status.append("Re-Opened")
        if self.chk_fixed.get(): lista_status.append("Fixed")
        
        status_str = ",".join(lista_status) if lista_status else "New,Active,Re-Opened,Fixed"

        self.btn_execute.configure(state="disabled", text="PROCESSANDO... AGUARDE")
        
        if hasattr(self, 'log_box'):
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", "end")
            self.log_box.configure(state="disabled")

        threading.Thread(target=self.executar_logica, args=(cliente, status_str, segmento, periodo, usar_ia, start_date_str, usar_nvd)).start()

    def finalizar_execucao(self, sucesso=True, msg=""):
        self.btn_execute.configure(state="normal", text="INICIAR GERAÇÃO DE RELATÓRIO")
        if sucesso:
            self.log(f"SUCESSO: {msg}")
            messagebox.showinfo("Concluído", msg)
        else:
            self.log(f"FALHA: {msg}")
            messagebox.showerror("Erro", "Falha no processo. Verifique o log.")

    # --- NÚCLEO LÓGICO (BACKEND REAL + EXCEL AVANÇADO) ---
    def perform_ai_analysis(self, summary, segment, period, start_date_str):
        """
        Gera o prompt usando o PromptEngineer.
        Tenta Google Gemini PRIMEIRO. Se falhar ou não tiver chave, tenta Groq (Llama 3).
        Retorna uma tupla: (texto_da_analise, nome_do_modelo)
        """
        try:
            # 1. Gera o Prompt Engenheirado
            engineer = PromptEngineer()
            prompt = engineer.generate_analysis_prompt(summary, segment, period, start_date_str)
            
            # ---------------------------------------------------------
            # 2. PRIORIDADE: Tenta usar Google Gemini
            # ---------------------------------------------------------
            if GEMINI_KEY:
                try:
                    self.log(">>> Conectando ao Google Gemini...")
                    genai.configure(api_key=GEMINI_KEY)
                    
                    # Usando gemini-pro (estável) ou gemini-1.5-flash (rápido)
                    # Se preferir o modelo preview que estava usando: 'gemini-3-pro-preview'
                    model = genai.GenerativeModel('gemini-3-flash-preview') 
                    
                    response = model.generate_content(prompt)
                    return response.text, "Google Gemini 3"
                except Exception as e:
                    self.log(f"Erro Gemini: {e}. Tentando fallback para Groq...")
            else:
                self.log("Chave Gemini não configurada. Tentando Groq...")

            # ---------------------------------------------------------
            # 3. FALLBACK: Tenta usar GROQ (Llama 3)
            # ---------------------------------------------------------
            if GROQ_KEY:
                try:
                    self.log(">>> Conectando à Groq Cloud (Llama-3)...")
                    client = Groq(api_key=GROQ_KEY)
                    chat_completion = client.chat.completions.create(
                        messages=[
                            {
                                "role": "user",
                                "content": prompt,
                            }
                        ],
                        model="llama-3.3-70b-versatile", # Modelo rápido e inteligente
                        temperature=0.3,
                        max_tokens=2048
                    )
                    return chat_completion.choices[0].message.content, "Groq (Llama 3.3 70B)"
                except Exception as e:
                    self.log(f"Erro Groq: {e}.")
            
            return "Nenhuma chave de API (Gemini ou Groq) funcional configurada.", "Erro"

        except Exception as e:
            error_msg = f"Erro ao gerar análise de IA: {str(e)}"
            self.log(error_msg)
            return error_msg, "Erro"
        
        
    def executar_logica(self, cliente_selecionado, status_str, segmento_selecionado, periodo_selecionado, usar_ia, start_date_str, usar_nvd):
        try:
            self.log("="*60)
            self.log(f"INICIANDO PROCESSO PARA: {cliente_selecionado}")
            self.log(f"SEGMENTO: {segmento_selecionado} | PERÍODO: {periodo_selecionado}")
            if start_date_str: self.log(f"INÍCIO GESTÃO: {start_date_str}")
            self.log(f"THREAT INTEL (NVD): {'ATIVADO' if usar_nvd else 'DESATIVADO'}")
            self.log("="*60)

            BASE_URL = os.getenv(f"QUALYS_URL_{cliente_selecionado}")
            user_raw = os.getenv(f"QUALYS_USER_{cliente_selecionado}")
            pass_raw = os.getenv(f"QUALYS_PASS_{cliente_selecionado}")
            
            if not BASE_URL: BASE_URL = os.getenv(f"QUALYS_BASE_URL_{cliente_selecionado}")
            if not BASE_URL or not user_raw or not pass_raw:
                self.log("ERRO CRÍTICO: Credenciais ausentes no .env")
                self.after(0, lambda: self.finalizar_execucao(False))
                return

            USERNAME = user_raw.strip()
            PASSWORD = pass_raw.strip()
            
            BATCH_SIZE = 250 
            HEADERS = {'X-Requested-With': 'Python Script', 'Content-Type': 'application/x-www-form-urlencoded'}
            
            session = requests.Session()
            session.auth = (USERNAME, PASSWORD)
            session.headers.update(HEADERS)

            # --- API FUNCTIONS ---
            def get_all_host_data():
                url = f"{BASE_URL}/api/4.0/fo/asset/host/"
                self.log(f">>> Buscando Asset Inventory (API 4.0)...")
                payload = {'action': 'list', 'details': 'All', 'show_tags': '1', 'truncation_limit': '0'} 
                
                try:
                    r = session.post(url, data=payload, timeout=120)
                    if r.status_code != 200:
                        self.log(f"Erro API Status {r.status_code}: {r.text}")
                        return [], {}, {}, []
                    
                    root = ET.fromstring(r.text)
                    tags_by_id, tags_by_ip = {}, {}
                    all_ids, asset_inventory = [], []
                    
                    hosts_found = root.findall('.//HOST')
                    self.log(f"Hosts encontrados: {len(hosts_found)}")
                    
                    for host in hosts_found:
                        id_elem = host.find('ID')
                        hid = id_elem.text if id_elem is not None else "N/A"
                        if hid != "N/A": all_ids.append(hid)
                        
                        ip_elem = host.find('IP')
                        if ip_elem is None: ip_elem = host.find('IP_ADDRESS')
                        hip = ip_elem.text if ip_elem is not None else "N/A"
                        
                        tags = []
                        tags_block = host.find('TAGS')
                        if tags_block is not None:
                            for name_node in tags_block.findall('.//NAME'):
                                if name_node.text: tags.append(name_node.text)
                        
                        tags.sort() 
                        tags_str = ", ".join(tags)
                        
                        if hid != "N/A": tags_by_id[hid] = tags_str
                        if hip != "N/A": tags_by_ip[hip] = tags_str

                        # Inventário
                        os_elem = host.find('OS')
                        dns_elem = host.find('DNS')
                        netbios_elem = host.find('NETBIOS')
                        tracking_elem = host.find('TRACKING_METHOD')
                        last_scan_elem = host.find('LAST_VULN_SCAN_DATETIME')

                        asset_data = {
                            'Host ID': hid,
                            'IP Address': hip,
                            'DNS Name': dns_elem.text if dns_elem is not None else "N/A",
                            'NetBIOS Name': netbios_elem.text if netbios_elem is not None else "N/A",
                            'Operating System': os_elem.text if os_elem is not None else "N/A",
                            'Tracking Method': tracking_elem.text if tracking_elem is not None else "N/A",
                            'Last Scan': last_scan_elem.text if last_scan_elem is not None else "N/A",
                            'Tags': tags_str
                        }
                        asset_inventory.append(asset_data)
                            
                    return list(set(all_ids)), tags_by_id, tags_by_ip, asset_inventory
                
                except Exception as e:
                    self.log(f"Erro XML: {e}")
                    return [], {}, {}, []

            def fetch_detections_batch(session_obj, id_list, batch_index, total_batches):
                url = f"{BASE_URL}/api/3.0/fo/asset/host/vm/detection/"
                ids_string = ",".join(id_list)
                payload = {
                    'action': 'list', 'output_format': 'CSV', 'ids': ids_string,
                    'truncation_limit': '0', 'status': status_str, 'show_qds': '1'
                }
                
                for attempt in range(5):
                    try:
                        r = session_obj.post(url, data=payload, timeout=180)
                        if r.status_code == 200:
                            self.log(f"   [OK] Lote {batch_index}/{total_batches}")
                            return r.text
                        elif r.status_code == 409:
                            time.sleep(random.randint(15, 45))
                        else:
                            time.sleep(5)
                    except:
                        time.sleep(5)
                return None

            def get_vulnerability_details(qids):
                if not qids: return {}
                self.log(f">>> Consultando KnowledgeBase para {len(qids)} QIDs...")
                url = f"{BASE_URL}/api/2.0/fo/knowledge_base/vuln/"
                kb_details = {}
                
                # Processa em lotes de 1000 (Qualys recomenda max 2k, mas 1k é mais seguro para XML grande)
                for i in range(0, len(qids), 1000):
                    batch = qids[i:i+1000]
                    ids_str = ",".join(map(str, batch))
                    payload = {'action': 'list', 'details': 'All', 'ids': ids_str}
                    
                    try:
                        r = session.post(url, data=payload, timeout=120) # Aumentei timeout
                        if r.status_code == 200:
                            # --- CORREÇÃO ROBUSTA DE NAMESPACE ---
                            # Parseia o XML diretamente
                            try:
                                root = ET.fromstring(r.text)
                            except ET.ParseError:
                                # Fallback para bytes se houver erro de encoding
                                root = ET.fromstring(r.content)

                            # Remove namespaces de TODAS as tags recursivamente
                            for elem in root.iter():
                                if '}' in elem.tag:
                                    elem.tag = elem.tag.split('}', 1)[1]
                            # -------------------------------------

                            vulns_found = root.findall('.//VULN')
                            
                            # DEBUG: Se quiser ver se achou algo no lote
                            # print(f"Lote {i}: Encontrados {len(vulns_found)} vulns no XML")

                            for vuln in vulns_found:
                                try:
                                    qid_elem = vuln.find('QID')
                                    if qid_elem is not None:
                                        qid_val = qid_elem.text
                                        
                                        # Extração de CVEs
                                        cve_list = []
                                        cve_block = vuln.find('CVE_LIST')
                                        if cve_block is not None:
                                            for cve in cve_block.findall('CVE'):
                                                cid = cve.find('ID')
                                                if cid is not None:
                                                    cve_list.append(cid.text)

                                        kb_details[qid_val] = {
                                                'TITLE': vuln.find('TITLE').text if vuln.find('TITLE') is not None else 'N/A',
                                                'CATEGORY': vuln.find('CATEGORY').text if vuln.find('CATEGORY') is not None else 'N/A',
                                                'SOLUTION': vuln.find('SOLUTION').text if vuln.find('SOLUTION') is not None else 'Consulte o fabricante.',
                                                'CVE_IDS': ",".join(cve_list)
                                        }
                                except Exception as e_parse:
                                    print(f"Erro parseando uma VULN: {e_parse}")
                                    continue
                        else:
                            self.log(f"Erro API KB: {r.status_code} - {r.text[:100]}")

                    except Exception as e_req:
                        self.log(f"Erro requisição KB: {e_req}")
                        
                self.log(f">>> Detalhes coletados para {len(kb_details)} QIDs.")
                return kb_details
            # --- EXECUÇÃO PRINCIPAL ---
            all_ids, tags_by_id, tags_by_ip, asset_inventory = get_all_host_data()
            
            if not all_ids:
                self.log("Nenhum host encontrado.")
                session.close()
                self.after(0, lambda: self.finalizar_execucao(False, "Zero assets."))
                return
            
            full_csv_lines = []
            unique_qids = set()
            total_batches = (len(all_ids) // BATCH_SIZE) + 1
            
            self.log(f"Iniciando download de detecções para {len(all_ids)} ativos...")

            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for i in range(0, len(all_ids), BATCH_SIZE):
                    batch = all_ids[i:i+BATCH_SIZE]
                    batch_num = (i // BATCH_SIZE) + 1
                    futures.append(executor.submit(fetch_detections_batch, session, batch, batch_num, total_batches))
                
                for future in as_completed(futures):
                    raw_csv = future.result()
                    if raw_csv:
                        lines = raw_csv.strip().splitlines()
                        start_index = 0
                        header_found = False
                        for idx, line in enumerate(lines):
                            if '"QID"' in line.upper() or ",QID," in line.upper():
                                header_found = True
                                start_index = idx
                                break
                        
                        if header_found:
                            if not full_csv_lines: full_csv_lines.extend(lines[start_index:])
                            else: full_csv_lines.extend(lines[start_index+1:])
                            
                            for l in lines[start_index:]:
                                qids = re.findall(r'\b\d{4,8}\b', l)
                                unique_qids.update(qids)
            
            session.close() 

            if not full_csv_lines:
                self.after(0, lambda: self.finalizar_execucao(True, "Nenhuma vulnerabilidade encontrada."))
                return

            csv_str = "\n".join(full_csv_lines)
            kb_details = get_vulnerability_details(list(unique_qids))
            
            # --- ENRIQUECIMENTO COM NVD/THREAT INTEL (MULTI-KEY ROUND ROBIN & SMART TTL) ---
            if NVD_API_KEYS and usar_nvd:
                self.log(f"Iniciando Enriquecimento Threat Intel (NVD) em QIDs com CVEs usando {len(NVD_API_KEYS)} chave(s)...")
                nvd_integrator = NVDIntegration(api_keys=NVD_API_KEYS)
                enricher = ThreatIntelligenceEnricher(nvd_integrator)
                
                qids_with_cves = [qid for qid, data in kb_details.items() if data.get('CVE_IDS')]
                total_to_enrich = len(qids_with_cves)
                
                # Aumenta número de threads baseado no número de chaves disponíveis
                # Aprox 10 threads por chave, com um teto de segurança
                dynamic_workers = min(len(NVD_API_KEYS) * 10, 60)
                
                self.log(f"Iniciando enriquecimento paralelo ({dynamic_workers} threads) de {total_to_enrich} QIDs...")
                
                with ThreadPoolExecutor(max_workers=dynamic_workers) as executor:
                    future_to_qid = {executor.submit(enricher.enrich_vulnerability, kb_details[qid]): qid for qid in qids_with_cves}
                    completed = 0
                    for future in as_completed(future_to_qid):
                        qid = future_to_qid[future]
                        try:
                            intel = future.result()
                            kb_details[qid].update({
                                'Threat_Max_CVSS': intel['max_cvss'],
                                'Threat_Exploit': "SIM" if intel['has_exploit'] else "NAO",
                                'Threat_KEV': "SIM" if intel['cisa_kev'] else "NAO",
                                'CVSS_Vector': intel['cvss_vector']
                            })
                        except Exception as e_enrich:
                            print(f"Erro enriquecendo QID {qid}: {e_enrich}")
                        completed += 1
                        if completed % 50 == 0 or completed == total_to_enrich:
                            self.log(f"Enriquecendo CVEs... {completed}/{total_to_enrich}")
            elif not usar_nvd:
                self.log("Análise NVD/Threat Intel desativada pelo usuário.")
            else:
                self.log("Nenhuma NVD API KEY encontrada. Pulando enriquecimento de Threat Intel.")

            # CHAMA O ENRICH CSV AVANÇADO
            csv_path, excel_path = self.enrich_and_save_csv(csv_str, kb_details, cliente_selecionado, tags_by_id, tags_by_ip, periodo_selecionado, asset_inventory)
            
            if csv_path:
                summary = self.analyze_data_for_charts(csv_path, periodo_selecionado)
                if summary:
                    # Geração de Gráficos Avançados
                    self.log("Gerando Dashboard Executivo (Matplotlib)...")
                    chart_gen = ReportChartGenerator(os.path.dirname(csv_path))
                    chart_path = chart_gen.create_executive_summary_chart(summary)

                    ai_report = "Análise ignorada."
                    ai_model_used = "Nenhuma"
                    
                    if usar_ia:
                        self.log("Enviando dados para IA Generativa (Isso pode levar 15-30s)...")
                        # Agora desempacota o texto E o nome do modelo, passando a start_date
                        ai_report, ai_model_used = self.perform_ai_analysis(summary, segmento_selecionado, periodo_selecionado, start_date_str)
                        
                        self.log("-" * 40)
                        self.log(f">>> ANÁLISE GERADA COM SUCESSO")
                        self.log(f">>> MODELO IA UTILIZADO: {ai_model_used}")
                        self.log("-" * 40)
                    
                    output_dir = os.path.dirname(csv_path)
                    doc_path = self.generate_word_report_v2(cliente_selecionado, summary, ai_report, chart_path, output_dir, periodo_selecionado)
                    
                    # --- CARREGAR DADOS NO FLASK/DASHBOARD WEB ---
                    self.log("Carregando dados no Dashboard Web Interativo...")
                    try:
                        df_dashboard = pd.read_csv(csv_path, on_bad_lines='skip', low_memory=False)
                        # Aplica filtro de data se necessário
                        df_dashboard = self.filtrar_dataframe_por_data(df_dashboard, periodo_selecionado)
                        
                        # Cálculo de idade (Aging) para o Dashboard Web também
                        col_ff = next((c for c in df_dashboard.columns if 'FIRST' in c.upper()), None)
                        if col_ff:
                            df_dashboard['First Found'] = pd.to_datetime(df_dashboard[col_ff], errors='coerce', utc=True)
                            df_dashboard['Age_Days'] = (pd.Timestamp.now(timezone.utc) - df_dashboard['First Found']).dt.days.fillna(0)
                        
                        # Armazena na classe Global
                        shared_data.dataframe = df_dashboard
                        shared_data.client_name = cliente_selecionado
                        shared_data.updated_at = datetime.now()
                        self.log("Dados carregados com sucesso no Web Dashboard.")
                    except Exception as ed:
                        self.log(f"Erro ao carregar Dashboard Web: {ed}")

                    self.log(f"Excel: {excel_path}")
                    self.log(f"Word: {doc_path}")
                    self.after(0, lambda: self.finalizar_execucao(True, "Arquivos Gerados com Sucesso! Use o botão 'Abrir Dashboard Web'."))
            else:
                self.after(0, lambda: self.finalizar_execucao(False, "Erro ao salvar arquivos."))

        except Exception as e:
            self.log(f"ERRO FATAL: {e}")
            traceback.print_exc()
            self.after(0, lambda: self.finalizar_execucao(False))

    def enrich_and_save_csv(self, all_csv_data, kb_details, cliente_name, tags_by_id, tags_by_ip, periodo_str, asset_inventory):
        # --- CORREÇÃO DO ERRO DE LIMITE CSV ---
        try:
            csv.field_size_limit(sys.maxsize)
        except OverflowError:
            # Fallback para sistemas onde sys.maxsize causa overflow (Windows 32-bit legacy)
            csv.field_size_limit(2147483647) 
        # --------------------------------------

        self.log(f"Cruzando dados e gerando Excel Formatado...")
        csv_file = StringIO(all_csv_data)
        reader = csv.reader(csv_file)
        
        try:
            # PARTE 1: CSV RAW
            header_found = False
            source_header = []
            for line in reader:
                if not line: continue
                line_str = ",".join(line).upper()
                if "IP" in line_str and "QID" in line_str:
                    source_header = line
                    header_found = True
                    break
            
            if not header_found: return None, None
            
            cleaned_header = [h.strip().strip('"').upper() for h in source_header]
            try: qid_idx = cleaned_header.index('QID')
            except: qid_idx = -1

            # Índices para mapeamento
            host_id_idx = -1
            ip_col_idx = -1
            for idx, h in enumerate(cleaned_header):
                if h in ["HOST ID", "QUALYS HOST ID"]: host_id_idx = idx
                if h in ["IP", "IP ADDRESS", "IPADDRESS"]: ip_col_idx = idx

            # Novos headers incluindo Threat Intel e Vetor
            final_header = source_header + ["ASSET_TAGS", "Vuln_TITLE", "Vuln_CATEGORY", "Vuln_SOLUTION", "CVEs", "Threat_Exploit", "Threat_KEV", "Threat_Max_CVSS", "CVSS_Vector"]
            
            client_folder = re.sub(r'[<>:"/\\|?*]', '_', cliente_name).strip()
            output_folder = os.path.join(client_folder, datetime.now().strftime("%m - %B"))
            os.makedirs(output_folder, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%Hh%Mm")
            
            final_csv_file = os.path.join(output_folder, f"qualys_{client_folder}_{timestamp}-Intell.csv")

            with open(final_csv_file, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(final_header)
                for row in reader:
                    if len(row) <= qid_idx: continue
                    # --- CORREÇÃO DE STRIP PARA CORRESPONDÊNCIA CORRETA ---
                    qid = str(row[qid_idx]).strip() 
                    # ------------------------------------------------------
                    
                    tags_str = ""
                    if host_id_idx != -1 and len(row) > host_id_idx:
                        h_id = row[host_id_idx]
                        if h_id in tags_by_id: tags_str = tags_by_id[h_id]
                    if not tags_str and ip_col_idx != -1 and len(row) > ip_col_idx:
                        ip_val = row[ip_col_idx].strip().strip('"')
                        if ip_val in tags_by_ip: tags_str = tags_by_ip[ip_val]
                        elif ip_val.strip() in tags_by_ip: tags_str = tags_by_ip[ip_val.strip()]
                    
                    details = kb_details.get(qid, {})
                    title = details.get('TITLE', 'N/A')
                    category = details.get('CATEGORY', 'N/A')
                    solution = details.get('SOLUTION', 'N/A')
                    cves = details.get('CVE_IDS', '')
                    exploit = details.get('Threat_Exploit', '')
                    kev = details.get('Threat_KEV', '')
                    cvss = details.get('Threat_Max_CVSS', '')
                    vector = details.get('CVSS_Vector', '') # <--- VETOR

                    writer.writerow(row + [tags_str, title, category, solution, cves, exploit, kev, cvss, vector])

            # PARTE 2: EXCEL FORMATADO (RESTAURADO)
            final_excel_file = final_csv_file.replace('.csv', f'_FILTRADO_{periodo_str.replace(" ", "")}.xlsx')
            
            df = pd.read_csv(final_csv_file, on_bad_lines='skip', low_memory=False)
            df_filtrado = self.filtrar_dataframe_por_data(df, periodo_str)
            self.log(f"Linhas após filtro de data: {len(df_filtrado)}")

            # 2.1 Explosão de Tags do Inventário
            df_inventory = pd.DataFrame(asset_inventory)
            if not df_inventory.empty and 'Tags' in df_inventory.columns:
                unique_tags = set()
                for t_str in df_inventory['Tags'].dropna():
                    if t_str: unique_tags.update([p.strip() for p in t_str.split(',')])
                
                sorted_tags = sorted(list(unique_tags))
                for tag in sorted_tags:
                    df_inventory[tag] = df_inventory['Tags'].apply(lambda x: tag if x and tag in str(x).split(',') else "")

            # 2.2 Helper para Formatação
            def add_formatted_sheet(writer, df_to_write, sheet_name, tab_color, table_style='Table Style Medium 2'):
                if df_to_write.empty: return
                
                # --- FIX: REMOVER TIMEZONE PARA O EXCEL ---
                # Cria uma cópia para não afetar o DF original se for usado depois
                df_to_write = df_to_write.copy() 
                for col in df_to_write.columns:
                    if pd.api.types.is_datetime64_any_dtype(df_to_write[col]):
                        try:
                            df_to_write[col] = df_to_write[col].dt.tz_localize(None)
                        except: pass
                # ------------------------------------------

                df_to_write.columns = df_to_write.columns.astype(str)
                df_to_write.to_excel(writer, sheet_name=sheet_name, index=False, startrow=1, header=False)
                
                workbook = writer.book
                worksheet = writer.sheets[sheet_name]
                worksheet.set_tab_color(tab_color)
                
                (max_row, max_col) = df_to_write.shape
                column_settings = [{'header': col} for col in df_to_write.columns]
                
                worksheet.add_table(0, 0, max_row, max_col - 1, {
                    'columns': column_settings,
                    'style': table_style,
                    'name': re.sub(r'\W+', '_', sheet_name)
                })
                worksheet.set_column(0, max_col - 1, 18)

            # 2.3 Gravação com XlsxWriter
            col_status = next((c for c in df_filtrado.columns if 'STATUS' in c.upper() and 'VULN' in c.upper()), 'Status')
            col_title = 'Vuln_TITLE'

            with pd.ExcelWriter(final_excel_file, engine='xlsxwriter') as writer:
                # INVENTÁRIO
                if not df_inventory.empty:
                    add_formatted_sheet(writer, df_inventory, 'INVENTÁRIO', 'blue', 'Table Style Medium 9')

                # FIXED
                if col_status in df_filtrado.columns:
                    df_fixed = df_filtrado[df_filtrado[col_status].astype(str).str.upper().str.contains('FIXED')]
                    add_formatted_sheet(writer, df_fixed, 'FIXED', '#008000', 'Table Style Medium 7')

                # EOL
                if col_title in df_filtrado.columns:
                    mask_eol = df_filtrado[col_title].astype(str).str.contains(r'EOL|Obsolete|End of Life|Unsupported', case=False, regex=True)
                    df_eol = df_filtrado[mask_eol]
                    add_formatted_sheet(writer, df_eol, 'EOL', '#800080', 'Table Style Medium 12')

                # THREAT INTEL (CRÍTICAS COM EXPLOIT)
                if 'Threat_Exploit' in df_filtrado.columns:
                      df_exploit = df_filtrado[df_filtrado['Threat_Exploit'] == "SIM"]
                      if not df_exploit.empty:
                          add_formatted_sheet(writer, df_exploit, 'CRITICAL_EXPLOIT', '#C0392B', 'Table Style Medium 3')

                # ATIVAS
                if col_status in df_filtrado.columns:
                    df_active = df_filtrado[~df_filtrado[col_status].astype(str).str.upper().str.contains('FIXED')]
                    add_formatted_sheet(writer, df_active, 'Todas ATIVAS', '#FF0000', 'Table Style Medium 3')

            return final_csv_file, final_excel_file

        except Exception as e:
            self.log(f"Erro na geração do Excel: {e}")
            traceback.print_exc()
            return None, None




    def filtrar_dataframe_por_data(self, df, periodo_str):
        if not periodo_str or "Todo" in periodo_str: return df
        try:
            dias = int(periodo_str.split()[0])
            col_last = next((c for c in df.columns if 'LAST' in c.upper() and ('FOUND' in c.upper() or 'DETECTED' in c.upper())), None)
            if col_last:
                df[col_last] = pd.to_datetime(df[col_last], errors='coerce', utc=True)
                cutoff = pd.Timestamp.now(timezone.utc) - pd.Timedelta(days=dias)
                return df[df[col_last] >= cutoff]
        except: pass
        return df

    def analyze_data_for_charts(self, file_path, periodo_str):
        try:
            df = pd.read_csv(file_path, on_bad_lines='skip', low_memory=False)
            df = self.filtrar_dataframe_por_data(df, periodo_str)
            if df.empty: return None
        except: return None
        
        # Mapeamento de Colunas
        col_sev = next((c for c in df.columns if 'SEV' in c.upper()), None)
        col_title = next((c for c in df.columns if 'TITLE' in c.upper()), None)
        col_status = next((c for c in df.columns if 'STATUS' in c.upper()), None)
        col_ff = next((c for c in df.columns if 'FIRST' in c.upper()), None)
        col_fixed = next((c for c in df.columns if 'FIXED' in c.upper() and 'DATE' in c.upper()), None)
        
        df['Severity'] = pd.to_numeric(df[col_sev], errors='coerce').fillna(0) if col_sev else 0
        
        df['Age_Days'] = 0
        if col_ff:
            df['First Found'] = pd.to_datetime(df[col_ff], errors='coerce', utc=True)
            df['Age_Days'] = (pd.Timestamp.now(timezone.utc) - df['First Found']).dt.days.fillna(0)
            
        if col_fixed:
            df['Fixed_Date'] = pd.to_datetime(df[col_fixed], errors='coerce', utc=True)

        # Risk Score (Técnico)
        df['Risk_Score'] = df['Severity'] * 10
        if col_title:
            crit = df[col_title].astype(str).str.upper().str.contains(r'RCE|SQL|RANSOMWARE', regex=True)
            df.loc[crit, 'Risk_Score'] *= 2

        # 1. Status Counts
        stats = {'Active': 0, 'Fixed': 0, 'Re-Opened': 0, 'New': 0}
        if col_status:
            s = df[col_status].astype(str).str.upper()
            stats['Fixed'] = s[s.str.contains('FIXED')].count()
            stats['Active'] = s[s.str.contains('ACTIVE')].count()
            stats['New'] = s[s.str.contains('NEW')].count()
            stats['Re-Opened'] = s[s.str.contains('RE-OPENED')].count()

        # 2. Severity Counts
        severity_counts = df['Severity'].value_counts().to_dict()

        # 3. Aging Buckets
        aging = {
            '0-30': len(df[df['Age_Days'] <= 30]),
            '31-60': len(df[(df['Age_Days'] > 30) & (df['Age_Days'] <= 60)]),
            '61-90': len(df[(df['Age_Days'] > 60) & (df['Age_Days'] <= 90)]),
            '90+': len(df[df['Age_Days'] > 90])
        }

        # 4. Risk Score Normalizado (0-100) para o Gauge
        avg_sev = df['Severity'].mean()
        total_vulns = len(df)
        if total_vulns > 0:
            crit_active = len(df[(df['Severity'] >= 4) & (df['Status'] != 'Fixed')]) if col_status else len(df[df['Severity'] >= 4])
            ratio_crit = crit_active / total_vulns
        else:
            ratio_crit = 0
        
        # Fórmula customizada de risco
        risk_norm = (avg_sev / 5 * 40) + (ratio_crit * 60)
        risk_norm = min(risk_norm * 1.8, 100) 

        # 5. Top Remediation
        top_remediation = []
        try:
            grp = ['QID', col_title] if col_title else ['QID']
            col_ip = next((c for c in df.columns if 'IP' in c.upper()), 'IP')
            
            # Filtra apenas não corrigidas para o Top Remediation
            df_active = df
            if col_status:
                df_active = df[~df[col_status].astype(str).str.upper().str.contains('FIXED')]

            remed = df_active[df_active['Severity'] >= 3].groupby(grp).agg(
                Hosts_Count=(col_ip, 'nunique'),
                Max_Sev=('Severity', 'max'),
                Risk_Sum=('Risk_Score', 'sum')
            ).reset_index().sort_values('Risk_Sum', ascending=False).head(20)
            
            remed.rename(columns={col_title: 'Vuln_TITLE'}, inplace=True)
            top_remediation = remed.to_dict('records')
        except: pass

        # 6. MTTR
        mttr = {}
        if col_fixed and not df.empty:
            df_fixed = df[df['Fixed_Date'].notnull()].copy()
            if not df_fixed.empty:
                df_fixed['Time_To_Fix'] = (df_fixed['Fixed_Date'] - df_fixed['First Found']).dt.days
                mttr = df_fixed.groupby('Severity')['Time_To_Fix'].mean().round(1).to_dict()

        return {
            'status_counts': stats,
            'severity_counts': severity_counts,
            'aging_buckets': aging,
            'risk_score_norm': risk_norm,
            'top_remediation': top_remediation,
            'avg_time_to_fix': mttr,
            'smart_insights': {'old_crit_count': len(df[(df['Age_Days'] > 90) & (df['Severity'] >= 4)])}
        }

    # --- NOVO MÉTODO DE RELATÓRIO FORMATADO ---
    def generate_word_report_v2(self, client, summary, ai_text, chart_path, out_dir, periodo):
        try:
            doc = Document()
            
            # --- Configuração de Estilos Básicos ---
            style = doc.styles['Normal']
            font = style.font
            font.name = 'Calibri'
            font.size = Pt(11)
            
            # --- 1. CAPA ---
            # Adiciona espaçamento vertical
            doc.add_paragraph("\n" * 4)
            
            # Título Principal
            title_head = doc.add_heading(f'Relatório Executivo de Segurança', 0)
            title_head.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            subtitle = doc.add_paragraph(f"Análise de Vulnerabilidades & Risco Cibernético")
            subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
            subtitle.runs[0].font.size = Pt(16)
            subtitle.runs[0].font.color.rgb = RGBColor(128, 128, 128) # Cinza
            
            doc.add_paragraph("\n" * 2)
            
            # Tabela de Metadados da Capa (Centralizada e sem bordas visíveis para layout)
            table_cover = doc.add_table(rows=3, cols=1)
            table_cover.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            row0 = table_cover.rows[0].cells[0]
            p0 = row0.paragraphs[0]
            p0.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run0 = p0.add_run(f"CLIENTE: {client.upper()}")
            run0.bold = True
            run0.font.size = Pt(14)
            
            row1 = table_cover.rows[1].cells[0]
            p1 = row1.paragraphs[0]
            p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p1.add_run(f"Período Analisado: {periodo}")
            
            row2 = table_cover.rows[2].cells[0]
            p2 = row2.paragraphs[0]
            p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p2.add_run(f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}")
            
            doc.add_page_break()
            
            # --- 2. DASHBOARD VISUAL ---
            doc.add_heading('1. Panorama Visual (Dashboard)', 1)
            if chart_path and os.path.exists(chart_path):
                doc.add_picture(chart_path, width=Inches(6.2))
                last_paragraph = doc.paragraphs[-1] 
                last_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            doc.add_paragraph("\n")

            # --- 3. INDICADORES CHAVE (TABELA FORMATADA) ---
            doc.add_heading('2. Indicadores Críticos (KPIs)', 1)
            
            # Cria tabela com estilo
            table = doc.add_table(rows=1, cols=3)
            table.style = 'Medium Grid 1 Accent 1' # Estilo azulado profissional
            
            # Cabeçalho
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = 'Vulnerabilidades Ativas'
            hdr_cells[1].text = 'Vulnerabilidades Corrigidas'
            hdr_cells[2].text = 'Legado Crítico (>90d)'
            
            # Dados
            row_cells = table.add_row().cells
            
            # Formatação dos números (Grande e Centralizado)
            def format_cell_big(cell, text, color=None):
                p = cell.paragraphs[0]
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run = p.add_run(str(text))
                run.bold = True
                run.font.size = Pt(24)
                if color: run.font.color.rgb = color
            
            format_cell_big(row_cells[0], summary['status_counts']['Active'], RGBColor(200, 0, 0)) # Vermelho
            format_cell_big(row_cells[1], summary['status_counts']['Fixed'], RGBColor(0, 128, 0)) # Verde
            format_cell_big(row_cells[2], summary['smart_insights']['old_crit_count'], RGBColor(255, 140, 0)) # Laranja
            
            doc.add_paragraph("\n")
            
            # --- 4. ANÁLISE DE IA (COM PARSER DE MARKDOWN) ---
            doc.add_heading('3. Análise Estratégica & Priorização (AI)', 1)
            
            # Box de introdução
            intro = doc.add_paragraph()
            intro_run = intro.add_run("A análise abaixo foi gerada por Inteligência Artificial Generativa baseada no contexto do segmento e nos dados técnicos coletados.")
            intro_run.italic = True
            intro_run.font.size = Pt(9)
            intro_run.font.color.rgb = RGBColor(100, 100, 100)
            
            doc.add_paragraph("-" * 90)
            
            # Processa o texto da IA linha por linha para formatar
            self._apply_markdown_formatting(doc, ai_text)
            
            # Salvar
            fname = os.path.join(out_dir, f"Relatorio_Executivo_{client}_{datetime.now().strftime('%Y%m%d_%H%M')}.docx")
            doc.save(fname)
            return fname
        except Exception as e:
            traceback.print_exc()
            return f"Erro Word: {e}"

    def _apply_markdown_formatting(self, doc, text):
        """
        Converte Markdown básico (Headers #, Bold **, Listas -) para formato Word nativo.
        """
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Headers
            if line.startswith('### '):
                h = doc.add_heading(line.replace('### ', ''), level=3)
                h.runs[0].font.color.rgb = RGBColor(50, 50, 50)
            elif line.startswith('## '):
                h = doc.add_heading(line.replace('## ', ''), level=2)
                h.runs[0].font.color.rgb = RGBColor(30, 60, 100)
            elif line.startswith('# '):
                doc.add_heading(line.replace('# ', ''), level=1)
            
            # Listas
            elif line.startswith('- ') or line.startswith('* '):
                p = doc.add_paragraph(style='List Bullet')
                clean_text = line[2:]
                self._parse_bold_runs(p, clean_text)
            
            # Texto Normal (com negrito)
            else:
                p = doc.add_paragraph()
                self._parse_bold_runs(p, line)

    def _parse_bold_runs(self, paragraph, text):
        """Auxiliar para processar **negrito** dentro de um parágrafo"""
        parts = re.split(r'(\*\*.*?\*\*)', text)
        for part in parts:
            if part.startswith('**') and part.endswith('**'):
                run = paragraph.add_run(part.replace('**', ''))
                run.bold = True
            else:
                paragraph.add_run(part)

if __name__ == "__main__":
    app = ModernQualysApp()
    app.mainloop()