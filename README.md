# QualysIA-Analyzer
Uma ferramenta avançada de orquestração de vulnerabilidades que integra a API da Qualys, enriquecimento de Threat Intel (NVD/CVE) e Inteligência Artificial Generativa (Gemini/Groq) para criar relatórios executivos estratégicos, dashboards interativos (Web/Flask) e planilhas automatizadas.


**VulnManager AI** é uma solução completa de orquestração e análise de vulnerabilidades projetada para transformar dados brutos de scans (Qualys VMDR) em inteligência acionável. 

A ferramenta combina uma interface gráfica moderna, processamento de dados robusto, enriquecimento de Threat Intelligence (NVD) e o poder da **Inteligência Artificial Generativa** (Google Gemini ou Groq/Llama-3) para atuar como um "CISO Virtual", gerando análises de risco contextualizadas por setor de negócio.

## 🚀 Funcionalidades Principais

### 🧠 Inteligência Artificial & Engenharia de Prompt
- **Análise Executiva Automatizada:** Utiliza LLMs (Gemini Pro ou Llama-3) para analisar o cenário de vulnerabilidades.
- **Contexto de Negócio:** Gera relatórios adaptados ao setor da empresa (Financeiro, Saúde, Varejo, Indústria, etc.), citando regulações específicas (LGPD, PCI-DSS, HIPAA, BACEN).
- **Priorização Inteligente:** Seleciona o "Top 5" vulnerabilidades críticas baseadas em risco real ao negócio, não apenas no CVSS.

### 🔍 Integração & Dados
- **Qualys API (v2, v3, v4):** Download automático de inventário de ativos (Host Assets) e detecções de vulnerabilidades.
- **Threat Intel (NVD):** Enriquecimento de CVEs usando a API do NIST/NVD com estratégia de **Round Robin** (múltiplas chaves) e **Smart TTL Caching** (SQLite) para evitar *throttling* e otimizar performance.
- **Processamento Paralelo:** Uso de `ThreadPoolExecutor` para downloads e processamento de dados em alta velocidade.

### 📊 Visualização & Relatórios
- **Dashboard Web Interativo:** Servidor Flask integrado com gráficos dinâmicos (Plotly) acessíveis via navegador.
- **Relatórios Word (.docx):** Geração automática de relatórios executivos formatados, incluindo gráficos estáticos (Matplotlib) e o texto da análise da IA.
- **Excel Formatado (.xlsx):** Planilhas com abas separadas por status (Ativas, Fixed, EOL), formatação condicional e estilos de tabela.
- **GUI Desktop:** Interface moderna construída com `customtkinter` (Dark Mode).

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3.10+
- **GUI:** CustomTkinter
- **Web/Dashboard:** Flask, Plotly, HTML5/Bootstrap
- **Data Science:** Pandas, NumPy, Matplotlib
- **AI/LLM:** Google Generative AI SDK, Groq SDK
- **APIs:** Requests, XML parsing (ElementTree)
- **Reporting:** Python-docx, XlsxWriter
- **Database:** SQLite (para cache de Threat Intel)

## Configuração do .env
Crie um arquivo .env na raiz do projeto e configure suas chaves de API e credenciais. O sistema suporta múltiplos clientes Qualys.

Snippet de código ---------------------------------------------------------------------

# --- Configurações de IA ---
GEMINI_API_KEY=sua_chave_google_aistudio
GROQ_API_KEY=sua_chave_groq_cloud

# --- Configurações NVD (Threat Intel) ---
# Você pode colocar várias chaves separadas por vírgula para balanceamento de carga
NVD_API_KEYS=chave_nvd_1,chave_nvd_2,chave_nvd_3

# --- Credenciais Qualys (Por Cliente) ---
# Substitua "CLIENTE1" pelo nome que aparecerá na interface
QUALYS_base_url_CLIENTE1=[https://qualysapi.qg2.apps.qualys.com]
QUALYS_USER_CLIENTE1=seu_usuario_qualys
QUALYS_PASS_CLIENTE1=sua_senha_qualys

QUALYS_base_url_CLIENTE2=[https://qualysapi.qg3.apps.qualys.com]
QUALYS_USER_CLIENTE2=outro_usuario
QUALYS_PASS_CLIENTE2=outra_senha

-----------------------------------------------------------------------------------------------

Aqui está uma proposta completa e profissional para o seu repositório no GitHub. Preparei o conteúdo no formato README.md (padrão do GitHub), além de uma descrição curta para a seção "About" e uma lista de dependências (requirements.txt).

1. Descrição Curta (Para a seção "About" do GitHub)
VulnManager AI: Uma ferramenta avançada de orquestração de vulnerabilidades que integra a API da Qualys, enriquecimento de Threat Intel (NVD/CVE) e Inteligência Artificial Generativa (Gemini/Groq) para criar relatórios executivos estratégicos, dashboards interativos (Web/Flask) e planilhas automatizadas.

2. Conteúdo do README.md (Copie e cole isso no arquivo README.md)
Markdown

# 🛡️ VulnManager AI

**VulnManager AI** é uma solução completa de orquestração e análise de vulnerabilidades projetada para transformar dados brutos de scans (Qualys VMDR) em inteligência acionável. 

A ferramenta combina uma interface gráfica moderna, processamento de dados robusto, enriquecimento de Threat Intelligence (NVD) e o poder da **Inteligência Artificial Generativa** (Google Gemini ou Groq/Llama-3) para atuar como um "CISO Virtual", gerando análises de risco contextualizadas por setor de negócio.

## 🚀 Funcionalidades Principais

### 🧠 Inteligência Artificial & Engenharia de Prompt
- **Análise Executiva Automatizada:** Utiliza LLMs (Gemini Pro ou Llama-3) para analisar o cenário de vulnerabilidades.
- **Contexto de Negócio:** Gera relatórios adaptados ao setor da empresa (Financeiro, Saúde, Varejo, Indústria, etc.), citando regulações específicas (LGPD, PCI-DSS, HIPAA, BACEN).
- **Priorização Inteligente:** Seleciona o "Top 5" vulnerabilidades críticas baseadas em risco real ao negócio, não apenas no CVSS.

### 🔍 Integração & Dados
- **Qualys API (v2, v3, v4):** Download automático de inventário de ativos (Host Assets) e detecções de vulnerabilidades.
- **Threat Intel (NVD):** Enriquecimento de CVEs usando a API do NIST/NVD com estratégia de **Round Robin** (múltiplas chaves) e **Smart TTL Caching** (SQLite) para evitar *throttling* e otimizar performance.
- **Processamento Paralelo:** Uso de `ThreadPoolExecutor` para downloads e processamento de dados em alta velocidade.

### 📊 Visualização & Relatórios
- **Dashboard Web Interativo:** Servidor Flask integrado com gráficos dinâmicos (Plotly) acessíveis via navegador.
- **Relatórios Word (.docx):** Geração automática de relatórios executivos formatados, incluindo gráficos estáticos (Matplotlib) e o texto da análise da IA.
- **Excel Formatado (.xlsx):** Planilhas com abas separadas por status (Ativas, Fixed, EOL), formatação condicional e estilos de tabela.
- **GUI Desktop:** Interface moderna construída com `customtkinter` (Dark Mode).

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3.10+
- **GUI:** CustomTkinter
- **Web/Dashboard:** Flask, Plotly, HTML5/Bootstrap
- **Data Science:** Pandas, NumPy, Matplotlib
- **AI/LLM:** Google Generative AI SDK, Groq SDK
- **APIs:** Requests, XML parsing (ElementTree)
- **Reporting:** Python-docx, XlsxWriter
- **Database:** SQLite (para cache de Threat Intel)

## ⚙️ Instalação e Configuração

### 1. Clone o repositório
```bash
git clone
cd QualysIA-Analyzer
2. Instale as dependências
Crie um ambiente virtual e instale os pacotes necessários:

Bash

pip install -r requirements.txt
