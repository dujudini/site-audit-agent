# CLAUDE.md

Especificação do projeto. Leia inteiro antes de escrever qualquer linha.

---

## 1. O que é isso

Um agente que audita um site a partir de uma URL. Ele coleta dados, decide sozinho o que investigar em seguida com base no que encontrou, e entrega um relatório priorizado com evidência para cada achado.

**Nome do projeto:** `site-audit-agent`
**Autor:** Eduardo Dini (`dujudini`)
**Público:** repositório público no GitHub, usado como peça de portfólio para vagas de AI Engineer nos EUA e Europa, e como ferramenta real de prospecção de consultoria.

Esse duplo propósito manda em várias decisões abaixo. O código precisa funcionar de verdade **e** precisa ser legível por um engenheiro que abriu o repositório para decidir se chama o Eduardo para uma entrevista.

---

## 2. A decisão central

**Isso não é um scanner linear.** Um script que roda vinte checagens em sequência e imprime o resultado não tem valor nenhum aqui, porque qualquer pessoa escreve em uma tarde.

O que dá valor é o **loop adaptativo**: o agente roda uma coleta, lê o resultado, e escolhe a próxima ferramenta com base no que descobriu.

Exemplos do comportamento esperado:

- Detectou WordPress → investiga versão exposta, `readme.html`, `/wp-json/wp/v2/users`, plugins visíveis no HTML, XML-RPC.
- TTFB acima de 800ms → investiga cabeçalhos de cache, compressão, CDN, tempo de resposta da origem.
- Sem CDN e com formulário de login exposto → investiga cabeçalhos de segurança e superfície de ataque.
- Certificado perto de expirar → sobe a prioridade e para de gastar iteração com performance.

Se o agente sempre roda a mesma sequência independentemente do que acha, o projeto falhou no seu objetivo principal.

---

## 3. Regras invioláveis

Estas não são negociáveis. Se alguma implementação conflitar com elas, a implementação está errada.

### 3.1 Ferramentas determinísticas, LLM orquestrando

Toda coleta de dado é código Python normal, testável, sem LLM. HTTP, DNS, TLS, parsing de HTML, PageSpeed: tudo determinístico.

O LLM faz três coisas e só três:
1. escolhe qual ferramenta chamar em seguida
2. interpreta o retorno das ferramentas
3. redige a explicação e a recomendação de cada achado

O LLM **nunca** inventa um dado. Se um número aparece no relatório, ele veio de uma ferramenta.

### 3.2 Todo achado carrega evidência

Um `Finding` sem campo `evidence` preenchido a partir de retorno de ferramenta é inválido e deve ser descartado na validação, não apenas avisado. Isso mata alucinação por construção, não por prompt.

### 3.3 Coleta passiva apenas

- Respeitar `robots.txt`.
- Nada de tentativa de exploração, fuzzing, brute force, injeção ou bypass de autenticação.
- Nada de scan de porta.
- Rate limit padrão de no máximo 1 requisição por segundo por host.
- `User-Agent` identificável e honesto, com URL do repositório.

O README precisa dizer explicitamente que a ferramenta é para sites próprios ou com autorização.

### 3.4 Guardrails de execução

Toda execução tem teto, configurável e com default seguro:

- máximo de iterações do loop (default 12)
- máximo de custo em USD por execução (default 0.50)
- máximo de chamadas de ferramenta (default 30)
- timeout global (default 180s)
- timeout por ferramenta (default 15s)

Ao bater qualquer teto, o agente encerra com o que tem e marca o relatório como `partial`. Nunca trava, nunca estoura silencioso.

### 3.5 Instrumentação não é opcional

Cada execução registra custo em USD, tokens de entrada e saída por etapa, latência por chamada de ferramenta, número de iterações, e a sequência de decisões tomadas. Sem isso o README não tem número, e sem número o repositório não convence ninguém.

---

## 4. Stack

```
Python 3.12
httpx              requisições HTTP assíncronas
anthropic          SDK oficial, com tool use
pydantic v2        schema dos achados e validação
typer              CLI
rich               saída no terminal
pytest             testes e evals
python-dotenv      configuração
```

**Sem framework de agente.** Nada de LangChain, LlamaIndex, CrewAI. O loop precisa estar visível no repositório, escrito à mão, porque é justamente ele que o entrevistador quer ver. Um framework esconde a parte que dá valor ao projeto.

Modelos: usar Sonnet para o loop de decisão e Haiku para tarefas baratas de classificação, se houver. Deixar os identificadores em `config.py` lendo de variável de ambiente, nunca hardcoded no meio do código. Confirmar os identificadores atuais na documentação da Anthropic antes de fixar o default.

---

## 5. Antes de escrever código

Existem três arquivos anteriores do Eduardo que podem ser reaproveitados. **Leia os três primeiro** e reporte o que dá para aproveitar antes de começar:

- `scanner.py`
- `audit.py`
- `report_pdf.py`

Provavelmente boa parte das coletas vira ferramenta do agente com uma casca fina em volta. Não reescreva o que já funciona. Se o código existente estiver síncrono e o projeto for assíncrono, adapte em vez de jogar fora.

Se os arquivos não estiverem na pasta, pergunte antes de seguir.

---

## 6. Estrutura

```
site-audit-agent/
├── README.md
├── CLAUDE.md
├── pyproject.toml
├── .env.example
├── src/
│   └── audit_agent/
│       ├── __init__.py
│       ├── cli.py            entrada Typer
│       ├── config.py         limites, modelos, defaults
│       ├── agent.py          o loop, escrito à mão
│       ├── schemas.py        modelos Pydantic
│       ├── instrumentation.py custo, tokens, latência, trace
│       ├── prompts/
│       │   ├── system.md
│       │   └── report.md
│       ├── tools/
│       │   ├── __init__.py   registry e schemas JSON
│       │   ├── http_probe.py
│       │   ├── tls_check.py
│       │   ├── dns_check.py
│       │   ├── tech_detect.py
│       │   ├── headers_audit.py
│       │   ├── perf_probe.py
│       │   ├── content_probe.py
│       │   └── wordpress_probe.py
│       └── report/
│           ├── markdown.py
│           └── json_out.py
├── evals/
│   ├── cases.yaml
│   ├── test_evals.py
│   └── fixtures/
└── tests/
```

---

## 7. Schema dos achados

Em `schemas.py`, com Pydantic v2. Esse é o contrato do sistema inteiro.

```python
class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Category(str, Enum):
    security = "security"
    performance = "performance"
    seo = "seo"
    availability = "availability"
    maintenance = "maintenance"

class Evidence(BaseModel):
    tool: str            # qual ferramenta produziu
    raw: dict            # retorno bruto, sem interpretação
    captured_at: datetime

class Finding(BaseModel):
    id: str
    title: str           # curto, sem adjetivo
    category: Category
    severity: Severity
    explanation: str     # o que é e por que importa, redigido pelo LLM
    recommendation: str  # o que fazer, acionável
    effort: Literal["quick", "moderate", "involved"]
    evidence: list[Evidence]   # nunca vazio

class AuditReport(BaseModel):
    url: str
    status: Literal["complete", "partial"]
    findings: list[Finding]
    run: RunMetrics      # custo, tokens, latência, iterações, trace de decisões
```

`explanation` e `recommendation` são os únicos campos que o LLM escreve livremente. Todo o resto é derivado de ferramenta ou de regra.

---

## 8. O loop

Em `agent.py`, escrito de forma que dê para ler de cima a baixo e entender:

1. Executa a coleta base: `http_probe`, `dns_check`, `tls_check`, `tech_detect`. Sempre essas quatro, é o ponto de partida.
2. Entra no loop. A cada iteração, manda o estado acumulado ao modelo com as ferramentas disponíveis e pergunta qual chamar em seguida e por quê.
3. Executa a ferramenta escolhida, registra latência e resultado, acrescenta ao estado.
4. Registra no trace a decisão e a justificativa do modelo.
5. Repete até o modelo declarar que terminou, ou até bater um teto.
6. Fase final separada: com todo o estado coletado, gera os `Finding`, prioriza e escreve o relatório.

A geração de achados é uma **etapa distinta** do loop de investigação. Não misture as duas. Investigar e concluir são operações diferentes e o repositório deve deixar isso óbvio.

O trace de decisões é entregável, não log de debug. Ele vai no relatório e vai no README.

---

## 9. Ferramentas

Cada uma é uma função pura com schema JSON declarado, que recebe parâmetros validados e devolve dict serializável. Cada uma tem teste unitário com fixture, sem rede.

| Ferramenta | O que coleta |
|---|---|
| `http_probe` | status, cabeçalhos, redirects, TTFB, tamanho |
| `tls_check` | emissor, validade, dias para expirar, versão do protocolo |
| `dns_check` | A, AAAA, MX, TXT, NS, detecção de CDN |
| `tech_detect` | CMS, framework, servidor, analytics, versões expostas |
| `headers_audit` | CSP, HSTS, X-Frame-Options, cookies, referrer policy |
| `perf_probe` | PageSpeed Insights ou métricas próprias, compressão, cache |
| `content_probe` | title, meta, headings, robots.txt, sitemap, canonical |
| `wordpress_probe` | versão, REST users, xmlrpc, readme, plugins no HTML |

`wordpress_probe` só entra no registry se `tech_detect` identificou WordPress. Ferramenta irrelevante não deve aparecer para o modelo. Registry dinâmico é parte do design.

---

## 10. Evals

Isso é o item mais raro em portfólio de dev e o mais valorizado em vaga de IA aplicada. Não deixe para o fim.

`evals/cases.yaml` guarda casos com respostas conhecidas:

```yaml
- name: expired_tls
  fixture: fixtures/expired_tls/
  must_find:
    - category: security
      severity: critical
      matches: "certificate"
  must_not_find:
    - category: seo
```

`test_evals.py` roda o agente contra as fixtures, sem rede, e mede:

- **recall**: dos problemas plantados, quantos o agente achou
- **precisão**: dos achados, quantos eram reais
- **custo médio** por execução
- **iterações médias** até concluir

Mínimo de 8 casos, cobrindo pelo menos: TLS expirado, sem cabeçalhos de segurança, WordPress com versão exposta, TTFB alto, sem sitemap, redirect em cadeia, site saudável (o agente não pode inventar problema), e site fora do ar.

O caso do site saudável é o mais importante de todos. Agente que sempre acha alguma coisa é agente inútil.

Os números dos evals vão no README. É isso que transforma o repositório de "mais um projeto" em prova de trabalho.

---

## 11. README

Escrito **em inglês**, e é a peça mais importante do repositório depois do código. Quem contrata lê o README e olha três arquivos.

Estrutura obrigatória:

1. **O problema**, em duas frases. Sem preâmbulo.
2. **Demo**: um GIF ou asciinema de uma execução real. Isso vale mais que qualquer parágrafo.
3. **Arquitetura**: um diagrama, e a explicação de por que as ferramentas são determinísticas e o LLM só orquestra.
4. **Como o loop decide**: um trace real de execução, mostrando a sequência de decisões e a justificativa de cada uma. Essa seção é o coração do README.
5. **Números**: custo médio em USD por auditoria, latência média, iterações médias, precisão e recall dos evals. Números reais, medidos, não estimados.
6. **Guardrails**: os tetos, o respeito ao robots.txt, e a limitação a coleta passiva.
7. **O que quebrou e como resolvi**: uma seção curta e honesta. Quase ninguém escreve isso e é o que mais impressiona.
8. **Instalação e uso.**
9. **Limitações conhecidas.**

Sobre o texto do README: sem travessão, sem tríade forçada, sem "não é X, é Y", sem frase de efeito no fim de parágrafo, sem advérbio decorativo. Afirmação direta com número. Se existir a skill `stop-slop` no ambiente, aplique nela.

---

## 12. Convenções

- Type hints em tudo. `mypy` limpo.
- `ruff` para lint e format.
- Docstring só onde o código não se explica sozinho. Nada de docstring repetindo o nome da função.
- Nada de `print` fora do CLI. Logging estruturado no resto.
- Segredo só via variável de ambiente. `.env` no `.gitignore`, `.env.example` versionado.
- Commits em inglês, no imperativo, uma mudança por commit. O histórico é lido por quem avalia o repositório.
- Sem comentário explicando o que o código já diz. Comentário serve para explicar decisão, não sintaxe.

---

## 13. Fases

Não avance de fase sem cumprir o critério de pronto. Ao terminar cada fase, pare e reporte.

**Fase 1: fundação**
Estrutura, `pyproject.toml`, config, schemas, três ferramentas (`http_probe`, `dns_check`, `tls_check`) com teste unitário cada. Sem LLM ainda.
*Pronto quando:* `pytest` passa e as três ferramentas rodam contra um site real pelo CLI.

**Fase 2: o loop**
`agent.py` com tool use, registry, guardrails, instrumentação. Saída em JSON bruto.
*Pronto quando:* uma execução real completa mostra no trace pelo menos uma decisão condicionada ao resultado anterior.

**Fase 3: ferramentas restantes e relatório**
As cinco ferramentas que faltam, registry dinâmico, geração de `Finding` com validação de evidência, relatório em Markdown.
*Pronto quando:* auditoria completa de um site WordPress real produz relatório priorizado com evidência em todo achado.

**Fase 4: evals**
Fixtures, casos, métricas de precisão e recall.
*Pronto quando:* os 8 casos rodam sem rede e o caso do site saudável não gera achado falso.

**Fase 5: publicação**
README com trace real e números medidos, GIF da demo, licença MIT, GitHub Actions rodando testes e evals.
*Pronto quando:* alguém que nunca viu o projeto instala e roda seguindo só o README.

---

## 14. O que não fazer

- Não adicione framework de agente.
- Não use LLM para coletar dado que código consegue coletar.
- Não gere achado sem evidência de ferramenta.
- Não implemente exploração de vulnerabilidade, nem em modo opcional.
- Não deixe custo ou latência sem medição.
- Não escreva README com adjetivo no lugar de número.
- Não adicione interface web antes da Fase 5.
- Não crie abstração para um caso de uso só.

---

## 15. Quando parar e perguntar

- Os arquivos `scanner.py`, `audit.py` ou `report_pdf.py` não estão na pasta.
- Uma escolha de arquitetura conflita com alguma regra da seção 3.
- Uma ferramenta precisaria fazer requisição que passe do limite de coleta passiva.
- Terminou uma fase.
