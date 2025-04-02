# Network Analyze

**Network Analyze** é uma ferramenta de análise de tráfego de rede desenvolvida em Python, utilizando `streamlit` para construção interface web e `scapy` para a captura e simulação de pacotes em tempo real.

## 📌 Funcionalidades

- Captura de pacotes em tempo real
- Exibição dos pacotes capturados com detalhes
- Filtros para análise de pacotes específicos
- Algoritmos para detecção de ataques de rede
- Interface web amigável com `streamlit`

## 🛠 Tecnologias Utilizadas

- **Python**
- **Scapy** (para captura e manipulação de pacotes)
- **Streamlit** (para a interface)

## 🚀 Como Executar

### Pré-requisitos
Certifique-se de ter o docker instalado e as dependências necessárias:

```bash
pip install -r ./app/requirements.txt
```

### Executando o Projeto

```bash
streamlit run ./app/app.py
```

### Executando simulações de ataque na rede
A execução irá gerar dois containers que irão simular ataques aleatórios na rede conectada, é necessária configuração do arquivo compose.yaml
```bash
docker compose
```