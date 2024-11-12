import streamlit as st
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
from io import BytesIO

# Função para gerar uma chave com base em uma senha e um sal
def gerar_chave_senha(senha, sal):
    senha_bytes = senha.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=100000,
        backend=default_backend()
    )
    chave = base64.urlsafe_b64encode(kdf.derive(senha_bytes))
    return chave

# Função para criptografar o arquivo
def criptografar_arquivo(dados, senha):
    try:
        sal = os.urandom(16)
        chave = gerar_chave_senha(senha, sal)

        fernet = Fernet(chave)
        dados_criptografados = fernet.encrypt(dados)

        # Retorna o sal concatenado com os dados criptografados
        return sal + dados_criptografados
    
    except Exception as e:
        st.error(f"Erro ao criptografar o arquivo: {e}")
        return None

# Função para descriptografar o arquivo
def descriptografar_arquivo(dados, senha):
    try:
        sal = dados[:16]
        dados_criptografados = dados[16:]

        chave = gerar_chave_senha(senha, sal)

        fernet = Fernet(chave)
        dados_descriptografados = fernet.decrypt(dados_criptografados)

        return dados_descriptografados
    
    except Exception as e:
        st.error(f"Erro ao descriptografar o arquivo: {e}")
        return None

# Interface com Streamlit
st.title("Projeto de Criptografia de Arquivos")

# Escolha de ação: Criptografar ou Descriptografar
opcao = st.selectbox("Escolha a ação:", ["Criptografar", "Descriptografar"])

# Upload do arquivo
arquivo = st.file_uploader("Selecione o arquivo", type=["txt", "pdf", "png", "jpg", "jpeg", "docx","encrypted"])

# Campo para a senha
senha = st.text_input("Digite a senha", type="password")

# Botão para executar a ação
if st.button("Executar"):
    if arquivo is not None and senha:
        # Lê os dados do arquivo carregado
        dados = arquivo.read()
        
        if opcao == "Criptografar":
            dados_processados = criptografar_arquivo(dados, senha)
            if dados_processados is not None:
                # Converte o conteúdo criptografado em um arquivo para download
                st.download_button(
                    label="Baixar arquivo criptografado",
                    data=BytesIO(dados_processados),
                    file_name=f"{arquivo.name}.encrypted",
                    mime="application/octet-stream"
                )

        elif opcao == "Descriptografar":
            dados_processados = descriptografar_arquivo(dados, senha)
            if dados_processados is not None:
                # Converte o conteúdo descriptografado em um arquivo para download
                st.download_button(
                    label="Baixar arquivo descriptografado",
                    data=BytesIO(dados_processados),
                    file_name=arquivo.name.replace(".encrypted", ""),
                    mime="application/octet-stream"
                )
    else:
        st.error("Por favor, selecione um arquivo e insira uma senha.")