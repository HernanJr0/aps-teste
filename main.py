import streamlit as st
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
from io import BytesIO
import secrets

def verificar_forca_senha(senha):
    criterios = [
        any(c.islower() for c in senha),
        any(c.isupper() for c in senha),
        any(c.isdigit() for c in senha),
        any(c in "!@#$%^&*()-_=+" for c in senha)
    ]
    forca = sum(criterios)
    if forca == 4:
        return "Forte"
    elif forca == 3:
        return "Média"
    else:
        return "Fraca"

def gerar_senha_segura():
    caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    senha = ''.join(secrets.choice(caracteres) for _ in range(12))
    return senha

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

def criptografar_arquivo(dados, senha):
    try:
        sal = os.urandom(16)
        chave = gerar_chave_senha(senha, sal)

        fernet = Fernet(chave)
        dados_criptografados = fernet.encrypt(dados)

        return sal + dados_criptografados
    
    except Exception as e:
        st.error(f"Erro ao criptografar o arquivo: {e}")
        return None

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

st.title("Projeto de Criptografia de Arquivos")

with st.expander("Ajuda e Suporte"):
    st.write("""
    Esta ferramenta permite criptografar e descriptografar arquivos com base em uma senha.
    
    - **Criptografia**: Selecione a opção 'Criptografar', faça upload do arquivo e defina uma senha.
    - **Descriptografia**: Selecione 'Descriptografar', faça upload do arquivo criptografado e insira a mesma senha usada para criptografá-lo.
    
    **Funcionalidades Adicionais**:
    - Verificação de força da senha. (Aperte Enter após digitar a senha)
    - Geração de senha segura.
    - Exibição de tamanho do arquivo.
    - Prevenção contra sobrescrita e exibição de progresso para arquivos grandes.
    """)

opcao = st.selectbox("Escolha a ação:", ["Criptografar", "Descriptografar"])

arquivo = st.file_uploader("Selecione o arquivo", type=["txt", "pdf", "png", "jpg", "jpeg", "docx","encrypted"])

if arquivo is not None:
    tamanho_arquivo = len(arquivo.read())
    st.write(f"Tamanho do arquivo: {tamanho_arquivo / 1024:.2f} KB")
    arquivo.seek(0)

senha = st.text_input("Digite a senha", type="password")
if senha:
    st.write(f"Força da senha: {verificar_forca_senha(senha)}")

if st.button("Gerar senha segura"):
    senha_gerada = gerar_senha_segura()
    st.write(f"Senha gerada: {senha_gerada}")

if st.button("Executar"):
    if arquivo is not None and senha:
        dados = arquivo.read()
        progresso = st.progress(0)

        if opcao == "Criptografar":
            dados_processados = criptografar_arquivo(dados, senha)
            if dados_processados is not None:
                progresso.progress(50)
                st.download_button(
                    label="Baixar arquivo criptografado",
                    data=BytesIO(dados_processados),
                    file_name=f"{arquivo.name}.encrypted",
                    mime="application/octet-stream"
                )
                progresso.progress(100)

        elif opcao == "Descriptografar":
            dados_processados = descriptografar_arquivo(dados, senha)
            if dados_processados is not None:
                progresso.progress(50)
                st.download_button(
                    label="Baixar arquivo descriptografado",
                    data=BytesIO(dados_processados),
                    file_name=arquivo.name.replace(".encrypted", ""),
                    mime="application/octet-stream"
                )
                progresso.progress(100)
    else:
        st.error("Por favor, selecione um arquivo e insira uma senha.")
