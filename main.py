import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# Função para gerar uma chave com base em uma senha e um sal
def gerar_chave_senha(senha, sal):
    senha_bytes = senha.encode()  # Converte a senha em bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=100000,
        backend=default_backend()
    )
    chave = base64.urlsafe_b64encode(kdf.derive(senha_bytes))  # Gera a chave
    return chave

# Função para criptografar o arquivo
def criptografar_arquivo(caminho_arquivo, senha):
    try:
        # Gera um sal aleatório
        sal = os.urandom(16)
        chave = gerar_chave_senha(senha, sal)

        with open(caminho_arquivo, 'rb') as file:
            dados = file.read()

        fernet = Fernet(chave)
        dados_criptografados = fernet.encrypt(dados)

        # Escreve o sal e os dados criptografados no novo arquivo
        with open(caminho_arquivo + '.encrypted', 'wb') as file_criptografado:
            file_criptografado.write(sal + dados_criptografados)

        os.remove(caminho_arquivo)  # Remove o arquivo original
        print(f"Arquivo {caminho_arquivo} criptografado com sucesso!")
    
    except Exception as e:
        print(f"Erro ao criptografar o arquivo: {e}")

# Função para descriptografar o arquivo
def descriptografar_arquivo(caminho_arquivo, senha):
    try:
        with open(caminho_arquivo, 'rb') as file:
            # Lê o sal do arquivo
            sal = file.read(16)
            dados_criptografados = file.read()

        chave = gerar_chave_senha(senha, sal)

        fernet = Fernet(chave)
        dados_descriptografados = fernet.decrypt(dados_criptografados)

        caminho_descriptografado = caminho_arquivo.replace('.encrypted', '')
        with open(caminho_descriptografado, 'wb') as file_descriptografado:
            file_descriptografado.write(dados_descriptografados)

        os.remove(caminho_arquivo)  # Remove o arquivo criptografado
        print(f"Arquivo {caminho_arquivo} descriptografado com sucesso!")
    
    except Exception as e:
        print(f"Erro ao descriptografar o arquivo: {e}")

# Função principal para escolher a ação
def main():
    opcao = input("Digite '1' para criptografar ou '2' para descriptografar: ")

    if opcao == '1':
        caminho_arquivo = input("Digite o caminho do arquivo para criptografar: ")
        senha = input("Digite a senha para criptografia: ")
        criptografar_arquivo(caminho_arquivo, senha)
    
    elif opcao == '2':
        caminho_arquivo = input("Digite o caminho do arquivo para descriptografar: ")
        senha = input("Digite a senha usada na criptografia: ")
        descriptografar_arquivo(caminho_arquivo, senha)
    
    else:
        print("Opção inválida. Tente novamente.")

if __name__ == '__main__':
    main()
