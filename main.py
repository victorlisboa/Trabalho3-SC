import base64
import os
import sys

from rsa_pss_project.key_manager import RSAKey
from rsa_pss_project.signer import rsa_pss
from rsa_pss_project.encrypt import rsa_oaep
from rsa_pss_project.utils import *

def display_menu():
    print("\n" + "="*50)
    print("Trabalho 3 - SC: Cifragem e Assinatura RSA")
    print("Desenvolvido por Iasmim, Maxwell e Victor Hugo")
    print("="*50)
    print("1. Gerar novo par de chaves RSA")
    print("2. Cifrar arquivo (RSA-OAEP)")
    print("3. Decifrar arquivo (RSA-OAEP)")
    print("4. Assinar arquivo (RSA-PSS)")
    print("5. Verificar assinatura (RSA-PSS)")
    print("0. Sair")
    print("-"*50)

def get_path_from_user(prompt, must_exist=False):
    """Pede um caminho de arquivo ao utilizador e verifica se existe, se necessário."""
    while True:
        path = input(prompt)
        if not must_exist or os.path.exists(path):
            return path
        else:
            print(f"❌ ERRO: O arquivo '{path}' não foi encontrado. Tente novamente.")

def handle_generate():
    """Lida com a lógica de geração de chaves."""
    print("\n--- Geração de Chaves ---")
    try:
        bits = int(input("Digite o tamanho da chave em bits (ex: 2048): "))

        print(f"\nGerando par de chaves RSA de {bits} bits... (Isso pode demorar um pouco)")
        key = RSAKey(bits=bits)
        key.generate()
        print(f"✅ Chaves salvas com sucesso na pasta 'keys'.")
    except ValueError:
        print("❌ ERRO: O tamanho da chave deve ser um número inteiro.")
    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado: {e}")

def handle_encrypt():
    """Lida com a lógica de cifragem."""
    print("\n--- Cifrar Arquivo (RSA-OAEP) ---")
    key_path = get_path_from_user("Caminho para a chave pública (.pem): ", must_exist=True)
    input_file = get_path_from_user("Arquivo de entrada para cifrar: ", must_exist=True)
    output_file = get_path_from_user("Arquivo de saída para o texto cifrado: ")

    try:
        PU = RSAKey.load_pem_file(key_path)
        k = (PU['n'].bit_length() + 7) // 8
        cipher = rsa_oaep(k=k)
        
        with open(input_file, 'r') as f_in:
            plaintext = f_in.read().encode('utf-8')
        
        ciphertext = cipher.encrypt(PU, plaintext)
        print(ciphertext)
        
        with open(output_file, 'w') as f_out:
            f_out.write(ciphertext)
        print(f"✅ Arquivo cifrado salvo em '{output_file}'.")
    except Exception as e:
        print(f"❌ Ocorreu um erro ao cifrar: {e}")

def handle_decrypt():
    """Lida com a lógica de decifragem."""
    print("\n--- Decifrar Arquivo (RSA-OAEP) ---")
    key_path = get_path_from_user("Caminho para a chave privada (.pem): ", must_exist=True)
    input_file = get_path_from_user("Arquivo de entrada para decifrar: ", must_exist=True)
    output_file = get_path_from_user("Arquivo de saída para o texto decifrado: ")

    try:
        private_key_data = RSAKey.load_pem_file(key_path)
        k = (private_key_data['n'].bit_length()+7) // 8
        cipher = rsa_oaep(k=k)

        with open(input_file, 'r') as f_in:
            ciphertext = f_in.read()
        
        ciphertext = base64_to_byte(ciphertext)
        plaintext = cipher.decrypt(private_key_data, ciphertext)
        with open(output_file, 'w') as f_out:
            f_out.write(plaintext)
        print(f"✅ Arquivo decifrado salvo em '{output_file}'.")
    except ValueError as e:
        print(f"❌ ERRO AO DECIFRAR: {e}")
    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado: {e}")

def handle_sign():
    """Lida com a lógica de assinatura."""
    print("\n--- Assinar Arquivo (RSA-PSS) ---")
    key_path = get_path_from_user("Caminho para a chave privada (.pem): ", must_exist=True)
    input_file = get_path_from_user("Arquivo de entrada para assinar: ", must_exist=True)
    output_file = get_path_from_user("Arquivo de saída para a assinatura (.sig): ")

    try:
        private_key_data = RSAKey.load_pem_file(key_path)
        k = (private_key_data['n'].bit_length()+7) // 8
        signer = rsa_pss(k=k)
        
        with open(input_file, 'r') as f_in:
            message = f_in.read().encode('utf-8')
            
        signature_b64 = signer.sign(message, private_key_data)
        
        with open(output_file, 'w') as f_out:
            f_out.write(signature_b64)
        print(f"✅ Assinatura salva em '{output_file}'.")
    except Exception as e:
        print(f"❌ Ocorreu um erro ao assinar: {e}")

def handle_verify():
    """Lida com a lógica de verificação de assinatura."""
    print("\n--- Verificar Assinatura (RSA-PSS) ---")
    key_path = get_path_from_user("Caminho para a chave pública (.pem): ", must_exist=True)
    input_file = get_path_from_user("Arquivo original que foi assinado: ", must_exist=True)
    sig_file = get_path_from_user("Arquivo da assinatura (.sig) a ser verificado: ", must_exist=True)

    try:
        public_key_data = RSAKey.load_pem_file(key_path)
        k = (public_key_data['n'].bit_length()+7) // 8
        verifier = rsa_pss(k=k)
        
        with open(input_file, 'r') as f_in:
            message = f_in.read().encode('utf-8')
            
        with open(sig_file, 'r') as f_sig:
            signature = f_sig.read()
            
        is_valid = verifier.verify_signature(message, signature, public_key_data)
        
        if is_valid:
            print("✅ Assinatura VÁLIDA.")
        else:
            print("❌ Assinatura INVÁLIDA.")
    except Exception as e:
        print(f"❌ Ocorreu um erro ao verificar: {e}")

def main():
    sieve(1000000)
    """Função principal que executa o loop do menu interativo."""
    actions = {
        '1': handle_generate,
        '2': handle_encrypt,
        '3': handle_decrypt,
        '4': handle_sign,
        '5': handle_verify
    }

    while True:
        display_menu()
        choice = input("Escolha uma opção: ")

        if choice == '0':
            print("Encerrando o programa...")
            sys.exit(0)
        
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Opção inválida. Por favor, tente novamente.")
        
        input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    main()
