using System;
using System.Security.Cryptography;

namespace HashExample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Solicita ao usuário que digite a senha
            Console.Write("Digite a senha para criptografar: ");
            string digSenha = Console.ReadLine();

            // Gera uma chave aleatória para HMACSHA256
            byte[] key = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }

            // Cria uma instância da classe Hash com a chave gerada
            Hash hash = new Hash(key);

            // Criptografa a senha digitada e exibe o hash resultante
            string senhaEncr = hash.EncryptPassword(digSenha);
            Console.WriteLine($"Hash gerado: {senhaEncr}");

            // Solicita ao usuário que digite a senha novamente para verificar
            Console.Write("Digite a senha novamente para verificar: ");
            string digSenhaVerificar = Console.ReadLine();

            // Verifica se a senha digitada corresponde ao hash
            bool val = hash.VerifyPassword(digSenhaVerificar, senhaEncr);
            string check = val ? "correta" : "incorreta";
            Console.WriteLine($"Validação: A senha está {check}");

            Console.ReadLine();
        }
    }
}
