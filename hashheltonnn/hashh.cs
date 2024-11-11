using System;
using System.Security.Cryptography;
using System.Text;

namespace HashExample
{
    internal class Hash
    {
        private readonly HMACSHA256 _hmac;

        public Hash(byte[] key)
        {
            _hmac = new HMACSHA256(key);
        }

        public string EncryptPassword(string password)
        {
            // Gera um salt aleatório de 16 bytes
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Combina o salt com a senha
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var saltedPassword = new byte[salt.Length + passwordBytes.Length];
            Buffer.BlockCopy(salt, 0, saltedPassword, 0, salt.Length);
            Buffer.BlockCopy(passwordBytes, 0, saltedPassword, salt.Length, passwordBytes.Length);

            // Gera o hash da senha com salt usando HMACSHA256
            var hashBytes = _hmac.ComputeHash(saltedPassword);

            // Concatena o salt e o hash em um único array de bytes
            var hashWithSaltBytes = new byte[salt.Length + hashBytes.Length];
            Buffer.BlockCopy(salt, 0, hashWithSaltBytes, 0, salt.Length);
            Buffer.BlockCopy(hashBytes, 0, hashWithSaltBytes, salt.Length, hashBytes.Length);

            // Converte o array de bytes para uma string base64
            return Convert.ToBase64String(hashWithSaltBytes);
        }

        public bool VerifyPassword(string enteredPassword, string storedPassword)
        {
            if (string.IsNullOrEmpty(storedPassword))
                throw new ArgumentNullException(nameof(storedPassword), "Por favor, registre uma senha.");

            // Converte a string base64 de volta para um array de bytes
            var hashWithSaltBytes = Convert.FromBase64String(storedPassword);

            // Extrai o salt dos primeiros 16 bytes do hash armazenado
            byte[] salt = new byte[16];
            Buffer.BlockCopy(hashWithSaltBytes, 0, salt, 0, salt.Length);

            // Combina o salt com a senha digitada
            var passwordBytes = Encoding.UTF8.GetBytes(enteredPassword);
            var saltedPassword = new byte[salt.Length + passwordBytes.Length];
            Buffer.BlockCopy(salt, 0, saltedPassword, 0, salt.Length);
            Buffer.BlockCopy(passwordBytes, 0, saltedPassword, salt.Length, passwordBytes.Length);

            // Gera o hash da senha digitada com salt usando HMACSHA256
            var hashBytes = _hmac.ComputeHash(saltedPassword);

            // Concatena o salt e o hash gerado em um único array de bytes
            var hashWithSaltBytesToCompare = new byte[salt.Length + hashBytes.Length];
            Buffer.BlockCopy(salt, 0, hashWithSaltBytesToCompare, 0, salt.Length);
            Buffer.BlockCopy(hashBytes, 0, hashWithSaltBytesToCompare, salt.Length, hashBytes.Length);

            // Compara os arrays de bytes
            return Convert.ToBase64String(hashWithSaltBytesToCompare) == storedPassword;
        }
    }
}
