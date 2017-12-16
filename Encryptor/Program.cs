using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Encryptor
{
    class Program
    {
        public static Thread ThreadForFilesSearch = new Thread(FindInDir);
        public static Thread ThreadForFileEncryptionN1 = new Thread(EncryptFiles);
        public static Thread ThreadForFileEncryptionN2 = new Thread(EncryptFiles);
        public static Thread ThreadForFileEncryptionN3 = new Thread(EncryptFiles);
        public static Thread ThreadForFileEncryptionN4 = new Thread(EncryptFiles);
        private static ReaderWriterLock rwl = new ReaderWriterLock();
        static readonly Stack<string> AllFilesThatHaveBeenFound = new Stack<string>();

        static void Main(string[] args)
        {
            var dir = new DirectoryInfo(Console.ReadLine() ?? throw new InvalidOperationException());
            ThreadForFilesSearch.Start(dir);//поиск файлов и запись их в стек в отдельном потоке
            ThreadForFileEncryptionN1.Start();//потоки для шифрофания
            ThreadForFileEncryptionN2.Start();
            ThreadForFileEncryptionN3.Start();
            ThreadForFileEncryptionN4.Start();
            while (ThreadForFilesSearch.IsAlive || ThreadForFileEncryptionN1.IsAlive
                   || ThreadForFileEncryptionN2.IsAlive || ThreadForFileEncryptionN3.IsAlive
                   || ThreadForFileEncryptionN4.IsAlive)
            {
                // пока какойто из потоков работает, крутимся тут
            }


        }
        public static void FindInDir(object obj)
        {
            var dir = (DirectoryInfo)obj;

            try
            {
                foreach (FileInfo file in dir.GetFiles("*.*").Where(str =>
                    str.Name.EndsWith(".doc") || str.Name.EndsWith(".docx") || str.Name.EndsWith(".pdf"))) //поиск Файла, расширение которого удовлетворяет сразу нескольким типам
                {
                    rwl.AcquireWriterLock(Int32.MaxValue);
                    try
                    {
                        AllFilesThatHaveBeenFound.Push(file.FullName);
                    }
                    finally
                    {
                        rwl.ReleaseWriterLock();
                    }
                }
                foreach (DirectoryInfo subdir in dir.GetDirectories())
                {
                    FindInDir(subdir);//рекурсивный заход в поддиректорию
                }
            }
            catch (Exception)
            {
                // ignored
            }
        }

        private static  void EncryptFiles()
        {
            while (ThreadForFilesSearch.IsAlive || !ThreadForFilesSearch.IsAlive && AllFilesThatHaveBeenFound.Count!=0) //поток работает, пока работает записывающий новые файлы поток, или пока еще есть файлы, а поток уже умер
            {
                try
                {
                    string file = null;
                    rwl.AcquireWriterLock(int.MaxValue);
                    try
                    {
                        if (AllFilesThatHaveBeenFound.Count > 0)
                            file = AllFilesThatHaveBeenFound.Pop(); //записываем в file путь к нужному файлу, если есть файлы в стеке, если нет-ждем новых
                        else continue;
                    }
                    finally
                    {
                        rwl.ReleaseWriterLock();
                    }
                    byte[] original = File.ReadAllBytes(file); //читаем байты файла
                    string plainText = null;
                    foreach (var b in original)
                    {
                        plainText += b + "/"; //записываем байты в строку, так как я нашел только реализацию шифрования строки, а не массива сразу
                    }
                    /*
                     * 
                     * начало алгоритма шифрования Аеs
                     * 
                     */
                    using (var myAes = Aes.Create()) // Создаем новый экземпляр класса Aes  Создаем ключ и вектор инициализации (IV)
                    {
                        byte[] encrypted = EncryptStringToBytesAes(plainText, myAes.Key, myAes.IV);// Зашифрованную строку переводим в массив байтов
                        File.WriteAllBytes(file, encrypted); // теперь наш файл зашифрован
                        /*
                         * 
                         * начало алгоритма дешифрования Аеs
                         * 
                         */
                        string decripted = DecryptStringFromBytesAes(File.ReadAllBytes(file), myAes.Key, myAes.IV); // читаем байты уже изменненого файла
                        original = new byte[original.Length];//смотрим сколько байтов было до шифрования
                        string tmp = null;
                        int i = 0;
                        foreach (var b in decripted) //переводим расшифрованнную строку в массив байт
                        {
                            if (b != '/')
                            {
                                tmp += b;
                                continue;
                            }
                            original[i] = Convert.ToByte(tmp);
                            i++;
                            tmp = null;
                        }
                        File.WriteAllBytes(file, original);//файл такой же как и прежде
                    }
                }
                catch (Exception e)
                {
                    // Если что-то не так выбрасываем исключение
                    Console.WriteLine("Error: {0}", e.Message);
                }
            }
        }
        static string DecryptStringFromBytesAes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Проверяем аргументы
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Строка, для хранения расшифрованного текста
            string plaintext;

            // Создаем объект класса AES,
            // Ключ и IV
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создаем объект, который определяет основные операции преобразований.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток для расшифрования.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Читаем расшифрованное сообщение и записываем в строку
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        static byte[] EncryptStringToBytesAes(string plainText, byte[] Key, byte[] IV)
        {
            // Проверка аргументов
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Создаем объект класса AES
            // с определенным ключом and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создаем объект, который определяет основные операции преобразований.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток для шифрования.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                                swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            //Возвращаем зашифрованные байты из потока памяти.
            return encrypted;

        }
    }
}
