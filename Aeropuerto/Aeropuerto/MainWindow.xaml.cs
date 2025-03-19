using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using Microsoft.Win32;
using Microsoft.VisualBasic; // Para Interaction, si lo necesitas.
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Aeropuerto
{
    public partial class MainWindow : Window
    {
        private const string ConnectionString = "Server=MALONDY\\SQLEXPRESS;Database=bdEcojetSD;Integrated Security=True;TrustServerCertificate=True;";

        // Ya no usamos EncryptionKey en el constructor,
        // pero la conservamos si deseas seguir usándola internamente.
        private static byte[] EncryptionKey;

        // Clave que guardaremos una vez verificada:
        private string _currentKeyHex = null;

        public MainWindow()
        {
            InitializeComponent();

            //LoadEncryptionKey(); 
        }

        private void LoadEncryptionKey()
        {
            // Mantén este método si quieres seguir usando el InputBox en vez de la interfaz WPF:
            string keyInput = Interaction.InputBox("Enter the 16-byte encryption key (hex, e.g., 0102030405060708090A0B0C0D0E0F10):",
                                                  "Encryption Key",
                                                  "0102030405060708090A0B0C0D0E0F10");
            if (string.IsNullOrEmpty(keyInput) || keyInput.Length != 32)
            {
                MessageBox.Show("Invalid key. Application will close.");
                Close();
                return;
            }
            EncryptionKey = HexStringToByteArray(keyInput);
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            try
            {
                int numberChars = hex.Length;
                byte[] bytes = new byte[numberChars / 2];
                for (int i = 0; i < numberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Invalid hex string for key.", ex);
            }
        }

        private DateTime ParseDateTime(string value, string context, DateTime? referenceDate = null)
        {
            string[] formats = { "dd/MM/yyyy HH:mm", "dd-MM-yyyy HH:mm", "dd/MM/yyyy", "dd-MM-yyyy", "HH:mm" };
            string cleanedValue = Regex.Replace(value.Trim(), @"\s+", " "); // Normalize spaces
            foreach (var format in formats)
            {
                if (DateTime.TryParseExact(cleanedValue, format, null, System.Globalization.DateTimeStyles.None, out DateTime result))
                {
                    if (format == "HH:mm" && referenceDate.HasValue)
                        return referenceDate.Value.Date + result.TimeOfDay;
                    return result;
                }
            }
            throw new FormatException($"Cannot parse '{cleanedValue}' as a valid DateTime in {context}");
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Multiselect = true
            };

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    foreach (string filePath in openFileDialog.FileNames)
                    {
                        ProcessTextFile(filePath);
                    }
                    MessageBox.Show("Se insertó correctamente.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error processing files: {ex.Message}");
                }
            }
        }

        private void ProcessTextFile(string filePath)
        {
            try
            {
                string[] rawLines = File.ReadAllLines(filePath);
                DateTime? fileDate = ExtractFileDate(rawLines) ?? throw new Exception("No valid 'Desde' date found in file.");

                string fullContent = File.ReadAllText(filePath).Replace("\r\n", " ").Replace("\n", " ");
                string[] employeeBlocks = Regex.Split(fullContent, @"(?<=^|\s)ID\s*,");

                foreach (var block in employeeBlocks)
                {
                    if (string.IsNullOrWhiteSpace(block) || !block.Contains("Nombre")) continue;

                    string fullBlock = "ID," + block.Trim();
                    int currentEmployeeId = 0;
                    string currentDepartment = "UNKNOWN";
                    string encryptedName = "";

                    var parts = fullBlock.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    string nameBuilder = "";

                    // Buscar ID
                    for (int i = 0; i < parts.Length; i++)
                    {
                        if (parts[i].Trim() == "ID" && i + 1 < parts.Length)
                        {
                            currentEmployeeId = int.Parse(parts[i + 1].Trim());
                            break;
                        }
                    }

                    // Buscar Nombre y Departamento
                    for (int i = 0; i < parts.Length; i++)
                    {
                        if (parts[i].Trim() == "Nombre" && i + 1 < parts.Length)
                        {
                            int j = i + 1;
                            nameBuilder = parts[j].Trim();
                            while (j + 1 < parts.Length && parts[j + 1].Trim() != "Departamento" &&
                                   !Regex.IsMatch(parts[j + 1].Trim(), @"\d{2}/\d{2}/\d{4}"))
                            {
                                j++;
                                nameBuilder += " " + parts[j].Trim();
                            }
                            encryptedName = EncryptName(nameBuilder, EncryptionKey);
                        }
                        if (parts[i].Trim() == "Departamento" && i + 1 < parts.Length)
                        {
                            currentDepartment = parts[i + 1].Trim();
                            if (string.IsNullOrEmpty(currentDepartment)) currentDepartment = "UNKNOWN";
                        }
                    }

                    if (currentEmployeeId == 0 || string.IsNullOrEmpty(encryptedName))
                    {
                        MessageBox.Show($"Skipping block debido a datos incompletos: ID={currentEmployeeId}, Name={nameBuilder}");
                        continue;
                    }

                    if (!EmployeeExists(currentEmployeeId))
                        InsertEmployeeData(currentEmployeeId, encryptedName, currentDepartment);

                    try
                    {
                        ProcessEntryExitLine(fullBlock, currentEmployeeId, fileDate);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error procesando bloque: '{fullBlock}' - {ex.Message}");
                        throw;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error procesando archivo {Path.GetFileName(filePath)}: {ex.Message}");
                throw;
            }
        }

        private DateTime? ExtractFileDate(string[] lines)
        {
            foreach (var line in lines)
            {
                if (line.Contains("Desde"))
                {
                    var parts = line.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < parts.Length; i++)
                    {
                        if (parts[i].Trim() == "Desde" && i + 1 < parts.Length)
                            return ParseDateTime(parts[i + 1], "Desde date");
                    }
                }
            }
            return null;
        }

        private void ProcessEntryExitLine(string line, int employeeId, DateTime? fileDate)
        {
            var parts = line.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            DateTime? lastDate = fileDate;

            for (int i = 0; i < parts.Length - 1; i++)
            {
                string current = parts[i].Trim();
                string next = parts[i + 1].Trim();

                try
                {
                    lastDate = ParseDateTime(current, "date check", lastDate);
                }
                catch (FormatException)
                {
                    // No es una fecha válida, seguimos.
                }

                if (next == "Entrada")
                {
                    try
                    {
                        DateTime entry = ParseDateTime(current, "entry", lastDate);
                        DateTime? exit = null;
                        if (i + 3 < parts.Length && parts[i + 3].Trim() == "Salida")
                        {
                            exit = ParseDateTime(parts[i + 2].Trim(), "exit", lastDate);
                            i += 2;
                        }
                        if (!EntryExitExists(employeeId, entry, exit, fileDate))
                            InsertEntryExitData(employeeId, entry, exit, fileDate);
                    }
                    catch (FormatException)
                    {
                        continue;
                    }
                }
                else if (next == "Salida" && (i == 0 || parts[i - 1].Trim() != "Entrada"))
                {
                    try
                    {
                        DateTime exit = ParseDateTime(current, "standalone exit", lastDate);
                        if (!EntryExitExists(employeeId, null, exit, fileDate))
                            InsertEntryExitData(employeeId, null, exit, fileDate);
                    }
                    catch (FormatException)
                    {
                        continue;
                    }
                }
            }
        }

        private string EncryptName(string name, byte[] encryptionKey)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = encryptionKey;
                aesAlg.GenerateIV();
                byte[] iv = aesAlg.IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(name);
                    }

                    byte[] encryptedData = msEncrypt.ToArray();
                    byte[] result = new byte[iv.Length + encryptedData.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);
                    return Convert.ToBase64String(result);
                }
            }
        }

        private bool EmployeeExists(int employeeId)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = "SELECT COUNT(*) FROM Employees WHERE EmployeeID = @EmployeeID";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    return (int)command.ExecuteScalar() > 0;
                }
            }
        }

        private bool EntryExitExists(int employeeId, DateTime? entry, DateTime? exit, DateTime? fileDate)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = @"SELECT COUNT(*) FROM EntryExitHistory 
                                 WHERE EmployeeID = @EmployeeID 
                                   AND (EntryDateTime = @EntryDateTime OR (EntryDateTime IS NULL AND @EntryDateTime IS NULL))
                                   AND (ExitDateTime = @ExitDateTime OR (ExitDateTime IS NULL AND @ExitDateTime IS NULL))
                                   AND FileDate = @FileDate";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    command.Parameters.AddWithValue("@EntryDateTime", entry.HasValue ? (object)entry.Value : DBNull.Value);
                    command.Parameters.AddWithValue("@ExitDateTime", exit.HasValue ? (object)exit.Value : DBNull.Value);
                    command.Parameters.AddWithValue("@FileDate", fileDate.HasValue ? (object)fileDate.Value : DBNull.Value);
                    return (int)command.ExecuteScalar() > 0;
                }
            }
        }

        private void InsertEmployeeData(int employeeId, string encryptedName, string department)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = "INSERT INTO Employees (EmployeeID, EncryptedName, Department) VALUES (@EmployeeID, @EncryptedName, @Department)";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    command.Parameters.AddWithValue("@EncryptedName", encryptedName);
                    command.Parameters.AddWithValue("@Department", department);
                    command.ExecuteNonQuery();
                }
            }
        }

        private void InsertEntryExitData(int employeeId, DateTime? entry, DateTime? exit, DateTime? fileDate)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = "INSERT INTO EntryExitHistory (EmployeeID, EntryDateTime, ExitDateTime, FileDate) " +
                               "VALUES (@EmployeeID, @EntryDateTime, @ExitDateTime, @FileDate)";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    command.Parameters.AddWithValue("@EntryDateTime", entry.HasValue ? (object)entry.Value : DBNull.Value);
                    command.Parameters.AddWithValue("@ExitDateTime", exit.HasValue ? (object)exit.Value : DBNull.Value);
                    command.Parameters.AddWithValue("@FileDate", fileDate.HasValue ? (object)fileDate.Value : DBNull.Value);
                    command.ExecuteNonQuery();
                }
            }
        }

        public string DecryptName(string encryptedName, string keyHex)
        {
            byte[] key = HexStringToByteArray(keyHex);
            byte[] fullCipher = Convert.FromBase64String(encryptedName);
            byte[] iv = new byte[16];
            byte[] cipherText = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipherText, 0, cipherText.Length);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }

        private void DisplayDecryptedData_Click(object sender, RoutedEventArgs e)
        {
            // Botón existente que muestra en un MessageBox toda la info desencriptada.
            // Lo dejamos tal cual, pero seguirá pidiendo la clave vía InputBox.
            // Puedes reutilizar la clave _currentKeyHex si ya fue verificada.

            string keyInput = Interaction.InputBox("Enter the encryption key to decrypt names:", "Decrypt Data");
            if (string.IsNullOrEmpty(keyInput) || keyInput.Length != 32)
            {
                MessageBox.Show("Invalid key.");
                return;
            }

            try
            {
                using (SqlConnection connection = new SqlConnection(ConnectionString))
                {
                    connection.Open();
                    string query = "SELECT EmployeeID, EncryptedName, Department FROM Employees";
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            StringBuilder result = new StringBuilder();
                            while (reader.Read())
                            {
                                int id = reader.GetInt32(0);
                                string encryptedName = reader.GetString(1);
                                string department = reader.GetString(2);
                                try
                                {
                                    string decryptedName = DecryptName(encryptedName, keyInput);
                                    result.AppendLine($"ID: {id}, Name: {decryptedName}, Department: {department}");
                                }
                                catch (Exception ex)
                                {
                                    result.AppendLine($"ID: {id}, Name: [Decryption Failed - {ex.Message}], Department: {department}");
                                }
                            }
                            MessageBox.Show(result.ToString(), "Employee Data");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error retrieving data: {ex.Message}");
            }
        }

        // ============================================================

        // Modelo para mostrar el empleado en el ComboBox (ID + Nombre desencriptado).
        private class EmployeeViewModel
        {
            public int EmployeeID { get; set; }
            public string DecryptedName { get; set; }

            // Para mostrar en el ComboBox
            public override string ToString()
            {
                return $"{EmployeeID} - {DecryptedName}";
            }
        }

        // Modelo para mostrar la info de entradas/salidas en el DataGrid
        private class EntryExitViewModel
        {
            public DateTime Date { get; set; }
            public string Entry { get; set; }
            public string Exit { get; set; }
        }

        // Evento al hacer clic en "Verificar Clave"
        private void VerifyKeyButton_Click(object sender, RoutedEventArgs e)
        {
            string keyHex = KeyTextBox.Text.Trim();
            if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 32)
            {
                MessageBox.Show("La key es incorrecta");
                return;
            }

            // Intentamos desencriptar algún registro para validar la clave:
            try
            {
                // Si no hay empleados, simplemente guardamos la clave como válida.
                // De lo contrario, la probamos con los registros que existan.
                var employees = LoadEmployeesDecrypted(keyHex);
                // Si llegamos aquí sin excepción, la clave es válida:
                _currentKeyHex = keyHex;

                // Poblar el ComboBox con la lista de empleados desencriptados
                EmployeesComboBox.ItemsSource = employees;
                if (employees.Count > 0)
                {
                    EmployeesComboBox.SelectedIndex = 0;
                }

                MessageBox.Show("Clave verificada correctamente.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error al verificar la clave: {ex.Message}");
            }
        }

        // Carga la lista de empleados desde la BD desencriptando con la clave dada.
        // Lanza excepción si la clave es incorrecta.
        private List<EmployeeViewModel> LoadEmployeesDecrypted(string keyHex)
        {
            List<EmployeeViewModel> employees = new List<EmployeeViewModel>();

            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = "SELECT EmployeeID, EncryptedName FROM Employees ORDER BY EmployeeID";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            int id = reader.GetInt32(0);
                            string encryptedName = reader.GetString(1);
                            // Si la clave es incorrecta, DecryptName lanzará excepción:
                            string decrypted = DecryptName(encryptedName, keyHex);

                            employees.Add(new EmployeeViewModel
                            {
                                EmployeeID = id,
                                DecryptedName = decrypted
                            });
                        }
                    }
                }
            }
            return employees;
        }

        // Cuando se selecciona un empleado en el ComboBox, mostramos su historial
        private void EmployeesComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (EmployeesComboBox.SelectedItem is EmployeeViewModel selectedEmployee)
            {

                LoadEmployeeDailyAttendance(selectedEmployee.EmployeeID);

                // la vista antigua de entradas en filas separadas, usar:
                // LoadEmployeeHistory(selectedEmployee.EmployeeID);
            }
        }


        // Carga la historia de entrada/salida de un empleado y la muestra en el DataGrid
        private void LoadEmployeeHistory(int employeeId)
        {
            List<EntryExitViewModel> data = new List<EntryExitViewModel>();
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = @"SELECT EntryDateTime, ExitDateTime 
                         FROM EntryExitHistory 
                         WHERE EmployeeID = @EmployeeID
                         ORDER BY EntryDateTime";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            DateTime? entryDateTime = reader["EntryDateTime"] as DateTime?;
                            DateTime? exitDateTime = reader["ExitDateTime"] as DateTime?;

                            DateTime date = entryDateTime?.Date
                                            ?? exitDateTime?.Date
                                            ?? DateTime.MinValue;

                            string entryTime = entryDateTime?.ToString("HH:mm") ?? "No Registrado";
                            string exitTime = exitDateTime?.ToString("HH:mm") ?? "No Registrado";

                            data.Add(new EntryExitViewModel
                            {
                                Date = date,
                                Entry = entryTime,
                                Exit = exitTime
                            });
                        }
                    }
                }
            }

            EmployeeDataGrid.ItemsSource = data;
        }

        //modificacion 1 

        private class DailyAttendanceViewModel
        {
            public DateTime Date { get; set; }

            // Cuatro columnas que mostraremos en el DataGrid
            public string EntradaAM { get; set; }
            public string SalidaAM { get; set; }
            public string EntradaPM { get; set; }
            public string SalidaPM { get; set; }

            // --- Validaciones para "pintar en rojo" ---

            // 1) Entrada AM roja si es mayor a 8:30
            public bool IsEntradaAMOutOfRange
            {
                get
                {
                    if (DateTime.TryParse(EntradaAM, out DateTime dt))
                    {
                        return dt.TimeOfDay > new TimeSpan(8, 30, 0);
                    }
                    return false;
                }
            }

            // 2) Salida AM roja si es menor a 12:00
            public bool IsSalidaAMOutOfRange
            {
                get
                {
                    if (DateTime.TryParse(SalidaAM, out DateTime dt))
                    {
                        return dt.TimeOfDay < new TimeSpan(12, 0, 0);
                    }
                    return false;
                }
            }

            // 3) Entrada PM roja si es mayor a 14:30
            public bool IsEntradaPMOutOfRange
            {
                get
                {
                    if (DateTime.TryParse(EntradaPM, out DateTime dt))
                    {
                        return dt.TimeOfDay > new TimeSpan(14, 30, 0);
                    }
                    return false;
                }
            }

            // 4) Salida PM roja si es menor a 18:30
            public bool IsSalidaPMOutOfRange
            {
                get
                {
                    if (DateTime.TryParse(SalidaPM, out DateTime dt))
                    {
                        return dt.TimeOfDay < new TimeSpan(18, 30, 0);
                    }
                    return false;
                }
            }

        }
        private void LoadEmployeeDailyAttendance(int employeeId)
        {
            // Diccionario: la llave será la fecha (DateTime.Date),
            // y el valor será un objeto DailyAttendanceViewModel
            var dailyMap = new Dictionary<DateTime, DailyAttendanceViewModel>();

            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                string query = @"
            SELECT EntryDateTime, ExitDateTime
            FROM EntryExitHistory
            WHERE EmployeeID = @EmployeeID
            ORDER BY EntryDateTime
        ";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EmployeeID", employeeId);
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            DateTime? entryDateTime = reader["EntryDateTime"] as DateTime?;
                            DateTime? exitDateTime = reader["ExitDateTime"] as DateTime?;

                            // Determinar la fecha base (DateOnly)
                            DateTime fecha = entryDateTime?.Date
                                             ?? exitDateTime?.Date
                                             ?? DateTime.MinValue;

                            // Ver si ya existe la fecha en el diccionario
                            if (!dailyMap.TryGetValue(fecha, out var daily))
                            {
                                daily = new DailyAttendanceViewModel { Date = fecha };
                                dailyMap[fecha] = daily;
                            }

                            // Si hay hora de entrada, ver si es AM o PM
                            if (entryDateTime.HasValue)
                            {
                                if (entryDateTime.Value.Hour < 12)
                                {
                                    // AM
                                    daily.EntradaAM = entryDateTime.Value.ToString("HH:mm");
                                }
                                else
                                {
                                    // PM
                                    daily.EntradaPM = entryDateTime.Value.ToString("HH:mm");
                                }
                            }

                            // Si hay hora de salida, ver si es AM o PM
                            if (exitDateTime.HasValue)
                            {
                                if (exitDateTime.Value.Hour < 12)
                                {
                                    // AM
                                    daily.SalidaAM = exitDateTime.Value.ToString("HH:mm");
                                }
                                else
                                {
                                    // PM
                                    daily.SalidaPM = exitDateTime.Value.ToString("HH:mm");
                                }
                            }
                        }
                    }
                }
            }

            // Convierte el diccionario en lista y ordénala por fecha
            var resultList = new List<DailyAttendanceViewModel>(dailyMap.Values);
            resultList.Sort((a, b) => a.Date.CompareTo(b.Date));

            // Si alguna columna quedó nula, la marcamos como "No Registrado"
            foreach (var item in resultList)
            {
                if (string.IsNullOrEmpty(item.EntradaAM)) item.EntradaAM = "No Registrado";
                if (string.IsNullOrEmpty(item.SalidaAM)) item.SalidaAM = "No Registrado";
                if (string.IsNullOrEmpty(item.EntradaPM)) item.EntradaPM = "No Registrado";
                if (string.IsNullOrEmpty(item.SalidaPM)) item.SalidaPM = "No Registrado";
            }

            // Asignar al DataGrid
            EmployeeDataGrid.ItemsSource = resultList;
        }
        //modificacion 2

        private void GenerateConsolidatedReport_Click(object sender, RoutedEventArgs e)
        {
            // Verificamos que ya exista una clave válida
            if (string.IsNullOrEmpty(_currentKeyHex))
            {
                MessageBox.Show("Primero verifica la clave de encriptación.");
                return;
            }

            // Dialog para guardar el archivo .txt
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = "Consolidado.txt"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    // 1) Cargar lista de empleados desencriptados
                    var employees = LoadEmployeesDecrypted(_currentKeyHex);
                    // Diccionario para buscar nombre por EmployeeID
                    Dictionary<int, string> employeeNames = new Dictionary<int, string>();
                    foreach (var emp in employees)
                    {
                        employeeNames[emp.EmployeeID] = emp.DecryptedName;
                    }

                    // 2) Leer todas las marcas de EntryExitHistory de TODOS los empleados
                    //    y agrupar por fecha para clasificar EntradaAM/PM y SalidaAM/PM
                    // bigMap[employeeId][fecha] = (EntradaAM, SalidaAM, EntradaPM, SalidaPM)
                    var bigMap = new Dictionary<int, Dictionary<DateTime, (DateTime? EntradaAM, DateTime? SalidaAM, DateTime? EntradaPM, DateTime? SalidaPM)>>();

                    using (SqlConnection connection = new SqlConnection(ConnectionString))
                    {
                        connection.Open();
                        string query = @"
                    SELECT EmployeeID, EntryDateTime, ExitDateTime 
                    FROM EntryExitHistory 
                    ORDER BY EmployeeID, EntryDateTime
                ";
                        using (SqlCommand cmd = new SqlCommand(query, connection))
                        {
                            using (SqlDataReader reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    int empId = reader.GetInt32(0);
                                    DateTime? entry = reader["EntryDateTime"] as DateTime?;
                                    DateTime? exit = reader["ExitDateTime"] as DateTime?;

                                    if (!bigMap.ContainsKey(empId))
                                    {
                                        bigMap[empId] = new Dictionary<DateTime, (DateTime?, DateTime?, DateTime?, DateTime?)>();
                                    }

                                    // Determinamos la fecha base (AM/PM se decide por la hora)
                                    DateTime fecha = entry?.Date ?? exit?.Date ?? DateTime.MinValue;

                                    if (!bigMap[empId].ContainsKey(fecha))
                                    {
                                        bigMap[empId][fecha] = (null, null, null, null);
                                    }

                                    var tuple = bigMap[empId][fecha];

                                    // Clasificar la entrada (si existe) en AM o PM
                                    if (entry.HasValue)
                                    {
                                        if (entry.Value.Hour < 12)
                                        {
                                            // Entrada AM
                                            tuple = (entry.Value, tuple.SalidaAM, tuple.EntradaPM, tuple.SalidaPM);
                                        }
                                        else
                                        {
                                            // Entrada PM
                                            tuple = (tuple.EntradaAM, tuple.SalidaAM, entry.Value, tuple.SalidaPM);
                                        }
                                    }

                                    // Clasificar la salida (si existe) en AM o PM
                                    if (exit.HasValue)
                                    {
                                        if (exit.Value.Hour < 12)
                                        {
                                            // Salida AM
                                            tuple = (tuple.EntradaAM, exit.Value, tuple.EntradaPM, tuple.SalidaPM);
                                        }
                                        else
                                        {
                                            // Salida PM
                                            tuple = (tuple.EntradaAM, tuple.SalidaAM, tuple.EntradaPM, exit.Value);
                                        }
                                    }

                                    // Actualizar el diccionario
                                    bigMap[empId][fecha] = tuple;
                                }
                            }
                        }
                    }

                    // 3) Calcular retrasos y días trabajados para cada empleado
                    //    Almacenamos en un diccionario: (totalTimeSpanRetraso, diasTrabajados)
                    var result = new Dictionary<int, (TimeSpan Tardiness, int DaysWorked)>();

                    foreach (var empId in bigMap.Keys)
                    {
                        TimeSpan totalTardiness = TimeSpan.Zero;
                        int daysWorked = 0;

                        // Recorremos cada fecha
                        foreach (var kvp in bigMap[empId])
                        {
                            var date = kvp.Key;
                            var (entradaAM, salidaAM, entradaPM, salidaPM) = kvp.Value;

                            // Verificamos si ese día tuvo al menos un registro
                            bool dayHasRecord = (entradaAM.HasValue || salidaAM.HasValue || entradaPM.HasValue || salidaPM.HasValue);

                            TimeSpan dayTardiness = TimeSpan.Zero;

                            // Entrada AM: si llegó después de las 8:30
                            if (entradaAM.HasValue)
                            {
                                DateTime realEntradaAM = entradaAM.Value;
                                DateTime scheduledAM = new DateTime(realEntradaAM.Year, realEntradaAM.Month, realEntradaAM.Day, 8, 30, 0);
                                if (realEntradaAM > scheduledAM)
                                {
                                    dayTardiness += (realEntradaAM - scheduledAM);
                                }
                            }

                            // Entrada PM: si llegó después de las 14:30
                            if (entradaPM.HasValue)
                            {
                                DateTime realEntradaPM = entradaPM.Value;
                                DateTime scheduledPM = new DateTime(realEntradaPM.Year, realEntradaPM.Month, realEntradaPM.Day, 14, 30, 0);
                                if (realEntradaPM > scheduledPM)
                                {
                                    dayTardiness += (realEntradaPM - scheduledPM);
                                }
                            }

                            // Si tuvo registros, contamos ese día como trabajado
                            if (dayHasRecord)
                            {
                                daysWorked++;
                            }

                            // Sumamos el retraso de ese día al total del empleado
                            totalTardiness += dayTardiness;
                        }

                        result[empId] = (totalTardiness, daysWorked);
                    }

                    // 4) Escribir el archivo .txt
                    using (var sw = new System.IO.StreamWriter(saveFileDialog.FileName, false, Encoding.UTF8))
                    {
                        // Encabezado
                        sw.WriteLine("Id, Nombre, Retrasos, Días Trabajados");

                        // Recorremos todos los empleados (ordenados por ID)
                        var allEmployeeIds = employeeNames.Keys;
                        foreach (var empId in allEmployeeIds)
                        {
                            string name = employeeNames[empId];

                            if (!result.ContainsKey(empId))
                            {
                                // Empleado sin registros en EntryExitHistory
                                sw.WriteLine($"{empId}, {name}, 00:00, 0");
                            }
                            else
                            {
                                var (tardiness, daysWorked) = result[empId];
                                // Convertir el TimeSpan a un formato tipo "HH:mm" que puede superar 24 horas
                                long totalMinutes = (long)tardiness.TotalMinutes;
                                long hours = totalMinutes / 60;
                                long minutes = totalMinutes % 60;
                                string tardinessString = $"{hours:D2}:{minutes:D2}";

                                sw.WriteLine($"{empId}, {name}, {tardinessString}, {daysWorked}");
                            }
                        }
                    }

                    MessageBox.Show("Reporte generado con éxito.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error generando reporte: {ex.Message}");
                }
            }
        }

    }

}
