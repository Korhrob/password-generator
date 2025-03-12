using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.System.Profile;
using Windows.UI.ViewManagement;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.UI.Xaml.Shapes;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace Passgen
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>

    public sealed partial class MainPage : Page
    {
        private static readonly byte[] StaticKey = new byte[32]  // 256-bit key
{
        0x23, 0x56, 0xA3, 0xF8, 0x98, 0xAB, 0xD4, 0x7F,
        0x14, 0x5B, 0xC2, 0x90, 0xE4, 0x33, 0x77, 0xAD,
        0x10, 0x42, 0x61, 0xF5, 0xFF, 0xF1, 0xDE, 0xD3,
        0xE0, 0xE7, 0x6C, 0xD9, 0x9F, 0xAC, 0x64, 0xB3
};

        private static readonly byte[] StaticIV = new byte[16]  // 128-bit IV
        {
        0x6B, 0x27, 0x56, 0x19, 0xC3, 0x41, 0xDC, 0x9A,
        0x48, 0x52, 0x17, 0x5F, 0xB2, 0xF4, 0x38, 0xEF
        };

        const int len_offset = 5;

        const string upperstr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowerstr = "abcdefghijklmnopqrstuvwxyz";
        const string digitstr = "0123456789";
        const string symbolstr = "!#¤%&/()=?@£${[]}\\;:,.~";

        enum W_TYPE
        {
            WRITE,
            APPEND
        };

        public MainPage()
        {
            this.InitializeComponent();

            // Hack to fix window size after "UWP Update"
            var view = ApplicationView.GetForCurrentView();
            view.TryResizeView(new Size(480, 320));

        }

        private void InsertRandom(char[] target, string set, byte[] bytes, int len)
        {
            List<int> empty = new List<int>();

            for (int i = 0; i < len; i++)
            {
                if (target[i] == '\0')
                    empty.Add(i);
            }

            if (empty.Count == 0)
                return;

            // pick random position

            int x = empty.Count;
            int randomIndex = bytes[x % bytes.Length] % empty.Count;
            int targetIndex = empty[randomIndex];

            target[targetIndex] = set[bytes[randomIndex] % set.Length];
        }

        private void Fill(char[] target, string set, byte[] bytes, int len)
        {
            for (int i = 0; i < len; i++)
            {
                if (target[i] != '\0')
                    continue;

                target[i] = set[bytes[i] % set.Length];
            }
        }

        private async Task ShowErrorPopup(string message)
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = "Error",
                Content = message,
                PrimaryButtonText = "Close"
            };

            //var result = await dialog.ShowAsync();
        }

        private async Task<ContentDialogResult> ShowInfoPopup(string title, string message, string button, string button2)
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = button,
                SecondaryButtonText = button2
            };

            return await dialog.ShowAsync();
        }

        private async Task DeleteData()
        {
            try
            {
                StorageFolder local = ApplicationData.Current.RoamingFolder;
                StorageFile file = await local.GetFileAsync("data.passgen");
                await file.DeleteAsync();

            } catch (Exception ex)
            {
                await ShowErrorPopup($"Error saving data: {ex.Message}");
            }
        }

        private async Task SaveData(string str, W_TYPE type)
        {
            try
            {
                byte[] bytes = Encrypt(str, StaticKey, StaticIV);
                string base64 = Convert.ToBase64String(bytes);
                string prefix = base64.Length.ToString("D5");
                string data = prefix + base64;

                StorageFolder local = ApplicationData.Current.RoamingFolder;
                StorageFile file = await local.CreateFileAsync("data.passgen", CreationCollisionOption.OpenIfExists);

                await FileIO.AppendTextAsync(file, data);

            } catch (Exception ex)
            {
                await ShowErrorPopup($"Error saving data: {ex.Message}");
            }
        }

        private async Task<string> LoadData(string filename)
        {
            try
            {
                StorageFolder local = ApplicationData.Current.RoamingFolder;
                StorageFile file = await local.CreateFileAsync(filename, CreationCollisionOption.OpenIfExists);
                return await FileIO.ReadTextAsync(file);
            } catch (Exception ex)
            {
                await ShowErrorPopup($"Error: failed to load data {filename} : {ex.Message}");
            }
            return string.Empty;
        }

        private List<string> ParseData(string raw)
        {
            List<string> lines = new List<string>();

            int pos = 0;
            while (pos < raw.Length)
            {
                string lenStr = raw.Substring(pos, len_offset);
                pos += len_offset;

                int len = int.Parse(lenStr);

                string base64 = raw.Substring(pos, len);
                pos += len;

                byte[] bytes = Convert.FromBase64String(base64);
                string data = Decrypt(bytes, StaticKey, StaticIV);
                lines.Add(data);
            }

            return lines;
        }

        private void RefreshComboBox(List<string> lines)
        {
            foreach (string line in lines)
            {
                string[] parts = line.Split(new[] { ':' }, 2);
                if (parts.Length == 2)
                {
                    string key = parts[0];
                    targetResult.Items.Add(key);
                }
            }

            if (lines.Count > 0)
                targetResult.SelectedIndex = 0;
        }

        private byte[]    Encrypt(string str, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(str);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private string Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                using (var msDecrypt = new MemoryStream(data))
                using (var csEncrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srEncrypt = new StreamReader(csEncrypt))
                {
                    return srEncrypt.ReadToEnd();
                }
            }
        }

        private void ToggleButtons(bool b)
        {
            result.IsEnabled = b;
            save.IsEnabled = b;
            load.IsEnabled = b;
            remove.IsEnabled = b;
        }

        private void length_TextChanged(object sender, TextChangedEventArgs e)
        {
            var field = (TextBox)sender;
            string txt = string.Empty;

            foreach (char c in field.Text)
            {
                if (char.IsDigit(c))
                    txt += c;
            }

            if (field.Text != txt)
            {
                txt = field.Text;
            }
        }

        private void generate_Click(object sender, RoutedEventArgs e)
        {
            int len = int.Parse(length.Text);

            bool[] flag = new bool[] {
                uppercase.IsChecked ?? false,
                lowercase.IsChecked ?? false,
                digit.IsChecked ?? false,
                symbol.IsChecked ?? false,
            };

            // Init Len
            int minLen = flag.Count(b => b);

            if (minLen <= 0)
                return;

            if (len < minLen)
                len = minLen;

            // Build Set
            string set = "";

            if (flag[0])
                set += upperstr;
            if (flag[1])
                set += lowerstr;
            if (flag[2])
                set += digitstr;
            if (flag[3])
                set += symbolstr;

            // Init Pass
            char[] pwd = new char[len];

            for (int i = 0; i < pwd.Length; i++)
                pwd[i] = '\0';

            // Generate
            byte[] bytes = new byte[len];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            if (flag[0])
                InsertRandom(pwd, upperstr, bytes, len);
            if (flag[1])
                InsertRandom(pwd, lowerstr, bytes, len);
            if (flag[2])
                InsertRandom(pwd, digitstr, bytes, len);
            if (flag[3])
                InsertRandom(pwd, symbolstr, bytes, len);

            Fill(pwd, set, bytes, len);

            // Set result
            result.Text = new string(pwd);
        }

        private async void save_Click(object sender, RoutedEventArgs e)
        {

            TextBox keyInput = new TextBox()
            {
                PlaceholderText = "key"
            };

            ContentDialog dialog = new ContentDialog
            {
                Title = "Enter Key",
                Content = keyInput,
                PrimaryButtonText = "Confirm",
                SecondaryButtonText = "Cancel",
            };

            var dialogOption = await dialog.ShowAsync();

            if (dialogOption == ContentDialogResult.Primary && keyInput.Text != string.Empty && result.Text != string.Empty)
            {
                SaveData(keyInput.Text + ":" + result.Text, W_TYPE.APPEND);

                ContentDialog success = new ContentDialog
                {
                    Title = "Success!!",
                    Content = "Added to DB",
                    PrimaryButtonText = "OK",
                };

                await ShowInfoPopup("Success!!", "Added entry to DB", "OK", "");
            }

        }

        private async void fetch_Click(object sender, RoutedEventArgs e)
        {

            targetResult.Items.Clear();

            ToggleButtons(false);

            try
            {
                string data = await LoadData("data.passgen");
                List<string> lines = ParseData(data);
                RefreshComboBox(lines);

            } catch (Exception ex)
            {
                await ShowErrorPopup($"Error loading data: {ex.Message}");
            }

            ToggleButtons(true);

        }

        private async void copy_Click(object sender, RoutedEventArgs e)
        {

            int index = targetResult.SelectedIndex;

            ToggleButtons(false);

            try
            {
                string raw = await LoadData("data.passgen");
                List<string> lines = ParseData(raw);

                if (index >= 0 && index < lines.Count)
                {
                    var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
                    var parts = lines[index].Split(new[] { ':' }, 2);

                    if (parts.Length == 2)
                    {
                        data.SetText(parts[1]);
                        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
                    }

                }
            } catch (Exception ex)
            {
                await ShowErrorPopup($"Error loading data: {ex.Message}");
            }

            ToggleButtons(true);

        }

        private async void remove_Click(object sender, RoutedEventArgs e)
        {
            int index = targetResult.SelectedIndex;

            if (index < 0 || index >= targetResult.Items.Count)
                return;

            var confirm = await ShowInfoPopup("Confirm", $"Delete {targetResult.Items[index].ToString()}?", "Confirm", "Cancel");

            if (confirm == ContentDialogResult.Secondary)
                return;

            ToggleButtons(false);
            string raw = await LoadData("data.passgen");
            List<string> lines = ParseData(raw);

            if (index >= 0 && index < lines.Count)
            {
                ContentDialog success = new ContentDialog
                {
                    Title = "Success",
                    Content = $"Entry {lines[index]} removed",
                    PrimaryButtonText = "OK",
                };

                await DeleteData();
                await success.ShowAsync();
                lines.RemoveAt(index);

                while (lines.Count > 0)
                {
                    await SaveData(lines[0], W_TYPE.APPEND);
                    lines.RemoveAt(0);
                }

                targetResult.Items.RemoveAt(index);
                targetResult.SelectedIndex = 0;
            }

            ToggleButtons(true);

        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}

//     <Button x:Name="copy" Click="copy_Click" Background="#33000000" FontWeight="Bold" Foreground="White" Margin="0,0,8,0" HorizontalAlignment="Left" VerticalAlignment="Stretch">Copy</Button>
