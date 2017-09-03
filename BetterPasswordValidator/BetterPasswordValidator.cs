using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


/// <summary>
/// TODO:
/// Better exception handling all round
/// Call more api endpoints
/// Create functions for the other password validation techniques
/// 
/// Provide useful feedback about how to improve the password
/// Create function to perform a global check against all password validation tests
/// </summary>


namespace BetterPasswordValidator
{
    class BetterPasswordValidator
    {
        private readonly string BaseURL = @"https://haveibeenpwned.com/api/v2";

        public BetterPasswordValidator()
        {

        }

        /// <summary>
        /// Takes a plain text password and forwards it on the the HaveIBeenPwned API
        /// As a GET request
        /// </summary>
        /// <param name="password">Plain text password string</param>
        /// <returns>Bool True if the password is known, False if the password safe*</returns>
        public async Task<bool> HasPasswordBeenPwned(string password)
        {
            string endpoint = "pwnedpassword";

            bool res = await GetRequestAsync(endpoint, password);

            return res;

        }

        /// <summary>
        /// Converts a plain text string to SHA1 hash before transit over a GET request
        /// </summary>
        /// <param name="password">Plain-text password string</param>
        /// <returns>Bool True if the password is known, False if the password safe*</returns>
        public async Task<bool> HasSha1PasswordBeenPwned(string password)
        {
            string endpoint = "pwnedpassword";

            var sha1 = SHA1.Create();

            var inputBytes = Encoding.ASCII.GetBytes(password);

            var hash = sha1.ComputeHash(inputBytes);

            string HashedPassword = BitConverter.ToString(hash).Replace("-", "");

            bool res = await GetRequestAsync(endpoint, HashedPassword);

            return res;

        }

        /// <summary>
        /// Takes a plain text password and forwards it on the the HaveIBeenPwned API
        /// As a POST request
        /// </summary>
        /// <param name="password">Plain text password string</param>
        /// <returns>Bool True if the password is known, False if the password safe*</returns>
        public async Task<bool> PostHasPasswordBeenPwned(string password)
        {
            string endpoint = "pwnedpassword";

            KeyValuePair<string, string> Body = new KeyValuePair<string, string>("Password", password);

            bool res = await PostRequestAsync(endpoint, Body);

            return res;
        }

        /// <summary>
        /// Generic GET request wrapper
        /// </summary>
        /// <param name="endpoint">The API Endpoint (service) to call</param>
        /// <param name="parameter">The string parameter to pass to the endpoint</param>
        /// <returns></returns>
        private async Task<bool> GetRequestAsync(string endpoint, string parameter)
        {
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "007");
            Uri api = new Uri($"{BaseURL}/{endpoint}/{parameter}");

            var result = await client.GetAsync(api);
            client.Dispose();

            return (result.IsSuccessStatusCode ? true : false);

        }

        /// <summary>
        /// Generic POST request wrapper
        /// </summary>
        /// <param name="endpoint">The API Endpoint (service) to call</param>
        /// <param name="bosy">KeyValuePair for the POST Body</param>
        /// <returns></returns>
        private async Task<bool> PostRequestAsync(string endpoint, KeyValuePair<string, string> body)
        {
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "007");
            Uri api = new Uri($"{BaseURL}/{endpoint}");

            var RequestBody = new FormUrlEncodedContent(new[]
            {
                    body
            });

            var result = await client.PostAsync(api, RequestBody);
            client.Dispose();
            return (result.IsSuccessStatusCode ? true : false);

        }

    }
}
