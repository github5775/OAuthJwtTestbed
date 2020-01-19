using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace TokenHelper
{
    public static class JwtHelper
    {
        #region hk
        private static readonly Lazy<HttpClient> lazyHttpClient = new Lazy<HttpClient>(() => new HttpClient());
        private static HttpClient _httpClient { get { return lazyHttpClient.Value; } }

        //public JwtHelper() { }
        #endregion

        #region methods
        /// <summary>
        /// This method allows the user to acquire a Jwt by passing in an OAuth token and token payload paramse.
        /// </summary>
        /// <param name="stsEndpointUrl"></param>
        /// <param name="oAuthToken"></param>
        /// <param name="keyValuePairs"></param>
        /// <returns>string</returns>
        public static async Task<string> GetJwtUsingOAuthToken(string stsEndpointUrl, string oAuthToken, List<KeyValuePair<string, string>> keyValuePairs)
        {
            return await CallEndpoint(stsEndpointUrl, oAuthToken, HttpMethod.Post, keyValuePairs);
        }
        /// <summary>
        /// This method allows the user to call an Api using a bearer token.
        /// </summary>
        /// <param name="apiEndpointUrl"></param>
        /// <param name="jwtToken"></param>
        /// /// <param name="httpMethod"></param>
        /// <param name="keyValuePairs"></param>
        /// <returns>string</returns>
        public static async Task<string> CallApiUsingBearerToken(string apiEndpointUrl, string jwtToken, HttpMethod httpMethod, List<KeyValuePair<string, string>> keyValuePairs)
        {
            return await CallEndpoint(apiEndpointUrl, jwtToken, httpMethod, keyValuePairs);
        }
        #endregion

        #region helpers
        private static async Task<string> CallEndpoint(string url, string token, HttpMethod httpMethod, List<KeyValuePair<string, string>> keyValuePairs)
        {
            string returnValue = "";

            using (HttpRequestMessage request = new HttpRequestMessage(httpMethod, url))
            {
                try
                {
                    _httpClient.DefaultRequestHeaders.Clear();
                    _httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);

                    if (keyValuePairs != null && keyValuePairs.Count > 0)
                    {
                        request.Content = new FormUrlEncodedContent(keyValuePairs);
                    }

                    HttpResponseMessage response = await _httpClient.SendAsync(request);

                    returnValue = await response.Content.ReadAsStringAsync();
                }
                catch (Exception ex)
                {
                    returnValue = "ERROR: " + ex.Message;
                }
            }

            return returnValue;
        }
        #endregion
    }
}
