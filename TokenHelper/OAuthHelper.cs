using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TokenHelper
{
    public static class OAuthHelper
    {
        /// <summary>
        /// This static helper class allows the user to simply pass in the required OAuth params for a OAuth Grant Type of "client_credentials".  If the user requires a certificate, the user must pass in a Certificate Issuer name, or part of one to match to.  If the user wants to test using a local user store, i.e. not on a server, the user can pass in the username (without domain) and set userCurrentUser to true.
        /// </summary>
        /// <param name="oauthEndpointUrl"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <param name="scope"></param>
        /// <param name="securityProtocolType"></param>
        /// <param name="certIssuerName"></param>
        /// <param name="username"></param>
        /// <param name="useCurrentUser"></param>
        /// <returns></returns>
        public static async Task<string> GetOAuthTokenAsync(string oauthEndpointUrl, string clientId, string clientSecret, string scope, SecurityProtocolType securityProtocolType, string certIssuerName = "", string username = "", bool useCurrentUser = false)
        {
            int requestTimeout = 9999;

            try
            {
                //connectivity settings
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.DefaultConnectionLimit = requestTimeout;
                ServicePointManager.SecurityProtocol = securityProtocolType;

                X509Certificate2 certificateToUse = null;

                if (!string.IsNullOrWhiteSpace(certIssuerName))
                {
                    certificateToUse = FindCertificate(useCurrentUser, certIssuerName, username);
                    //#region find cert

                    ////if testing locally, useCurrentUser = true
                    //using (X509Store store = new X509Store((useCurrentUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine)))
                    //{
                    //    store.Open(OpenFlags.ReadOnly);
                    //    X509Certificate2Collection certs = store.Certificates;

                    //    string machineName = Environment.GetEnvironmentVariable("COMPUTERNAME") + "." + Environment.GetEnvironmentVariable("USERDNSDOMAIN");

                    //    //must iterate with this collection
                    //    foreach (var item in certs)
                    //    {
                    //        if (item.IssuerName.Name.Contains(certIssuerName))
                    //        {
                    //            if (item.Subject.Contains(machineName.ToLower()) || (useCurrentUser && item.Subject.Contains(username.ToLower())))
                    //            {
                    //                certificateToUse = item;
                    //                break;
                    //            }
                    //        }
                    //    }
                    //} //using

                    if (certificateToUse == null)
                    {
                        return "ERROR: Cert not found";
                    }
                }


                #region create request with cert
                //create form data
                var postData = "grant_type=client_credentials";
                postData += "&client_id=" + clientId;
                postData += "&client_secret=" + clientSecret;
                postData += "&scope=" + scope;

                //utf8 to bytearray
                var data = Encoding.UTF8.GetBytes(postData);

                //config request
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(oauthEndpointUrl);

                //Add certificate to request.
                if (certificateToUse != null)
                {
                    request.ClientCertificates.Add(certificateToUse);
                }

                //configure request
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = data.Length;
                request.KeepAlive = false;
                request.UserAgent = null;
                request.Timeout = requestTimeout;
                request.ReadWriteTimeout = requestTimeout;

                //add form data
                using (var stream = await request.GetRequestStreamAsync())
                {
                    await stream.WriteAsync(data, 0, data.Length);
                    await stream.FlushAsync();
                }
                #endregion

                #region make request
                //make request, redact response
                using (WebResponse webResponse = await request.GetResponseAsync())
                using (HttpWebResponse response = webResponse as HttpWebResponse)
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
                #endregion
            }
            catch (Exception ex)
            {
                return "ERROR: " + ex.Message + "," + ex.StackTrace;
            }
        }
        private static X509Certificate2 FindCertificate(bool useCurrentUser, string certIssuerName, string username)
        {
            X509Certificate2 certificateToUse = null;

            //if testing locally, useCurrentUser = true
            using (X509Store store = new X509Store((useCurrentUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine)))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates;

                string machineName = Environment.GetEnvironmentVariable("COMPUTERNAME") + "." + Environment.GetEnvironmentVariable("USERDNSDOMAIN");

                //must iterate with this collection
                foreach (var item in certs)
                {
                    if (item.IssuerName.Name.Contains(certIssuerName))
                    {
                        if (item.Subject.Contains(machineName.ToLower()) || (useCurrentUser && item.Subject.Contains(username.ToLower())))
                        {
                            certificateToUse = item;
                            break;
                        }
                    }
                }
            } //using

            return certificateToUse;
        }

        private static X509Certificate2 FindCertificate(bool useCurrentUser, string thumbPrint)
        {
            X509Certificate2 certificateToUse = null;

            //if testing locally, useCurrentUser = true
            using (X509Store store = new X509Store((useCurrentUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine)))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);

                // Get the first cert with the thumbprint
                if (certCollection.Count > 0)
                {
                    certificateToUse = certCollection[0];
                    // Use certificate
                    Console.WriteLine(certificateToUse.FriendlyName);
                }

            } //using

            return certificateToUse;
        }
    }
}
