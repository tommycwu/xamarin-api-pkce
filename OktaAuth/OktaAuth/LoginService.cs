using IdentityModel;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Xamarin.Essentials;

namespace OktaAuth
{
    class LoginService
    {
        private const string RespType = "code";
        private const string CodeChallengeMethod = "S256";
        public string[] GetAuthzCode(string u, string p)
        {
            var domain = OktaConfiguration.OrganizationUrl;
            var oktaAuthorizationServer = OktaConfiguration.AuthzServer;
            var clientId = OktaConfiguration.ClientId;
            var redirectUrl = OktaConfiguration.Callback;
            var redirectUrlEncoded = System.Net.WebUtility.UrlEncode(redirectUrl);
            var responseType = "code";
            var state = "state";
            var nonce = "nonce";
            var scope = System.Net.WebUtility.UrlEncode("openid email profile");
            var authnUri = $"{domain}/api/v1/authn";
            var username = u;
            var password = p;

            //put the username and password into the body of the post
            dynamic bodyOfRequest = new
            {
                username,
                password,
                options = new
                {
                    multiOptionalFactorEnroll = false,
                    warnBeforePasswordExpired = false,
                },
            };

            var body = JsonConvert.SerializeObject(bodyOfRequest);

            var stringContent = new StringContent(body, Encoding.UTF8, "application/json");

            string sessionToken;

            HttpClientHandler httpClientHandler = new HttpClientHandler();
            httpClientHandler.AllowAutoRedirect = false;

            using (var httpClient = new HttpClient(httpClientHandler))
            {
                httpClient.DefaultRequestHeaders
                    .Accept
                    .Add(new MediaTypeWithQualityHeaderValue("application/json"));

                //POST to authn endpoint
                HttpResponseMessage authnResponse = httpClient.PostAsync(authnUri, stringContent).Result;//post u/p to get session token

                if (authnResponse.IsSuccessStatusCode)
                {
                    var authnResponseContent = authnResponse.Content.ReadAsStringAsync().Result;
                    dynamic authnObject = JsonConvert.DeserializeObject(authnResponseContent);
                    
                    //session token from a successful authentication
                    sessionToken = authnObject.sessionToken;

                    //hash the code verifier
                    var codeVerifier = CryptoRandom.CreateUniqueId(32);
                    string codeChallenge;
                    using (var sha256 = SHA256.Create())
                    {
                        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                        codeChallenge = Base64Url.Encode(challengeBytes);
                    }

                    //build url with session token, hashed code challange
                    var authorizeUri = $"{domain}/oauth2/{oktaAuthorizationServer}/v1/authorize?client_id={clientId}" +
                        $"&redirect_uri={redirectUrlEncoded}&response_type={responseType}&sessionToken={sessionToken}" +
                        $"&state={state}&nonce={nonce}&scope={scope}&code_challenge={codeChallenge}&code_challenge_method=S256";
                    
                    //GET from authorize endpoint
                    HttpResponseMessage authorizeResponse = httpClient.GetAsync(authorizeUri).Result;
                    var statusCode = (int)authorizeResponse.StatusCode;

                    //if successful pull authz code from url
                    if (statusCode == (int)HttpStatusCode.Found)
                    {
                        var redirectUri = authorizeResponse.Headers.Location;
                        var queryDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                        string[] rtnArray = new string[2];
                        rtnArray[0] = queryDictionary[0];//authz code
                        rtnArray[1] = codeVerifier;
                        return rtnArray;
                    }
                }
            }

            return null;
        }


        public string[] GetTokens(string authzCode, string codeVerifier)
        {
            var domain = OktaConfiguration.OrganizationUrl;
            var oktaAuthorizationServer = "default";
            var client_id = OktaConfiguration.ClientId;
            var redirectUrl = OktaConfiguration.Callback;
            var redirect_uri = System.Net.WebUtility.UrlEncode(redirectUrl);
            var grant_type = System.Net.WebUtility.UrlEncode("authorization_code");
            var code = authzCode;
            var code_verifier = codeVerifier;

            //build body param with unhashed code verifier and authz code
            var addParam = $"grant_type={grant_type}&client_id={client_id}&code_verifier={code_verifier}&code={code}&redirect_uri={redirect_uri}";
            
            //build token url
            var tokenUri = $"{domain}/oauth2/{oktaAuthorizationServer}/v1/token";
            var client = new RestClient(tokenUri);
            var request = new RestRequest(Method.POST);
            request.AddHeader("content-type", "application/x-www-form-urlencoded");
            request.AddParameter("application/x-www-form-urlencoded", addParam, ParameterType.RequestBody);
            
            //POST to token endpoint
            IRestResponse response = client.Execute(request);
            var resultArr = new string[2];

            //if successful then you'll have an access token and id token
            if (response.Content.Contains("access_token"))
            {
                var jObject = JObject.Parse(response.Content);
                resultArr[1] = jObject.GetValue("access_token").ToString();
                resultArr[0] = jObject.GetValue("id_token").ToString();
            }
            return resultArr;
        }

    }
}