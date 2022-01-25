using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace SubscriptionMicroservice
{
    public class Client
    {
        public HttpClient Authapi()
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri("https://localhost:44311/");
            return client;
        }
        public HttpClient DrugApi()
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri("https://localhost:44337/");
            return client;

        }

        public HttpClient SubscriptionApi()
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri("https://localhost:44361/");
            return client;

        }
        public HttpClient RefillApi()
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri("https://localhost:44302/");
            return client;

        }
    }
}
