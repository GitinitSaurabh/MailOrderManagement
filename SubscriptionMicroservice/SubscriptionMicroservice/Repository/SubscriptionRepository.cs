using Newtonsoft.Json;
using SubscriptionMicroservice.Model;
using SubscriptionMicroservice.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace SubscriptionMicroservice.Repository
{
    public class SubscriptionRepository : ISubscriptionRepository
    {
        //Subscription Microservice - subscrribe
        static readonly log4net.ILog obj = log4net.LogManager.GetLogger(typeof(SubscriptionRepository));
        public string SubscribeRepo(MemberPrescription prescriptionDetails)
        {            
            string result = "Cannot Subscribe";
            try
            {
                Client obj1 = new Client();
                HttpClient client = obj1.DrugApi();

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ConstHelpers.TokenString);

                    HttpResponseMessage response = new HttpResponseMessage();
                    StringContent content = new StringContent(JsonConvert.SerializeObject(null), Encoding.UTF8, "application/json");
                    response = client.GetAsync("api/Drug/checkAvailbleForSubscription?drugId=" + prescriptionDetails.drugID).Result;
                    var responseData = JsonConvert.DeserializeObject<string>(response.Content.ReadAsStringAsync().Result);

                if (response.IsSuccessStatusCode)
                    {
                        if(responseData.Contains("Available"))
                            result = "Your hve subscribed successfully for given prescription. Thank You!";
                        else
                            result = "Your Prescription can not be accepted due to unavailabilitity of drugs";
                        obj.Info("Subscription Details will be added");
                        return result;
                    }
                
            }
            catch (Exception e)
            {

                obj.Info("Subscription Details will not be added"+e);
            }
            return result;

        }

        //Subscription Microservice - unsubscrribe
        public string Unsubscribe(int member_id, int subscription_id)
        {
            string result = "status defined";
            try
            {

                Client obj = new Client();
                HttpClient client = obj.RefillApi();

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ConstHelpers.TokenString);

                    HttpResponseMessage response = new HttpResponseMessage();
                    StringContent content = new StringContent(JsonConvert.SerializeObject(null), Encoding.UTF8, "application/json");
                    response = client.GetAsync("api/Refill/getPendingStatus?subscription_id=" + subscription_id).Result;
                    var responseData = JsonConvert.DeserializeObject<string>(response.Content.ReadAsStringAsync().Result);

                    if (response.IsSuccessStatusCode)
                    {
                        result = responseData;
                        return result;
                    }
                
            }
            catch (Exception e)
            {
                //Console.WriteLine("Exception occured" + e);
                obj.Info("Not Unsubscribe " + e);

            }
            return result;

        }


        //Invoked By Refill microservice - getting refill occurance
        public MemberSubscription GetRefillFrequency(int sId)
        {
            MemberSubscription member = new MemberSubscription();
            member = SubscriptionDetails.ls.Where(x => x.SubscriptionId == sId).FirstOrDefault();
            if (member == null)
            {
                obj.Info("getting refill frequency with subscription id "+sId);
                return null;
            }
            else
            {
                obj.Info("refill frequency is not updated in subscription id"+sId);
                return member;
            }
        }
        
    }
}
