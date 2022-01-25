using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using RefillMicroservice.Model;
using SubscriptionMicroservice.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using RefillMicroservice.TokeInfo;

namespace RefillMicroservice.Repository
{
    public class RefillRepository : IRefillRepository
    {
        RefillDetails refillDetails = new RefillDetails();

        //To View the latest Refill Status of a subscription
        public RefillOrder latestRefillOrder(int id)
        {
            RefillOrder refillOrder = new RefillOrder();
           
            refillOrder = RefillDetails.refillOrders.Where(x => x.Subscription_ID == id).FirstOrDefault();
            if (refillOrder == null)
                return null;
            return refillOrder;
        }


        //Refill microservice endpoint - get refill dues as of date
        public List<RefillOrder> GetRefillDueAsofdates(int sId, DateTime fromdates)
        {
            List<RefillOrder> refillOrder = new List<RefillOrder>();
            try
            {
                Client obj = new Client();
                HttpClient client = obj.SubscriptionApi();           

                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ConstHelpers.TokenString);

                    HttpResponseMessage response = new HttpResponseMessage();
                    StringContent content = new StringContent(JsonConvert.SerializeObject(null), Encoding.UTF8, "application/json");

                    response = client.GetAsync("/api/Subcription/getFrequency?subId=" + sId ).Result;
                    var responseData = JsonConvert.DeserializeObject<MemberSubscription>(response.Content.ReadAsStringAsync().Result);

                    if (response.IsSuccessStatusCode)
                    {
                            if (responseData != null)
                            {
                                //refillOrder.Location = "Hydrabad";
                                string frequency = responseData.RefillOccurrence;
                                refillOrder = CalculateDues(frequency, sId, fromdates);
                            }   
                            
                       
                    }
                
            }
            catch (Exception e)
            {
                return null;
            }
            return refillOrder;
        }

        //Method invoke by Refill microservice endpoint - get refill dues as of date
        public List<RefillOrder> CalculateDues(string frequency, int sid, DateTime fromDate)
        {
            RefillOrder refill1 = new RefillOrder();
            List<RefillOrder> refillList = new List<RefillOrder>();
            foreach (var item in RefillDetails.refillOrders)
            {
                if (item.Subscription_ID == sid)
                {
                    refill1 = item;
                    break;
                }
            }

            if (frequency == "weekly")
            {
                int month = fromDate.Month;
                int nxtmonth = month + 1;
                while (month != nxtmonth)
                {
                    RefillOrder refill = new RefillOrder();
                    refill.RefillOrderId = refill1.RefillOrderId;
                    refill.DrugID = refill1.DrugID;
                    refill.Location = refill1.Location;
                    refill.Subscription_ID = sid;
                    refill.Status = refill1.Status;
                    refill.Policy_ID = refill1.Policy_ID;
                    refill.Member_ID = refill1.Member_ID;
                    fromDate = fromDate.AddDays(7);
                    refill.RefillDate = fromDate;
                    refill.NextRefillDate = fromDate.AddDays(7);
                    refillList.Add(refill);
                    month = fromDate.Month;
                }
            }
            else if(frequency == "monthly")
            {
                int year = fromDate.Year;
                int nxtmonth = year + 1;
                while (year != nxtmonth)
                {
                    RefillOrder refill = new RefillOrder();
                    refill.RefillOrderId = refill1.RefillOrderId;
                    refill.DrugID = refill1.DrugID;
                    refill.Location = refill1.Location;
                    refill.Subscription_ID = sid;
                    refill.Status = refill1.Status;
                    refill.Policy_ID = refill1.Policy_ID;
                    refill.Member_ID = refill1.Member_ID;
                    fromDate = fromDate.AddMonths(1);
                    refill.RefillDate = fromDate;
                    refill.NextRefillDate = fromDate.AddMonths(1);
                    refillList.Add(refill);
                    year = fromDate.Year;
                }
            }    

            return refillList;
        }

        //Refill microservice endpoint - request for refill order
        public RefillOrder requestAdhocRefills(int pId, int sId, int mId, string location)
        {
            RefillOrder refill = new RefillOrder();
            foreach (var item in RefillDetails.refillOrders)
            {
                if (item.Member_ID == mId)
                {
                    refill = item;
                    break;
                }
            }

            //refill = RefillDetails.refillOrders.Where(x => x.Member_ID == mId).FirstOrDefault();
            if (refill != null)
            {
                using (var httpClient = new HttpClient())
                {
                    try
                    {
                        Client obj = new Client();
                        HttpClient client = obj.DrugApi();

                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                            HttpResponseMessage response = new HttpResponseMessage();
                            StringContent content = new StringContent(JsonConvert.SerializeObject(null), Encoding.UTF8, "application/json");
                            response = client.GetAsync("/api/Drug/checkDrugsToRefill?drugId=" + refill.DrugID + "&location=" + refill.DrugID +"&location="+ location).Result;
                            //var responseData = JsonConvert.DeserializeObject<int>(response.Content.ReadAsStringAsync().Result);


                            if (response.IsSuccessStatusCode)
                            {
                                return refill;
                            }
                        
                    }
                    catch (Exception e)
                    {
                        return null;
                    }

                    
                }
            }
            return refill;
                
        }


        //Invoked by subscription microservice for to check pending refill status
        public string getduerefillstatus(int subscription_id)
        {

            string res = "There are due for refill, Unsubscription Failed";
            foreach (var item in RefillDetails.refillOrders)
            {
                if (item.Subscription_ID == subscription_id)
                {                    
                        res = item.Status;
                        break;
                }

            }
            if (res == "pending")
                res = "There are due for refill, Unsubscription Failed";
            else
            {
                res = "You are unsubscribed successfully!";
            }
            return res;
        }

        

        
    }
}
