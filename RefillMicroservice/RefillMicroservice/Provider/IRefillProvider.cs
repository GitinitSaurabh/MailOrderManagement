using RefillMicroservice.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RefillMicroservice.Provider
{
    public interface IRefillProvider
    {
        public RefillOrder ViewLatestRefillDetails(int id);
        public List<RefillOrder> GetRefillDueAsofdates(int sId, DateTime fromDates);
        public RefillOrder requestAdhocRefill(int pId,int sId,int mId,string location);


        //invoked by subscription microservice for to check pending refill status
        public string getduerefillstatus(int subscription_id);

    }
}
