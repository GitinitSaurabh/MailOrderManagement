using RefillMicroservice.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RefillMicroservice.Repository
{
    public interface IRefillRepository
    {
        public RefillOrder latestRefillOrder(int id);
        public List<RefillOrder> GetRefillDueAsofdates(int sId, DateTime fromdates);
        public RefillOrder requestAdhocRefills(int pId, int sId, int mId, string location);

        //invoked by subscription microservice for to check pending refill status
        public string getduerefillstatus(int subscription_id);

    }
}
