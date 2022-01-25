using RefillMicroservice.Model;
using RefillMicroservice.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RefillMicroservice.Provider
{
    public class RefillProvider : IRefillProvider
    {
        IRefillRepository _refillRepository;
       
        public RefillProvider()
        {
        }
        public RefillProvider(IRefillRepository refillRepository)
        {
            _refillRepository = refillRepository;
        }

        //To View the latest Refill Status of a subscription
        public RefillOrder ViewLatestRefillDetails(int id)
        {
            _refillRepository = new RefillRepository();
            return _refillRepository.latestRefillOrder(id);
        }


        //Refill microservice endpoint - get refill dues as of date
        public List<RefillOrder> GetRefillDueAsofdates(int sId, DateTime fromDates)
        {
            _refillRepository = new RefillRepository();
            return _refillRepository.GetRefillDueAsofdates(sId,fromDates);
        }

        //Refill microservice endpoint - request for refill order
        public RefillOrder requestAdhocRefill(int pId, int sId, int mId, string location)
        {
            _refillRepository = new RefillRepository();
            return _refillRepository.requestAdhocRefills(pId,sId,mId,location);
        }

        // //invoked by subscription microservice for to check pending refill status
        public string getduerefillstatus(int subscription_id)
        {
            _refillRepository = new RefillRepository();
            return _refillRepository.getduerefillstatus(subscription_id);
        }


    }
}
