using SubscriptionMicroservice.Model;
using SubscriptionMicroservice.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SubscriptionMicroservice.Provider
{
    public class SubscriptionProvider : ISubscriptionProvider
    {
        ISubscriptionRepository _subscriptionRepository;
        public SubscriptionProvider()
        {           
        }
        public SubscriptionProvider(ISubscriptionRepository subscriptionRepository)
        {
            _subscriptionRepository = subscriptionRepository;
        }

        //Subscription Microservice - subscrribe
        public string Subscribe(MemberPrescription prescriptionDetails)
        {
            _subscriptionRepository = new SubscriptionRepository();
            return _subscriptionRepository.SubscribeRepo(prescriptionDetails);
        }

        //Subscription Microservice - unsubscrribe
        public string Unsubscribe(int member_id, int subscription_id)
        {
            _subscriptionRepository = new SubscriptionRepository();
            return _subscriptionRepository.Unsubscribe(member_id, subscription_id);
        }


        //Invoked By Refill microservice - getting refill occurance
        public MemberSubscription GetRefillfrequnecyAsofdates(int sId)
        {
            _subscriptionRepository = new SubscriptionRepository();
            return _subscriptionRepository.GetRefillFrequency(sId);
        }

     
    }
}
