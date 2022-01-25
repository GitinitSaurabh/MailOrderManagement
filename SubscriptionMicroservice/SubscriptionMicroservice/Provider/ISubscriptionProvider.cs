using SubscriptionMicroservice.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SubscriptionMicroservice.Provider
{
    public interface ISubscriptionProvider
    {
        public string Subscribe(MemberPrescription prescriptionDetails);
        public string Unsubscribe(int member_id, int subscription_id);
        public MemberSubscription GetRefillfrequnecyAsofdates(int sId);
        
    }
}
