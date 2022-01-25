using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RefillMicroservice.Model
{
    public class RefillDetails
    {
        public static List<RefillOrder> refillOrders = new List<RefillOrder>()
        {
            new RefillOrder()
            {
                 RefillOrderId=1,
                Subscription_ID = 7,
                DrugID=1,
                RefillDate=new DateTime(2020,09,12),
                FromDate = new DateTime(2020, 05, 15),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 001,
                Member_ID = 1,
                Location = "Mumbai"
            },
            new RefillOrder()
            {
                 RefillOrderId=2,
                Subscription_ID = 8,
                DrugID=2,
                RefillDate=new DateTime(2020,09,12),
                FromDate = new DateTime(2020, 05, 15),
                NextRefillDate=new DateTime(2020,10,08),
                Status="pending",
                Policy_ID = 001,
                Member_ID = 3,
                Location = "Mumbai"
            },
            new RefillOrder()
            {
                 RefillOrderId=3,
                Subscription_ID = 6,
                DrugID=3,
                RefillDate=new DateTime(2020,09,12),
                FromDate = new DateTime(2020, 05, 15),
                NextRefillDate=new DateTime(2020,10,08),
                Status="Successful",
                Policy_ID = 001,
                Member_ID = 2,
                Location = "Chennai"
            }
        };
    }
}
