using DrugApi.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Repository
{
    interface IDrug
    {
        public Drugs GetdrugDetails(int id);
        public Drugs GetdrugDetailsByName(string name);
        public DrugLocation GetDispatchableStock(int id,string name);
        public int AdhocRefillOrder(int drugId, string location);
        public string CheckAvailbleDrug(int drugId);

    }
}
