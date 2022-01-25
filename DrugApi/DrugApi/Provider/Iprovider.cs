using DrugApi.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Provider
{
    public interface Iprovider
    {
        public Drugs GetdrugDetail(int id);
        public Drugs GetdrugDetailByName(string name);
        public DrugLocation GetDispatchableStocks(int id, string location);
        public int AdhocRefillOrder(int drugId, string location);
        public string CheckAvailbleDrug(int drugId);

    }
}
