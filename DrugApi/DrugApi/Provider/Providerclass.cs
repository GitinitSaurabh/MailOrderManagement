using DrugApi.Model;
using DrugApi.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Provider
{
    public class providerclass : Iprovider
    {
        IDrug _drugRepository;

        public providerclass()
        {
        }

        public Drugs GetdrugDetailByName(string name)
        {
            _drugRepository = new RepoClass();
            return _drugRepository.GetdrugDetailsByName(name);
        }

        //Drug Microservice endpoint - Search Drug based on ID
        public Drugs GetdrugDetail(int id)
        {
            _drugRepository = new RepoClass();
            return _drugRepository.GetdrugDetails(id);
        }

        //Drug Microservice endpoint - get displacthable stocks
        public DrugLocation GetDispatchableStocks(int id, string location)
        {
            _drugRepository = new RepoClass();
            return _drugRepository.GetDispatchableStock(id, location);
        }

        //Invoked by Refill microservice - check drugs availble for refill order
        public int AdhocRefillOrder(int drugId, string location)
        {
            _drugRepository = new RepoClass();
            return _drugRepository.AdhocRefillOrder(drugId, location);
        }

        //Invoked by sybscription microservice - check drugs availble for getting subscribe
        public string CheckAvailbleDrug(int drugId)
        {
            _drugRepository = new RepoClass();
            return _drugRepository.CheckAvailbleDrug(drugId);
        }
    }
}
