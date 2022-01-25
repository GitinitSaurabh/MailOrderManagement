using DrugApi.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DrugApi.Repository
{
    public class RepoClass : IDrug
    {
        DrugDetails a = new DrugDetails();
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(RepoClass));

        public Drugs GetdrugDetailsByName(string name)
        {
            try
            {
                Drugs drug = new Drugs();


                foreach (var item in DrugDetails.Drugs)
                {
                    if (item.Drug_Name == name)
                    {
                        drug = item;
                        break;
                    }
                }

                //drug = DrugDetails.Drugs[id];
                _log4net.Info("GetdrugDetails by using the id +id+");
                return drug;
            }
            catch (Exception e)
            {
                return null;
            }

        }



        /// <summary>
        /// This method responsible for returing the Drug Details searched by Drug ID
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public Drugs GetdrugDetails(int id)
        {
            try
            {
                Drugs drug = new Drugs();


                foreach (var item in DrugDetails.Drugs)
                {
                    if (item.Drug_Id == id)
                    {
                        drug = item;
                        break;
                    }
                }

                //drug = DrugDetails.Drugs[id];
                _log4net.Info("GetdrugDetails by using the id +id+");
                return drug;
            }
            catch(Exception e)
            {
                return null;
            }
            
        }

        //Drug Microservice endpoint - get displacthable stocks
      

        //Invoked by Refill microservice - check drugs availble for refill order
        public int AdhocRefillOrder(int drugId, string location)
        {

            foreach (var item in DrugDetails.DrugLocations)
            {
                if (item.Drug_Id == drugId && item.Location_Name == location.ToLower())
                {
                    if (item.Available_Stock > 0)
                        //_log4net.Info()
                        return drugId;
                    else
                        return 0;
                }
            }
            return -1;
        }

        //Invoked by sybscription microservice - check drugs availble for getting subscribe
        public string CheckAvailbleDrug(int drugId)
        {
            try
            {

                foreach (var item in DrugDetails.Drugs)
                {

                    if (item.Drug_Id == drugId)
                    {
                        if (item.Quantity > 0)
                            return "Available";
                        else
                            return "Unavailable";
                    }
                }

                return "Drug not found";
            }
            catch(Exception e)
            {
                return null;
            }
        }
        /// <summary>
        ///  This method responsible for returing the Drug Details searched by Drug ID and Location
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public DrugLocation GetDispatchableStock(int id,string name)
        {
            try
            {
                DrugLocation drugLocation = new DrugLocation();

                foreach (var item in DrugDetails.DrugLocations)
                {
                    if (item.Drug_Id == id && item.Location_Name == name.ToLower())
                    {
                        drugLocation = item;
                        break;
                    }
                }



                //drugLocation = DrugDetails.DrugLocation[id];
                return drugLocation;
            }
            catch(Exception e)
            {
                return null;
            }
            
        }
    }
}
