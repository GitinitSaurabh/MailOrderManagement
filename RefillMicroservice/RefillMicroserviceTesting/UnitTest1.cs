using NUnit.Framework;
using RefillMicroservice.Model;
using RefillMicroservice.Repository;

namespace RefillMicroserviceTesting
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
            RefillRepository refill = new RefillRepository();
        }

        
    }
}