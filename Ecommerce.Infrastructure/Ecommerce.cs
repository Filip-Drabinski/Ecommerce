using Ecommerce.Application;
using MediatR;

namespace Ecommerce.Infrastructure
{
    internal class Ecommerce : Mediator, IEcommerce
    {
        public Ecommerce(ServiceFactory serviceFactory) : base(serviceFactory)
        {
        }
    }
}