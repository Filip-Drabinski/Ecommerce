using Ecommerce.Application;
using Microsoft.Extensions.Configuration;


// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddEcommerce(this IServiceCollection services,IConfiguration configuration)
        {
            services.AddCustomMediatR<IEcommerce, Ecommerce.Infrastructure.Ecommerce>(typeof(IEcommerce).Assembly);
            return services;
        }
    }
}