using MediatR;
using MediatR.Pipeline;
using System.Reflection;
using MediatR.Registration;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddCustomMediatR<TCustomMediatrInterface, TCustomMediatr>(this IServiceCollection services,
              params Assembly[] assemblies)
            where TCustomMediatrInterface : IMediator
            where TCustomMediatr : IMediator
            => services.AddCustomMediatR<TCustomMediatrInterface>(assemblies, cfg => cfg.Using<TCustomMediatr>().AsTransient());
        public static IServiceCollection AddCustomMediatR<TCustomMediatrInterface>(this IServiceCollection services, IEnumerable<Assembly> assemblies, Action<MediatRServiceConfiguration>? configuration) where TCustomMediatrInterface : IMediator
        {
            var assembliesToScan = assemblies as Assembly[] ?? assemblies.ToArray();
            if (!assembliesToScan.Any())
            {
                throw new ArgumentException("No assemblies found to scan. Supply at least one assembly to scan for handlers.");
            }
            var serviceConfig = new MediatRServiceConfiguration();

            configuration?.Invoke(serviceConfig);

            AddRequiredServices<TCustomMediatrInterface>(services, serviceConfig);

            ServiceRegistrar.AddMediatRClasses(services, assembliesToScan, serviceConfig);

            return services;
        }

        private static void AddRequiredServices<TCustomMediatrInterface>(IServiceCollection services, MediatRServiceConfiguration serviceConfiguration)
        {
            // Use TryAdd, so any existing ServiceFactory/IMediator registration doesn't get overriden
            services.TryAddTransient<ServiceFactory>(p => p.GetRequiredService);
            services.TryAdd(new ServiceDescriptor(typeof(TCustomMediatrInterface), serviceConfiguration.MediatorImplementationType, serviceConfiguration.Lifetime));
            services.TryAdd(new ServiceDescriptor(typeof(ISender), sp => sp.GetRequiredService<IMediator>(), serviceConfiguration.Lifetime));
            services.TryAdd(new ServiceDescriptor(typeof(IPublisher), sp => sp.GetRequiredService<IMediator>(), serviceConfiguration.Lifetime));

            // Use TryAddTransientExact (see below), we dó want to register our Pre/Post processor behavior, even if (a more concrete)
            // registration for IPipelineBehavior<,> already exists. But only once.
            services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestPreProcessorBehavior<,>));
            services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestPostProcessorBehavior<,>));

            if (serviceConfiguration.RequestExceptionActionProcessorStrategy == RequestExceptionActionProcessorStrategy.ApplyForUnhandledExceptions)
            {
                services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestExceptionActionProcessorBehavior<,>));
                services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestExceptionProcessorBehavior<,>));
            }
            else
            {
                services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestExceptionProcessorBehavior<,>));
                services.TryAddTransientExact(typeof(IPipelineBehavior<,>), typeof(RequestExceptionActionProcessorBehavior<,>));
            }
        }

        private static void TryAddTransientExact(this IServiceCollection services, Type serviceType, Type implementationType)
        {
            if (services.Any(reg => reg.ServiceType == serviceType && reg.ImplementationType == implementationType))
            {
                return;
            }

            services.AddTransient(serviceType, implementationType);
        }
    }
}