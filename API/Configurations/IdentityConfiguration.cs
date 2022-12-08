using Infraestructure.Data.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace example_dotnet_identity.Configurations;

public static class IdentityConfiguration
{
	public static void AddIdentityConfiguration(this IServiceCollection services)
	{
		services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
    }
}