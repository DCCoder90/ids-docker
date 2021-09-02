using System.Reflection;
using IdentityServer4.EntityFramework.DbContexts;
using Ids.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Ids
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment, ILogger logger)
        {
            Configuration = configuration;
            Environment = environment;
        }

        private IConfiguration Configuration { get; }
        private IWebHostEnvironment Environment { get; }
        
        public void ConfigureServices(IServiceCollection services)
        {
            //TODO: Clean this up
            using var serviceScope = services.BuildServiceProvider().GetService<IServiceScopeFactory>()?.CreateScope();
            var loggerFactory = serviceScope.ServiceProvider.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("Configure");

            services.AddHealthChecks();

//            if(!Configuration.HasLocalConfiguration())
//                services.AddModifiedConsulConfig(Configuration);
                
            services.AddControllersWithViews();

            services.AddLogging(x =>
            {
                x.AddConsole()
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning);
                
                if (Environment.IsDevelopment())
                    x.AddDebug();
            });
            
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            //Users:
            //Config
            //Operation
            
            services.AddDbContext<UserContext>(options=>options.UseSqlServer(Configuration["UsersConnStr"], 
                    sql => sql.MigrationsAssembly(migrationsAssembly)));
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<UserContext>()
                .AddDefaultTokenProviders();
            
            services.AddIdentityServer()
                .AddAspNetIdentity<ApplicationUser>()
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseSqlServer(Configuration["ConfigConnStr"],
                        sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseSqlServer(Configuration["OperationalConnStr"],
                        sql => sql.MigrationsAssembly(migrationsAssembly));
                }).AddDeveloperSigningCredential();
        }

        public void Configure(IApplicationBuilder app)
        {
            InitializeDatabase(app);
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

//            if(!Configuration.HasLocalConfiguration())
//                app.UseModifiedConsul();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
                endpoints.MapHealthChecks("/health");
            });
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            if (!bool.Parse(Configuration["Migrate"])) return;
            
            using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>()?.CreateScope();
            if (serviceScope == null) return;
            
            var loggerFactory = serviceScope.ServiceProvider.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("Initializer");
            
            logger.LogInformation("Initializing");
            
            logger.LogInformation("Migrating Databases");
            //Migrate Databases
            serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
            serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.Migrate();
            serviceScope.ServiceProvider.GetRequiredService<UserContext>().Database.Migrate();


            var configurationDbContext = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();


            Initialize.Clients(logger,configurationDbContext, Configuration);
            Initialize.IdentityResources(logger,configurationDbContext, Configuration);
            Initialize.ApiResources(logger,configurationDbContext, Configuration);
            Initialize.ApiScopes(logger,configurationDbContext, Configuration);
            
            logger.LogInformation("Done Initializing.");
        }
    }
}