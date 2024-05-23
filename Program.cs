using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Repositories;
using LeoPasswordManagerAPI.Utilities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using NLog;
using NLog.Web;


/*

keep database structure in sync with app:
    dotnet ef dbcontext scaffold "connection_string" Npgsql.EntityFrameworkCore.PostgreSQL -o Contexts -f


check tables via terminal:
    psql -h <Host/Server> -p <Port> -d <Database Name> -U <User Id> -W

*/

// MUST HAVE IT LIKE THIS FOR NLOG TO RECOGNIZE DOTNET USER-SECRETS INSTEAD OF HARDCODED DELIMIT PLACEHOLDER VALUE FROM APPSETTINGS.JSON
// var logger = LogManager.Setup().LoadConfigurationFromFile("nlog.config").GetCurrentClassLogger();


// try
// {

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    // builder.Logging.ClearProviders();
    // builder.Host.UseNLog();

    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options => {
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax; // We don't want to deal with CSRF Tokens
    });


    // builder.Services.AddAuthentication(
    //     options =>
    //     {
    //         options.DefaultScheme = Constants.AUTH_NAME;
    //     }
    // )
    // .AddCookie(Constants.AUTH_NAME, options => {});


    // var isDev = builder.Environment.IsDevelopment();
    // builder.Services.Configure<CookieAuthenticationOptions>(Constants.AUTH_NAME, options => {
    //     // options.AccessDeniedPath = "/Home/";
    //     options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
    //     options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    //     options.Cookie.HttpOnly = true;
    //     options.ExpireTimeSpan = TimeSpan.FromHours(1);
    //     options.Cookie.Name = "CookieMadeByLeo";

        
    // });

    builder.Services.AddControllers();
    builder.Services.AddHttpContextAccessor();

    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(
        swagger => {
            swagger.SwaggerDoc("v1", new OpenApiInfo {
                Version = "v1",
                Title = "Password Manager Web API",
                Description = "Authentication with Cookies",
            });
        }
    );

    builder.Services.AddDbContext<PasswordManagerDbContext>();

    builder.Services.AddSingleton<EncryptionContext>();
    builder.Services.AddScoped<IAccountRepository, AccountRepository>();
    builder.Services.AddScoped<IPasswordManagerAccountRepository<PasswordManagerAccountDTO>,PasswordManagerAccountRepository>();


    builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsSpecs",
    builder =>
    {
        builder
            .WithOrigins("https://centuryhopper.github.io/LeoPasswordManagerDeployed/", "http://localhost:5024")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .SetIsOriginAllowed(options => true)
            .AllowCredentials();
    });
});


    // comment this two lines out when testing locally
    // but uncomment them when deploying
    if (!builder.Environment.IsDevelopment())
    {
        var port = Environment.GetEnvironmentVariable("PORT") ?? "8081";
        builder.WebHost.UseUrls($"http://*:{port}");
    }

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseCors("CorsSpecs");
    // app.UseCors(policy =>
    // {
    //     // policy.WithOrigins("http://localhost:5121")
    //     policy.AllowAnyOrigin()
    //     .AllowAnyMethod()
    //     .AllowAnyHeader()
    //     .WithHeaders(HeaderNames.ContentType);
    // });

    app.UseDeveloperExceptionPage();

    // app.UseHttpsRedirection();

    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
// }
// catch (Exception ex)
// {
//     logger.Error(ex, "Stopped program because of exception: " + ex);
//     throw ex;
// }
// finally {
//     LogManager.Shutdown();
// }

