using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Repositories;
using LeoPasswordManagerAPI.Utilities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;



var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(
    options =>
    {
        options.DefaultScheme = Constants.AUTH_NAME;
    }
)
.AddCookie(Constants.AUTH_NAME, options => {});

builder.Services.Configure<CookieAuthenticationOptions>(Constants.AUTH_NAME, options => {
    // options.AccessDeniedPath = "/Home/";
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    // options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    options.Cookie.Name = "CookieMadeByLeo";
});

builder.Services.AddControllers();
builder.Services.AddHttpContextAccessor();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(
    swagger => {
        swagger.SwaggerDoc("v1", new OpenApiInfo {
            Version = "v1",
            Title = "Password Manager Web API",
            Description = "Authentication with JWT",
        });
    }
);

builder.Services.AddDbContext<PasswordAccountContext>();

builder.Services.AddSingleton<EncryptionContext>();
builder.Services.AddScoped<IAccountRepository, AccountRepository>();
builder.Services.AddScoped<IPasswordManagerAccountRepository<PasswordmanagerAccount>,PasswordManagerAccountRepository>();



// var port = Environment.GetEnvironmentVariable("PORT") ?? "8081";
// builder.WebHost.UseUrls($"http://*:{port}");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(policy =>
{
    // policy.WithOrigins("http://localhost:5121")
    policy.AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader()
    .WithHeaders(HeaderNames.ContentType);
});

app.UseDeveloperExceptionPage();

// app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
