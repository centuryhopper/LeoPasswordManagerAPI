using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.EntityFrameworkCore;
using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Models;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Utilities;
using Business.DTOs;


namespace LeoPasswordManagerAPI.Repositories;

public class PasswordManagerAccountRepository : IPasswordManagerAccountRepository<PasswordManagerAccountDTO>
{
    private readonly EncryptionContext encryptionContext;
    private readonly ILogger<PasswordManagerAccountRepository> logger;
    private readonly PasswordManagerDbContext PasswordAccountContext;

    public PasswordManagerAccountRepository(EncryptionContext encryptionContext, ILogger<PasswordManagerAccountRepository> logger, PasswordManagerDbContext PasswordAccountContext)
    {
        this.encryptionContext = encryptionContext;
        this.logger = logger;
        this.PasswordAccountContext = PasswordAccountContext;
    }

    public async Task<PasswordManagerAccountDTO?> CreateAsync(PasswordManagerAccountDTO model)
    {
        model.Id = Guid.NewGuid().ToString();
        model.Password = Convert.ToBase64String(encryptionContext.Encrypt(model.Password));
        model.CreatedAt = DateTime.Now.ToString("yyyy-MM-dd");
        await PasswordAccountContext.PasswordmanagerAccounts.AddAsync(model.ToPasswordManagerAccount());
        await PasswordAccountContext.SaveChangesAsync();
        return model;
    }

    public async Task<PasswordManagerAccountDTO?> DeleteAsync(string passwordAccountId, string userId)
    {
        var queryModel = await PasswordAccountContext.PasswordmanagerAccounts.FindAsync(passwordAccountId, userId);

        if (queryModel is null)
        {
            return null;
        }

        PasswordAccountContext.PasswordmanagerAccounts.Remove(queryModel!);
        await PasswordAccountContext.SaveChangesAsync();
        return queryModel.ToPasswordManagerAccountDTO();
    }

    public async Task<IEnumerable<PasswordManagerAccountDTO>> GetAllAccountsAsync(string userId)
    {
        var results = await PasswordAccountContext.PasswordmanagerAccounts.AsNoTracking().Where(a => a.Userid == userId).ToListAsync();
        // var results = await PasswordAccountContext.PasswordmanagerAccounts.AsNoTracking().ToListAsync();

        if (!results.Any())
        {
            return Enumerable.Empty<PasswordManagerAccountDTO>();
        }

        return results.Select(m =>
        {
            return new PasswordManagerAccountDTO
            {
                Id = m.Id,
                Title = m.Title,
                Username = m.Username,
                Password = encryptionContext.Decrypt(Convert.FromBase64String(m.Password)).Replace(",", "$"),
                Userid = m.Userid,
                CreatedAt = m.CreatedAt,
                LastUpdatedAt = m.LastUpdatedAt
            };
        });
    }

    public int AccountsCount(string UserId, string title)
    {
        var cnt = PasswordAccountContext.PasswordmanagerAccounts.Where(a => a.Userid == UserId && a.Title.ToLower().Contains(title)).Count();
        return cnt;
    }

    public async Task<PasswordManagerAccountDTO?> UpdateAsync(PasswordManagerAccountDTO model)
    {
        var dbModel = await PasswordAccountContext.PasswordmanagerAccounts.FindAsync(model.Id, model.Userid);
        dbModel!.LastUpdatedAt = DateTime.Now.ToString("yyyy-MM-dd");
        dbModel.Title = model.Title;
        dbModel.Username = model.Username;
        dbModel.Password = Convert.ToBase64String(encryptionContext.Encrypt(model.Password));
        await PasswordAccountContext.SaveChangesAsync();

        return model;
    }

    public async Task<ServiceResponse> UploadCsvAsync(IFormFile file, string userid)
    {
        // set up csv helper and read file
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = true,
        };

        using var streamReader = new StreamReader(file.OpenReadStream());
        using var csvReader = new CsvReader(streamReader, config);
        IAsyncEnumerable<PasswordUploadDTO> records;

        try
        {
            csvReader.Context.RegisterClassMap<PasswordsMapper>();
            records = csvReader.GetRecordsAsync<PasswordUploadDTO>();

            await foreach (var record in records)
            {
                await CreateAsync(new PasswordManagerAccountDTO
                {
                    Id = Guid.NewGuid().ToString(),
                    Userid = userid,
                    Title = record.Title,
                    Username = record.Username,
                    Password = record.Password,
                });
            }
        }
        catch (CsvHelperException ex)
        {
            return new ServiceResponse(false, "Failed to upload csv");
        }

        return new ServiceResponse(true, "Upload csv success!");
    }

}

