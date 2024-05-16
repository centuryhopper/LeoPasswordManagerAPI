using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.EntityFrameworkCore;
using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Models;


namespace LeoPasswordManagerAPI.Repositories;

public class PasswordManagerAccountRepository : IPasswordManagerAccountRepository<PasswordmanagerAccount>
{
    private readonly EncryptionContext encryptionContext;
    private readonly ILogger<PasswordManagerAccountRepository> logger;
    private readonly PasswordAccountContext PasswordAccountContext;

    public PasswordManagerAccountRepository(EncryptionContext encryptionContext, ILogger<PasswordManagerAccountRepository> logger, PasswordAccountContext PasswordAccountContext)
    {
        this.encryptionContext = encryptionContext;
        this.logger = logger;
        this.PasswordAccountContext = PasswordAccountContext;
    }

    public async Task<PasswordmanagerAccount?> CreateAsync(PasswordmanagerAccount model)
    {
        model.Id = Guid.NewGuid().ToString();
        model.Password = Convert.ToBase64String(encryptionContext.Encrypt(model.Password));
        model.CreatedAt = DateTime.Now.ToString("yyyy-MM-dd");
        await PasswordAccountContext.PasswordmanagerAccounts.AddAsync(model);
        await PasswordAccountContext.SaveChangesAsync();
        return model;
    }

    public async Task<PasswordmanagerAccount?> DeleteAsync(PasswordmanagerAccount model)
    {
        var queryModel = await PasswordAccountContext.PasswordmanagerAccounts.FindAsync(model.Id, model.Userid);
        PasswordAccountContext.PasswordmanagerAccounts.Remove(queryModel!);
        await PasswordAccountContext.SaveChangesAsync();
        return model;
    }

    public async Task<IEnumerable<PasswordmanagerAccount>> GetAllAccountsAsync(string userId)
    {
        var results = await PasswordAccountContext.PasswordmanagerAccounts.AsNoTracking().Where(a => a.Userid == userId).ToListAsync();
        // var results = await PasswordAccountContext.PasswordmanagerAccounts.AsNoTracking().ToListAsync();

        if (!results.Any())
        {
            return Enumerable.Empty<PasswordmanagerAccount>();
        }

        return results.Select(m =>
        {
            return new PasswordmanagerAccount
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

    public async Task<PasswordmanagerAccount?> UpdateAsync(PasswordmanagerAccount model)
    {
        var dbModel = await PasswordAccountContext.PasswordmanagerAccounts.FindAsync(model.Id, model.Userid);
        dbModel!.LastUpdatedAt = DateTime.Now.ToString("yyyy-MM-dd");
        dbModel.Title = model.Title;
        dbModel.Username = model.Username;
        dbModel.Password = Convert.ToBase64String(encryptionContext.Encrypt(model.Password));
        await PasswordAccountContext.SaveChangesAsync();

        return model;
    }

    public async Task<UploadStatus> UploadCsvAsync(IFormFile file, string userid)
    {
        // set up csv helper and read file
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = true,
        };

        using var streamReader = new StreamReader(file.OpenReadStream());
        using var csvReader = new CsvReader(streamReader, config);
        IAsyncEnumerable<PasswordmanagerAccount> records;

        try
        {
            csvReader.Context.RegisterClassMap<PasswordsMapper>();
            records = csvReader.GetRecordsAsync<PasswordmanagerAccount>();

            await foreach (var record in records)
            {
                await CreateAsync(new PasswordmanagerAccount
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
            return new UploadStatus
            {
                Message = "Failed to upload csv",
                UploadEnum = UploadEnum.FAIL
            };
        }

        return new UploadStatus
        {
            Message = "Upload csv success!",
            UploadEnum = UploadEnum.SUCCESS
        };
    }

}

