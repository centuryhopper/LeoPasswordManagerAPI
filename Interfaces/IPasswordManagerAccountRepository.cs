using Microsoft.AspNetCore.Http;
using LeoPasswordManagerAPI.Models;
using Business.DTOs;

namespace LeoPasswordManagerAPI.Interfaces;

public interface IPasswordManagerAccountRepository<T>
{
    Task<IEnumerable<T>> GetAllAccountsAsync(string userId);
    Task<T?> CreateAsync(T model);
    Task<T?> UpdateAsync(T model);
    Task<T?> DeleteAsync(string passwordAccountId, string userId);
    Task<ServiceResponse> UploadCsvAsync(IFormFile file, string userid);
}