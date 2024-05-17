using System.Security.Claims;
using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LeoPasswordManagerAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PasswordsController : ControllerBase
{
    private readonly ILogger<PasswordsController> logger;
    private readonly IPasswordManagerAccountRepository<PasswordManagerAccountDTO> passwordManagerAccountRepository;

    public PasswordsController(ILogger<PasswordsController> logger, IPasswordManagerAccountRepository<PasswordManagerAccountDTO> passwordManagerAccountRepository)
    {
        this.logger = logger;
        this.passwordManagerAccountRepository = passwordManagerAccountRepository;
    }

    [HttpGet]
    [Route("getaccounts")]
    public async Task<IActionResult> Get()
    {
        string userId = User.FindFirst(c=>c.Type == ClaimTypes.NameIdentifier).Value;

        return Ok(await passwordManagerAccountRepository.GetAllAccountsAsync(userId));
    }

    [HttpPost]
    [Route("create")]
    public async Task<IActionResult> Post([FromBody] PasswordManagerAccountDTO model)
    {
        var create = await passwordManagerAccountRepository.CreateAsync(model);

        if (create is null)
        {
            return BadRequest("couldn't create password account");
        }

        return Ok(create);
    }

    [HttpPut]
    [Route("update")]
    public async Task<IActionResult> Update([FromBody] PasswordManagerAccountDTO model)
    {
        var update = await passwordManagerAccountRepository.UpdateAsync(model);

        if (update is null)
        {
            return BadRequest("couldn't update password account");
        }

        return Ok(update);
    }

    [HttpDelete]
    [Route("delete")]
    public async Task<IActionResult> Delete([FromQuery] string passwordAccountId, [FromQuery] string userId)
    {
        var delete = await passwordManagerAccountRepository.DeleteAsync(passwordAccountId, userId);

        if (delete is null)
        {
            return BadRequest("couldn't delete password account");
        }

        return Ok(delete);
    }

    [HttpPost]
    [Route("upload-csv")]
    [Authorize]
    public async Task<IActionResult> UploadCSV(IFormFile file)
    {
        string userId = User.FindFirst(c=>c.Type == ClaimTypes.NameIdentifier).Value;

        var result = await passwordManagerAccountRepository.UploadCsvAsync(file, userId);

        if (!result.flag)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }
}
