using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace LeoPasswordManagerAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PasswordsController : ControllerBase
{
    private readonly ILogger<PasswordsController> logger;
    private readonly IPasswordManagerAccountRepository<PasswordmanagerAccount> passwordManagerAccountRepository;

    public PasswordsController(ILogger<PasswordsController> logger, IPasswordManagerAccountRepository<PasswordmanagerAccount> passwordManagerAccountRepository)
    {
        this.logger = logger;
        this.passwordManagerAccountRepository = passwordManagerAccountRepository;
    }

    [HttpGet]
    [Route("getaccounts")]
    public async Task<IActionResult> Get()
    {
        var userId = "c9162653-180b-4875-9fb3-40f8fd369b66";
        return Ok(await passwordManagerAccountRepository.GetAllAccountsAsync(userId));
    }

    [HttpPost]
    [Route("create")]
    public async Task<IActionResult> Post([FromBody] PasswordmanagerAccount model)
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
    public async Task<IActionResult> Update([FromBody] PasswordmanagerAccount model)
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
    public async Task<IActionResult> Delete([FromBody] PasswordmanagerAccount model)
    {
        var delete = await passwordManagerAccountRepository.DeleteAsync(model);

        if (delete is null)
        {
            return BadRequest("couldn't delete password account");
        }

        return Ok(delete);
    }
}
