using System.Security.Claims;
using LeoPasswordManager.Models;
using LeoPasswordManagerAPI.Contexts;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Models;
using LeoPasswordManagerAPI.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LeoPasswordManagerAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly ILogger<AccountController> logger;
    private readonly IAccountRepository accountRepository;

    public AccountController(ILogger<AccountController> logger, IAccountRepository accountRepository)
    {
        this.logger = logger;
        this.accountRepository = accountRepository;
    }

    [HttpPut, Route("update-user-details")]
    [Authorize]
    public async Task<IActionResult> UpdateUserAsync([FromBody] EditAccountDTO dto)
    {
        var updateUserResult = await accountRepository.UpdateUserAsync(dto);

        if (!updateUserResult.flag)
        {
            return BadRequest(updateUserResult);
        }

        return Ok(updateUserResult);
    }

    [HttpGet, Route("get-roles")]
    [Authorize]
    public async Task<IActionResult> GetRoles()
    {
        return Ok(await accountRepository.GetRolesAsync());
    }

    [HttpPost, Authorize, Route("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordVM model)
    {
        if (!ModelState.IsValid)
        {
            var lst = Helpers.GetErrors<AccountController>(ModelState).ToList();
            return BadRequest(string.Join("$$$", lst));
        }

        var user = await accountRepository.GetUserByEmailAsync(model.CurrentEmail);

        if (user is null)
        {
            return BadRequest("couldn't find you in our system");
        }

        var checkPasswordResult = await accountRepository.CheckPassword(user.Email, model.CurrentPassword);
        if (!checkPasswordResult.flag)
        {
            return BadRequest(checkPasswordResult);
        }

        var changePasswordResult = await accountRepository.ChangePasswordAsync(user.Id, model.NewPassword);

        if (!changePasswordResult.flag)
        {
            return BadRequest(changePasswordResult);
        }

        return Ok(changePasswordResult);
    }

    [HttpGet, Route("logout"), Authorize]
    public async Task<IActionResult> LogOut()
    {
        var userId = User.FindFirst(c => c.Type == ClaimTypes.NameIdentifier)!.Value;
        var logoutResult = await accountRepository.LogoutAsync(userId);
        await HttpContext.SignOutAsync(Constants.AUTH_NAME);

        return Ok(logoutResult);
    }

    [HttpGet, Route("test")]
    [Authorize]
    public IActionResult Test()
    {
        // logger.LogWarning("logged from accounts controller test method!");
        return Ok("access granted");
    }

    [HttpPost, Route("confirm-email"), AllowAnonymous]
    public async Task<IActionResult> ConfirmEmailAsync(string token, string userId)
    {
        var verifyToken = await accountRepository.ConfirmEmailAsync(AccountProviders.EMAIL_CONFIRMATION, token, userId);

        if (!verifyToken.flag)
        {
            return BadRequest(verifyToken);
        }

        return Ok(verifyToken);
    }

    [HttpPost]
    [Route("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterDTO vm)
    {
        if (!ModelState.IsValid)
        {
            var lst = Helpers.GetErrors<AccountController>(ModelState).ToList();
            return BadRequest(string.Join("$$$", lst));
        }

        var result = await accountRepository.RegisterAsync(vm);

        if (!result.flag)
        {
            return BadRequest(result);
        }

        return Ok(result);
    }

    [HttpGet]
    [Route("get-user-profile")]
    // [Authorize]
    public async Task<IActionResult> GetUserProfileAsync()
    {
        if (!User.Identity.IsAuthenticated)
        {
            return BadRequest();
        }
        string userId = User.FindFirst(c=>c.Type == ClaimTypes.NameIdentifier).Value;

        var user = await accountRepository.GetUserByIdAsDTOAsync(userId);

        return Ok(user);
    }

    [HttpPost]
    [Route("login")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginAsync([FromBody] LoginDTO vm)
    {
        if (!ModelState.IsValid)
        {
            var lst = Helpers.GetErrors<AccountController>(ModelState).ToList();
            return BadRequest(new LoginResponse(false, msg: string.Join("$$$", lst)));
        }

        if (User.Identity.IsAuthenticated)
        {
            return BadRequest(new LoginResponse(false, msg: "You're already logged in"));
        }

        if (await accountRepository.IsEmailConfirmed(vm.Email) == EmailConfirmStatus.NOT_CONFIRMED)
        {
            return BadRequest(new LoginResponse(false, msg: "Please confirm your email."));
        }

        // we don't tell the user that this email isn't in our database to avoid data breaching
        // that's why we give a generic error message below
        if (await accountRepository.IsEmailConfirmed(vm.Email) == EmailConfirmStatus.ACCOUNT_NOT_REGISTERED)
        {
            return BadRequest(new LoginResponse(false, msg: "Your identity couldn't be verified with us."));
        }

        var result = await accountRepository.LoginAsync(vm);

        if (result.flag)
        {

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, result.Id),
                new Claim(ClaimTypes.Name, result.Name),
                new Claim(ClaimTypes.Email, result.Email),
                new Claim(ClaimTypes.Role, result.Role),
            };

            var claimsIdentity = new ClaimsIdentity(
                claims, Constants.AUTH_NAME);

            var authProperties = new AuthenticationProperties();

            await HttpContext.SignInAsync(
                Constants.AUTH_NAME,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            return Ok(result);
        }

        return BadRequest(result);
    }

}
