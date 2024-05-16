using System.Collections;
using LeoPasswordManagerAPI.Contexts;
using Microsoft.EntityFrameworkCore;
using LeoPasswordManagerAPI.Models;
using LeoPasswordManagerAPI.Interfaces;
using LeoPasswordManagerAPI.Utilities;
using LeoPasswordManagerAPI.DTOs;
using Business.DTOs;
using LeoPasswordManager.Models;

namespace LeoPasswordManagerAPI.Repositories;

/*
insert into roles
values ('056k16c9-07fb-4184-b1e6-89df8474690f','Admin');
insert into roles
values ('930013u9-07fb-4184-b1e6-072f4474690f','User');

INSERT INTO userroles
values('056c56c9-07fb-4184-b1e6-89df8474690f','056k16c9-07fb-4184-b1e6-89df8474690f')
*/

public class AccountRepository : IAccountRepository
{
    private readonly EncryptionContext encryptionContext;
    private readonly PasswordManagerDbContext passwordManagerDbContext;
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly IConfiguration configuration;

    public AccountRepository(EncryptionContext encryptionContext, PasswordManagerDbContext passwordAccountContext, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
    {
        this.encryptionContext = encryptionContext;
        this.passwordManagerDbContext = passwordAccountContext;
        this.httpContextAccessor = httpContextAccessor;
        this.configuration = configuration;
    }

    // private string GenerateJWTToken(UserModel user)
    // {
    //     // Define token expiration time
    //     var expirationTime = DateTime.UtcNow.AddDays(5);

    //     // Create symmetric security key
    //     var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));

    //     // Create signing credentials
    //     var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    //     // Define claims (you can add more claims as needed)
    //     var claims = new[]
    //     {
    //         new Claim(ClaimTypes.NameIdentifier, user.Id),
    //         new Claim(ClaimTypes.Name, user.FirstName + " " + user.LastName),
    //         new Claim(ClaimTypes.Email, user.Email),
    //         new Claim(ClaimTypes.Role, user.Role),
    //     };

    //     var token = new JwtSecurityToken(
    //         issuer: configuration["Jwt:Issuer"],
    //         audience: configuration["Jwt:Audience"],
    //         claims: claims,
    //         expires: DateTime.Now.AddDays(5),
    //         signingCredentials: credentials
    //     );

    //     return new JwtSecurityTokenHandler().WriteToken(token);
    // }

    public async Task<IEnumerable<RoleDTO>> GetRolesAsync()
    {
        return from role in await passwordManagerDbContext.Roles.ToListAsync() select new RoleDTO { RoleId = role.Id, RoleName = role.Name };
    }

    public async Task<ServiceResponse> DeleteUserRoleAsync(string userId, string roleId)
    {
        var ur = await passwordManagerDbContext.Userroles.FirstOrDefaultAsync(ur => ur.Userid == userId && ur.Roleid == roleId);

        if (ur is null)
        {
            return new ServiceResponse(false, "user role not found");
        }

        passwordManagerDbContext.Userroles.Remove(ur!);

        await passwordManagerDbContext.SaveChangesAsync();

        return new ServiceResponse(true, "user role successfully deleted");
    }

    public async Task<UserRoleDTO?> GetUserCurrentRoleAsync(string userId)
    {
        var user = await passwordManagerDbContext.PasswordmanagerUsers.Where(u => u.Id == userId).Include(u => u.Userroles).ThenInclude(ur => ur.Role).FirstOrDefaultAsync();

        if (user is null)
        {
            return null;
        }

        return new UserRoleDTO
        {
            UserId = user.Userroles.First().Userid,
            RoleId = user.Userroles.First().Roleid,
            RoleName = user.Userroles.First().Role.Name,
        };
    }

    public async Task<PasswordmanagerUser?> GetUserByIdAsync(string userId)
    {
        var user = await passwordManagerDbContext.PasswordmanagerUsers.FindAsync(userId);
        return user;
    }

    public async Task<UserDTO?> GetUserByIdAsDTOAsync(string userId)
    {
        var user = await passwordManagerDbContext.PasswordmanagerUsers.FindAsync(userId);
        if (user == null)
        {
            return null;
        }

        var userRoleDTO = await GetUserCurrentRoleAsync(userId);
        if (userRoleDTO == null)
        {
            return null;
        }

        return new UserDTO
        {
            Id = user.Id
            ,
            Salt = user.Salt
            ,
            PasswordHash = user.Passwordhash
            ,
            Email = user.Email
            ,
            FirstName = user.Firstname
            ,
            LastName = user.Lastname
            ,
            Role = userRoleDTO!.RoleName
        };
    }

    public async Task<EmailConfirmStatus> IsEmailConfirmed(string email)
    {
        var user = await passwordManagerDbContext.PasswordmanagerUsers.FirstOrDefaultAsync(u => u.Email == email);
        if (user is null)
        {
            return EmailConfirmStatus.ACCOUNT_NOT_REGISTERED;
        }
        return user.Emailconfirmed.Get(0) ? EmailConfirmStatus.CONFIRMED : EmailConfirmStatus.NOT_CONFIRMED;
    }

    public async Task<UserDTO?> GetUserByEmailAsync(string email)
    {
        var users = passwordManagerDbContext.PasswordmanagerUsers.AsQueryable();
        var roles = passwordManagerDbContext.Roles.AsQueryable();
        var userroles = passwordManagerDbContext.Userroles.AsQueryable();
        // List<string> userroles = [];

        // List<UserModel> dbResult = [];

        var dbResult = from u in users
                       where u.Email == email
                       join ur in passwordManagerDbContext.Userroles on u.Id equals ur.Userid into userRoles_g
                       from userRole in userRoles_g.DefaultIfEmpty()
                       join r in passwordManagerDbContext.Roles on userRole.Roleid equals r.Id into roles_g
                       from r in roles_g.DefaultIfEmpty()
                       select new UserDTO
                       {
                           Id = u.Id,
                           Salt = u.Salt,
                           PasswordHash = u.Passwordhash,
                           Email = u.Email,
                           FirstName = u.Firstname,
                           LastName = u.Lastname,
                           Role = r.Name
                       };

        return await dbResult.FirstOrDefaultAsync();
    }

    public async Task<ServiceResponse> CheckPassword(string email, string password)
    {
        var userModel = await GetUserByEmailAsync(email);

        if (userModel is null)
        {
            return new ServiceResponse(false, "Couldn't find you in the system.");
        }

        var hashedPW = encryptionContext.OneWayHash($"{password}{userModel.Salt}");

        if (hashedPW != userModel.PasswordHash)
        {
            return new ServiceResponse(false, "Current password entered is incorrect.");
        }

        return new ServiceResponse(true, "Correct password entered!");
    }

    public async Task<LoginResponse> LoginAsync(LoginDTO model)
    {
        // get user from db
        // if user in db matches user logging in
        // then return the user
        // otherwise return null

        var userModel = await GetUserByEmailAsync(model.Email);

        // PasswordmanagerUser dbResult = null;

        if (userModel is null)
        {
            return new LoginResponse(false, msg: "User not found");
        }

        var hashedPW = encryptionContext.OneWayHash($"{model.Password}{userModel.Salt}");

        if (hashedPW == userModel.PasswordHash)
        {
            // update login userfield
            var user = await passwordManagerDbContext.PasswordmanagerUsers.FindAsync(userModel.Id);
            user!.Datelastlogin = DateTime.Now;
            await passwordManagerDbContext.SaveChangesAsync();

            return new LoginResponse(true, msg: "Login Succesful!", Id: userModel.Id, Name: userModel.FirstName + " " + userModel.LastName, Role: userModel.Role, Email: userModel.Email);
        }

        return new LoginResponse(false, msg: "Incorrect email or password");
    }

    public async Task<ServiceResponse> LogoutAsync(string userId)
    {
        // update logout userfield
        var user = await passwordManagerDbContext.PasswordmanagerUsers.FindAsync(userId);
        user!.Datelastlogout = DateTime.Now;
        await passwordManagerDbContext.SaveChangesAsync();
        return new ServiceResponse(true, "logout successful!");
    }

    public async Task<ServiceResponse> ChangePasswordAsync(string userId, string newPassword)
    {
        try
        {
            int salt = new Random().Next();
            var saltedPW = $"{newPassword}{salt}";
            var passwordHash = encryptionContext.OneWayHash(saltedPW);

            var user = await GetUserByIdAsync(userId);
            user.Passwordhash = passwordHash;
            user.Salt = salt.ToString();

            await passwordManagerDbContext.SaveChangesAsync();
        }
        catch (System.Exception ex)
        {
            return new ServiceResponse(false, ex.Message);
        }

        return new ServiceResponse(true, "Successfully changed password.");
    }

    public async Task<RegistrationResponse> RegisterAsync(RegisterDTO model)
    {
        var dbResult = await GetUserByEmailAsync(model.Email);

        if (dbResult is not null)
        {
            return new RegistrationResponse(false, "Can't register because user already exists");
        }

        try
        {
            var UserId = Guid.NewGuid().ToString();
            int salt = new Random().Next();
            var saltedPW = $"{model.Password}{salt}";
            var passwordHash = encryptionContext.OneWayHash(saltedPW);

            await passwordManagerDbContext.PasswordmanagerUsers.AddAsync(
                new PasswordmanagerUser
                {
                    Id = UserId,
                    Email = model.Email,
                    Salt = salt.ToString(),
                    Passwordhash = passwordHash,
                    Firstname = model.FirstName,
                    Lastname = model.LastName,
                    // make sure to keep this as false when done testing registration
                    Emailconfirmed = new BitArray(new bool[] { false }),
                    Lockoutenabled = new BitArray(new bool[] { false }),
                    Lockoutenddateutc = null,
                    Accessfailedcount = 0,
                    Datelastlogin = DateTime.Now,
                    Datelastlogout = null,
                }
            );

            await CreateEmailConfirmationToken(model.Email, UserId);

            // assign role of "User" to this user
            var role = await passwordManagerDbContext.Roles.FirstOrDefaultAsync(r => r.Name == "User");
            string roleId = Guid.NewGuid().ToString();
            if (role is null)
            {
                await passwordManagerDbContext.Roles.AddAsync(new Role
                {
                    Id = roleId,
                    Name = "User"
                });
            }

            await passwordManagerDbContext.Userroles.AddAsync(new Userrole { Roleid = role?.Id ?? roleId, Userid = UserId, Id = Guid.NewGuid().ToString() });

            await passwordManagerDbContext.SaveChangesAsync();

            return new RegistrationResponse(true, msg: "Registration Successful! Please confirm your email to get started.", Id: UserId, Name: model.FirstName + " " + model.LastName, Role: role!.Name, Email: model.Email);
        }
        catch (System.Exception e)
        {
            return new RegistrationResponse(false, e.Message);
        }
    }

    private async Task CreateEmailConfirmationToken(string email, string UserId)
    {
        // create and send email confirmation link
        var token = TokenGenerator.GenerateToken(32);

        var TokenPK = Guid.NewGuid().ToString();
        var LoginProvider = AccountProviders.EMAIL_CONFIRMATION.ToString();
        // make sure there are no spaces to preserve consistent token identity when passing thru urls
        var ProviderKey = token.Replace(" ", "+");
        var UserIdFK = UserId;

        await passwordManagerDbContext.Usertokens.AddAsync(new Usertoken
        {
            Id = TokenPK,
            Loginprovider = LoginProvider,
            Providerkey = ProviderKey,
            Userid = UserIdFK,
        });

        var emailLink = $"{httpContextAccessor.HttpContext.Request.Scheme}://{httpContextAccessor.HttpContext.Request.Host}";

        // store token in user token table
        SendConfirmationEmail(email, $"{emailLink}/api/Account/confirm-email/?token={token}&userId={UserIdFK}");
    }

    public async Task<ServiceResponse> UpdateUserAsync(EditAccountDTO model)
    {
        // yell at the user if old password is incorrect
        var userModel = await GetUserByIdAsync(model.Id!);

        if (userModel is null)
        {
            return new ServiceResponse(false, "User Not Found");
        }

        var hashedPW = encryptionContext.OneWayHash($"{model.OldPassword}{userModel.Salt}");

        if (hashedPW != userModel.Passwordhash)
        {
            return new ServiceResponse(false, "Your old password is incorrect!");
        }

        // modify fields
        userModel.Firstname = model.FirstName;
        userModel.Lastname = model.LastName;

        int salt = new Random().Next();
        var saltedPW = $"{model.NewPassword}{salt}";
        var passwordHash = encryptionContext.OneWayHash(saltedPW);
        userModel.Salt = salt.ToString();
        userModel.Passwordhash = passwordHash;


        // change role as well if different
        var userRoleDTO = await GetUserCurrentRoleAsync(userModel.Id);

        string userId = userRoleDTO!.UserId, roleId = userRoleDTO.RoleId, roleName = userRoleDTO.RoleName;

        if (model.Role != roleName)
        {
            // delete old userrole link and add new one
            var deletedUR = await DeleteUserRoleAsync(userId, roleId);

            var role = (await GetRolesAsync()).FirstOrDefault(r => r.RoleName == model.Role);

            // add new role
            await passwordManagerDbContext.Userroles.AddAsync(new Userrole { Roleid = role!.RoleId, Userid = userId, Id = Guid.NewGuid().ToString() });
            await passwordManagerDbContext.SaveChangesAsync();
        }

        // send confirmation email if user entered a new email
        // only remove the current working email once confirmed
        // in case they make a mistake and typed in the wrong email and cant log back in
        await CreateEmailConfirmationToken(model.Email!, userModel.Id);

        // add the new email to a "potential new email" column and set the email column value to it if the new email is confirmed
        if (model.Email != userModel.Email)
        {
            userModel.Newemail = model.Email;
            await passwordManagerDbContext.SaveChangesAsync();
        }


        return new ServiceResponse(true, "success!");
    }

    public async Task<ServiceResponse> ConfirmEmailAsync(AccountProviders accountProviders, string token, string userId)
    {
        var loginProvider = accountProviders.ToString();
        try
        {
            var result = await passwordManagerDbContext.Usertokens.FirstAsync(ut => ut.Userid == userId && ut.Loginprovider == loginProvider);

            // we know the any spaces of the token stored in the db has pluses replaced them, so we do this with our current token as well
            token = token.Replace(" ", "+");

            if (string.IsNullOrEmpty(result.Providerkey) || result.Providerkey != token)
            {
                // Console.WriteLine($"token: {token}");
                // Console.WriteLine($"result: {result}");
                return new ServiceResponse(false, "provider key doesn't match token");
            }

            // mark email as confirmed
            var user = await passwordManagerDbContext.PasswordmanagerUsers.FirstAsync(u => u.Id == userId);
            // updatedUserEmailConfirmed.Emailconfirmed.Set(0, true);
            user.Emailconfirmed = new BitArray(new bool[] { true });

            // set email to the new email if the new email exists then remove the value from new email column
            user.Email = user.Newemail ?? user.Email;
            user.Newemail = null;

            // remove user token
            passwordManagerDbContext.Usertokens.Remove(result);

            await passwordManagerDbContext.SaveChangesAsync();

            return new ServiceResponse(true, "Email confirmed!");
        }
        catch (Exception e)
        {
            return new ServiceResponse(false, e.Message);
        }
    }

    private void SendConfirmationEmail(string recipientEmail, string confirmationLink)
    {
        // Configure email settings
        string senderEmail = configuration.GetConnectionString("smtp_client").Split("|")[0];
        string senderPassword = configuration.GetConnectionString("smtp_client").Split("|")[1];

        // string receivers = config.GetConnectionString("smtp_receivers");

        Helpers.SendEmail(
            subject: "Password Manager email confirmation",
            body: $"Please confirm your email by clicking the following link: {confirmationLink}",
            senderEmail: senderEmail,
            senderPassword: senderPassword,
            receivers: [recipientEmail]
        );
    }

    Task<ServiceResponse> IAccountRepository.DeleteUserAsync(string Id)
    {
        throw new NotImplementedException();
    }
}