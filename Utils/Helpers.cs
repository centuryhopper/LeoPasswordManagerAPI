using Microsoft.AspNetCore.Mvc.ModelBinding;
using MimeKit;
using MailKit.Net.Smtp;
using LeoPasswordManagerAPI.DTOs;
using LeoPasswordManagerAPI.Contexts;

namespace LeoPasswordManagerAPI.Utilities;

public static class Helpers
{
    public static IEnumerable<string> GetErrors<T>(this ModelStateDictionary ModelState, ILogger<T>? logger = null)
    {
        // Retrieve the list of errors
        var errors = ModelState.Values.SelectMany(v => v.Errors);
        if (logger is not null)
        {
            errors.ToList().ForEach(e => logger.LogWarning(e.ErrorMessage));
        }

        return errors.Select(e => e.ErrorMessage);
    }

    public static void SendEmail(
        string subject,
        string body,
        string senderEmail,
        string senderPassword,
        IEnumerable<string> receivers
    )
    {
        var msg = new MimeMessage();

        msg.From.Add(new MailboxAddress("Automated Email Message", senderEmail));

        foreach (var receiver in receivers)
        {
            msg.To.Add(MailboxAddress.Parse(receiver));
        }

        msg.Subject = subject;

        msg.Body = new TextPart("plain") { Text = body, };

        var client = new SmtpClient();

        try
        {
            client.Connect("smtp.gmail.com", 465, true);
            client.Authenticate(senderEmail, senderPassword);
            var res = client.Send(msg);
        }
        catch (System.Exception ex)
        {
            System.Console.WriteLine(ex.Message);
        }
        finally
        {
            client.Disconnect(true);
            client.Dispose();
        }
    }

    public static PasswordmanagerAccount ToPasswordManagerAccount(this PasswordManagerAccountDTO dto)
    {
        return new PasswordmanagerAccount {
            Id = dto.Id
            ,Userid = dto.Userid
            ,Title = dto.Title
            ,Username = dto.Username
            ,Password = dto.Password
            ,CreatedAt = dto.CreatedAt
            ,LastUpdatedAt = dto.LastUpdatedAt
        };
    }

    public static PasswordManagerAccountDTO ToPasswordManagerAccountDTO(this PasswordmanagerAccount account)
    {
        return new PasswordManagerAccountDTO {
            Id = account.Id
            ,Userid = account.Userid
            ,Title = account.Title
            ,Username = account.Username
            ,Password = account.Password
            ,CreatedAt = account.CreatedAt
            ,LastUpdatedAt = account.LastUpdatedAt
        };
    }

}
