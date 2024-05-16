// using System;
// using System.Collections.Generic;
// using Microsoft.EntityFrameworkCore;

// KEEP WHOLE FILE COMMENTED OUT!

// namespace LeoPasswordManagerAPI.Contexts;

// public partial class PasswordManagerDbContext : DbContext
// {
//     private readonly IConfiguration configuration;
//     private readonly IHostEnvironment env;

//     public PasswordManagerDbContext()
//     {
//     }

//     public PasswordManagerDbContext(DbContextOptions<PasswordAccountContext> options, IConfiguration configuration, IHostEnvironment env)
//         : base(options)
//     {
//         this.configuration = configuration;
//         this.env = env;
//     }

//     public PasswordManagerDbContext(DbContextOptions<PasswordManagerDbContext> options)
//         : base(options)
//     {
//     }

//     public virtual DbSet<PasswordmanagerAccount> PasswordmanagerAccounts { get; set; }

//     public virtual DbSet<PasswordmanagerUser> PasswordmanagerUsers { get; set; }

//     public virtual DbSet<Role> Roles { get; set; }

//     public virtual DbSet<Userrole> Userroles { get; set; }

//     public virtual DbSet<Usertoken> Usertokens { get; set; }

//     protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
//     {
//         if (!optionsBuilder.IsConfigured)
//         {
//             optionsBuilder.UseNpgsql(env.IsDevelopment() ? configuration.GetConnectionString("DB_CONN") : Environment.GetEnvironmentVariable("DB_CONN"));
//         }
//     }

//     protected override void OnModelCreating(ModelBuilder modelBuilder)
//     {
//         modelBuilder.Entity<PasswordmanagerAccount>(entity =>
//         {
//             entity.HasKey(e => new { e.Id, e.Userid }).HasName("passwordmanager_accounts_pkey");

//             entity.ToTable("passwordmanager_accounts");

//             entity.Property(e => e.Id)
//                 .HasMaxLength(256)
//                 .HasColumnName("id");
//             entity.Property(e => e.Userid)
//                 .HasMaxLength(256)
//                 .HasColumnName("userid");
//             entity.Property(e => e.CreatedAt)
//                 .HasMaxLength(256)
//                 .HasColumnName("created_at");
//             entity.Property(e => e.LastUpdatedAt)
//                 .HasMaxLength(256)
//                 .HasColumnName("last_updated_at");
//             entity.Property(e => e.Password)
//                 .HasMaxLength(256)
//                 .HasColumnName("password");
//             entity.Property(e => e.Title)
//                 .HasMaxLength(256)
//                 .HasColumnName("title");
//             entity.Property(e => e.Username)
//                 .HasMaxLength(256)
//                 .HasColumnName("username");
//         });

//         modelBuilder.Entity<PasswordmanagerUser>(entity =>
//         {
//             entity.HasKey(e => e.Id).HasName("passwordmanager_users_pkey");

//             entity.ToTable("passwordmanager_users");

//             entity.Property(e => e.Id)
//                 .HasMaxLength(256)
//                 .HasColumnName("id");
//             entity.Property(e => e.Accessfailedcount).HasColumnName("accessfailedcount");
//             entity.Property(e => e.Datecreated)
//                 .HasColumnType("timestamp without time zone")
//                 .HasColumnName("datecreated");
//             entity.Property(e => e.Datelastlogin)
//                 .HasColumnType("timestamp without time zone")
//                 .HasColumnName("datelastlogin");
//             entity.Property(e => e.Datelastlogout)
//                 .HasColumnType("timestamp without time zone")
//                 .HasColumnName("datelastlogout");
//             entity.Property(e => e.Dateretired)
//                 .HasColumnType("timestamp without time zone")
//                 .HasColumnName("dateretired");
//             entity.Property(e => e.Email)
//                 .HasMaxLength(256)
//                 .HasColumnName("email");
//             entity.Property(e => e.Emailconfirmed)
//                 .HasColumnType("bit(1)")
//                 .HasColumnName("emailconfirmed");
//             entity.Property(e => e.Firstname)
//                 .HasMaxLength(256)
//                 .HasColumnName("firstname");
//             entity.Property(e => e.Lastname)
//                 .HasMaxLength(256)
//                 .HasColumnName("lastname");
//             entity.Property(e => e.Lockoutenabled)
//                 .HasColumnType("bit(1)")
//                 .HasColumnName("lockoutenabled");
//             entity.Property(e => e.Lockoutenddateutc).HasColumnName("lockoutenddateutc");
//             entity.Property(e => e.Newemail).HasColumnName("newemail");
//             entity.Property(e => e.Passwordhash)
//                 .HasMaxLength(256)
//                 .HasColumnName("passwordhash");
//             entity.Property(e => e.Salt)
//                 .HasMaxLength(256)
//                 .HasColumnName("salt");
//         });

//         modelBuilder.Entity<Role>(entity =>
//         {
//             entity.HasKey(e => e.Id).HasName("roles_pkey");

//             entity.ToTable("roles");

//             entity.Property(e => e.Id)
//                 .HasMaxLength(256)
//                 .HasColumnName("id");
//             entity.Property(e => e.Name)
//                 .HasMaxLength(256)
//                 .HasColumnName("name");
//         });

//         modelBuilder.Entity<Userrole>(entity =>
//         {
//             entity.HasKey(e => e.Id).HasName("userroles_pkey");

//             entity.ToTable("userroles");

//             entity.Property(e => e.Id)
//                 .HasMaxLength(256)
//                 .HasColumnName("id");
//             entity.Property(e => e.Roleid)
//                 .HasMaxLength(256)
//                 .HasColumnName("roleid");
//             entity.Property(e => e.Userid)
//                 .HasMaxLength(256)
//                 .HasColumnName("userid");

//             entity.HasOne(d => d.Role).WithMany(p => p.Userroles)
//                 .HasForeignKey(d => d.Roleid)
//                 .OnDelete(DeleteBehavior.Cascade)
//                 .HasConstraintName("userroles_roleid_fkey");

//             entity.HasOne(d => d.User).WithMany(p => p.Userroles)
//                 .HasForeignKey(d => d.Userid)
//                 .OnDelete(DeleteBehavior.Cascade)
//                 .HasConstraintName("userroles_userid_fkey");
//         });

//         modelBuilder.Entity<Usertoken>(entity =>
//         {
//             entity.HasKey(e => e.Id).HasName("usertokens_pkey");

//             entity.ToTable("usertokens");

//             entity.Property(e => e.Id)
//                 .HasMaxLength(256)
//                 .HasColumnName("id");
//             entity.Property(e => e.Loginprovider)
//                 .HasMaxLength(256)
//                 .HasColumnName("loginprovider");
//             entity.Property(e => e.Providerkey)
//                 .HasMaxLength(256)
//                 .HasColumnName("providerkey");
//             entity.Property(e => e.Userid)
//                 .HasMaxLength(256)
//                 .HasColumnName("userid");

//             entity.HasOne(d => d.User).WithMany(p => p.Usertokens)
//                 .HasForeignKey(d => d.Userid)
//                 .OnDelete(DeleteBehavior.Cascade)
//                 .HasConstraintName("usertokens_userid_fkey");
//         });

//         OnModelCreatingPartial(modelBuilder);
//     }

//     partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
// }
