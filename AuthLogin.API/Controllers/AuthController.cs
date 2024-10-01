using AuthLogin.API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity.Data;
using AuthLogin.API.Context;

namespace AuthLogin.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> _userManager; // UserManager, kullanıcı işlemlerini yönetmek için kullanılır.
		private readonly SignInManager<ApplicationUser> _signInManager; // SignInManager, kullanıcı oturum açma işlemlerini yönetir.
		private readonly ApplicationDbContext _applicationDbContext; // Veritabanı bağlamı.

		// Constructor, UserManager ve SignInManager bağımlılıklarını alır.
		public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
		{
			_userManager = userManager;
			_signInManager = signInManager;
		}

		// Kullanıcı kaydı için API uç noktası
		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] AuthLogin.API.Model.RegisterRequest model)
		{
			if (model == null) // Model null ise hata döndür
			{
				return BadRequest("Invalid registration request");
			}

			// Yeni kullanıcı oluştur
			var user = new ApplicationUser
			{
				Email = model.Email,
				UserName = model.UserName
			};

			// Kullanıcıyı veritabanında oluştur
			var result = await _userManager.CreateAsync(user, model.Password);
			if (result.Succeeded) // Başarılıysa onay döndür
			{
				return Ok(new { Message = "User registered successfully" });
			}

			// Hata varsa, hataları döndür
			return BadRequest(result.Errors);
		}

		// Kullanıcı girişi için API uç noktası
		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginRequest model)
		{
			if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password)) // E-posta ve şifre zorunlu
			{
				return BadRequest("Email and Password is required.");
			}

			var user = await _userManager.FindByEmailAsync(model.Email); // E-posta ile kullanıcıyı bul
			if (user == null) // Kullanıcı bulunamazsa yetkisiz döndür
			{
				return Unauthorized(new { message = "Kullanıcı adı ya da şifre yanlış" });
			}

			// Hesap kilitlenmiş mi kontrol et
			if (user.AccountLockoutEndTime.HasValue && user.AccountLockoutEndTime.Value > DateTime.UtcNow)
			{
				return BadRequest(new { message = "Hesabınız kilitli, lütfen daha sonra tekrar deneyin" });
			}

			// Şifre kontrolü
			var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
			if (!result.Succeeded) // Giriş başarısızsa
			{
				user.FailedLoginAttempts += 1; // Başarısız giriş sayısını artır

				// 3. başarısız girişten sonra hesabı kilitle
				if (user.FailedLoginAttempts >= 3)
				{
					user.AccountLockoutEndTime = DateTime.UtcNow.AddMinutes(15); // 15 dakika kilitle
					await _userManager.UpdateAsync(user);
					return BadRequest(new { message = "Hesabınız 15 dakika boyunca kilitlenmiştir" });
				}

				await _userManager.UpdateAsync(user); // Kullanıcıyı güncelle
				return Unauthorized(new { message = "Kullanıcı adı ya da şifre yanlış" });
			}

			user.FailedLoginAttempts = 0; // Başarılı girişte hatalı giriş sayısını sıfırla
			user.LastLoginTime = DateTime.UtcNow; // Son giriş zamanını güncelle
			await _userManager.UpdateAsync(user);

			// OTP oluştur ve gönder
			var otp = GenerateOtp(); // OTP oluştur
			await SendOtpEmail(user.Email, otp); // E-posta ile OTP gönder

			// İki faktörlü kimlik doğrulamasını etkinleştir
			user.IsTwoFactorEnabled = true;
			user.TwoFactorOtp = otp; // Kullanıcı nesnesinde OTP'yi sakla
			await _userManager.UpdateAsync(user);

			return Ok(new { Message = "OTP e-postanıza gönderildi", Email = user.Email });
		}

		// OTP doğrulama için API uç noktası
		[HttpPost("verify-otp")]
		public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest model)
		{
			var user = await _userManager.FindByEmailAsync(model.Email); // Kullanıcıyı bul
			if (user == null || !user.IsTwoFactorEnabled) // Kullanıcı yoksa veya 2FA etkin değilse
			{
				return Unauthorized(new { message = "Kullanıcı bulunamadı veya iki faktörlü kimlik doğrulaması etkin değil" });
			}

			// OTP'yi kontrol et
			if (model.Otp == user.TwoFactorOtp) // Geçerli OTP mi?
			{
				user.IsTwoFactorEnabled = false; // 2FA'yi devre dışı bırak
				await _userManager.UpdateAsync(user); // Kullanıcıyı güncelle

				var token = GenerateJwtToken(user); // JWT token oluştur
				return Ok(new { Token = token }); // Token'ı döndür
			}

			return Unauthorized(new { message = "Geçersiz OTP" }); // Geçersiz OTP ise yetkisiz döndür
		}

		// Rastgele 6 haneli OTP oluşturur
		private string GenerateOtp()
		{
			Random random = new Random();
			return random.Next(100000, 999999).ToString(); // 6 haneli rastgele OTP
		}

		// E-posta ile OTP gönderme işlemi
		private async Task SendOtpEmail(string email, string otp)
		{
			// E-posta gönderme işlemi
			var fromAddress = new MailAddress("your-email@example.com", "Your Name"); // Gönderen e-posta adresi
			var toAddress = new MailAddress(email); // Alıcı e-posta adresi
			const string fromPassword = "your-email-password"; // E-posta şifreniz
			const string subject = "Your OTP Code"; // E-posta konusu
			string body = $"Your OTP code is: {otp}"; // E-posta içeriği

			var smtp = new SmtpClient
			{
				Host = "smtp.example.com", // SMTP sunucunuz
				Port = 587, // SMTP port numarası
				EnableSsl = true,
				DeliveryMethod = SmtpDeliveryMethod.Network,
				UseDefaultCredentials = false,
				Credentials = new NetworkCredential(fromAddress.Address, fromPassword) // SMTP kimlik bilgileri
			};

			// E-posta mesajını oluştur ve gönder
			using (var message = new MailMessage(fromAddress, toAddress)
			{
				Subject = subject,
				Body = body
			})
			{
				await smtp.SendMailAsync(message); // E-postayı asenkron olarak gönder
			}
		}

		// JWT token oluşturur
		private string GenerateJwtToken(ApplicationUser user)
		{
			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.Email), // Kullanıcı e-postası
                new Claim(JwtRegisteredClaimNames.Jti, user.Id), // Kullanıcı ID'si
            };

			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YOUR_SECRET_KEY")); // Güvenlik anahtarı
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // İmzalama bilgileri

			// Token oluşturma
			var token = new JwtSecurityToken(
				issuer: "YOUR_ISSUER", // Token oluşturucu
				audience: "YOUR_AUDIENCE", // Token hedefi
				claims: claims, // İddialar
				expires: DateTime.Now.AddMinutes(60), // Geçerlilik süresi
				signingCredentials: creds); // İmzalama bilgileri

			return new JwtSecurityTokenHandler().WriteToken(token); // Token'ı döndür
		}
	}

	// Giriş isteği modeli
	public class LoginRequest
	{
		public string Email { get; set; } // Kullanıcı e-posta adresi
		public string Password { get; set; } // Kullanıcı şifresi
	}

	// OTP doğrulama isteği modeli
	public class VerifyOtpRequest
	{
		public string Email { get; set; } // Kullanıcı e-posta adresi
		public string Otp { get; set; } // Doğrulama için OTP
	}
}
