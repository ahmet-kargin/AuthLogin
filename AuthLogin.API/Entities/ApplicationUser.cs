using Microsoft.AspNetCore.Identity;

namespace AuthLogin.API.Entities;

public class ApplicationUser : IdentityUser
{
	public DateTime? LastLoginTime { get; set; }
	public int FailedLoginAttempts { get; set; }
	public DateTime? AccountLockoutEndTime { get; set; }
	public bool IsTwoFactorEnabled { get; set; }

	public string TwoFactorOtp { get; set; } // OTP'yi saklamak için
}
