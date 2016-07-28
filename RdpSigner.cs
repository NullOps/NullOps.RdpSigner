using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace NullOps.RdpSigner
{
	/// <summary>
	/// The magical Rdp Signer utility.
	/// </summary>
	public class RdpSigner : IDisposable
	{
		/// <summary>
		/// Because Rdp expects windows new line formatting, we hardcode it.
		/// </summary>
		private const string WindowsNewLine = "\r\n";

		/// <summary>
		/// Digest Algorithm to request when CMS signing
		/// </summary>
		private const string RdpSignatureDigestAlgorithmName = "sha256";

		/// <summary>
		/// As it says on the box, two bytes with 0x0 value.
		/// These are used to pad the end of the byte data that is signed.
		/// The reason there is 2? Unicode!
		/// </summary>
		private static readonly byte[] TwoBlankBytes = { 0x0, 0x0 };

		/// <summary>
		/// The magical unknown rdp signature header.
		/// </summary>
		private static readonly byte[] SignatureHeader = { 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x00, 0x00 };

		/// <summary>
		/// The certificate to sign with
		/// </summary>
		private readonly X509Certificate2 m_signingCertificate;

		/// <summary>
		/// If we are already disposed
		/// </summary>
		private bool m_disposed = false;

		/// <summary>
		/// RdpSigner
		/// </summary>
		/// <param name="signingCertificate">The certificate you wish to use when signing</param>
		public RdpSigner(X509Certificate2 signingCertificate)
		{
			m_signingCertificate = signingCertificate;
		}

		/// <summary>
		/// Signs the provided rdp string
		/// </summary>
		/// <param name="rdpText">The string data inside an rdp file</param>
		/// <returns>The signed value within an rdp file</returns>
		public string Sign(string rdpText)
		{
			return Sign(rdpText, m_signingCertificate);
		}

		/// <summary>
		/// Signs the rdp file at the given location
		/// </summary>
		/// <param name="rdpFilePath">Path to the rdp file</param>
		public void SignFile(string rdpFilePath)
		{
			SignFile(rdpFilePath, m_signingCertificate);
		}

		/// <summary>
		/// Signs the rdp file at the given location, outputting the signed file to a now location
		/// </summary>
		/// <param name="sourceRdpFilePath">The path to the source rdp file to sign</param>
		/// <param name="outputRdpFilePath">The output path for the signed rdp file</param>
		public void SignFile(string sourceRdpFilePath, string outputRdpFilePath)
		{
			SignFile(sourceRdpFilePath, outputRdpFilePath, m_signingCertificate);
		}

		/// <summary>
		/// Signs the rdp file at the given location
		/// </summary>
		/// <param name="rdpFilePath">Path to the rdp file</param>
		/// <param name="signingCertificate">The certificate you wish to use when signing</param>
		public static void SignFile(string rdpFilePath, X509Certificate2 signingCertificate)
		{
			if (string.IsNullOrWhiteSpace(rdpFilePath))
			{
				throw new ArgumentException(nameof(rdpFilePath) + " must be a valid path.");
			}

			SignFile(rdpFilePath, rdpFilePath, signingCertificate);
		}

		/// <summary>
		/// Signs the rdp file at the given location, outputting the signed file to a now location
		/// </summary>
		/// <param name="sourceRdpFilePath">The path to the source rdp file to sign</param>
		/// <param name="outputRdpFilePath">The output path for the signed rdp file</param>
		/// <param name="signingCertificate">The certificate you wish to use when signing</param>
		public static void SignFile(string sourceRdpFilePath, string outputRdpFilePath, X509Certificate2 signingCertificate)
		{
			if (string.IsNullOrWhiteSpace(sourceRdpFilePath))
			{
				throw new ArgumentException(nameof(sourceRdpFilePath) + " must be a valid path.");
			}

			if (string.IsNullOrWhiteSpace(outputRdpFilePath))
			{
				throw new ArgumentException(nameof(outputRdpFilePath) + " must be a valid path.");
			}

			if (!File.Exists(sourceRdpFilePath))
			{
				throw new ArgumentException("File '" + sourceRdpFilePath + "' does not exist.");
			}

			string sourceText = File.ReadAllText(sourceRdpFilePath);

			string signedText = Sign(sourceText, signingCertificate);

			if (!string.IsNullOrWhiteSpace(signedText))
			{
				File.WriteAllText(outputRdpFilePath, signedText, Encoding.Unicode);
			}
		}

		/// <summary>
		/// Signs the provided rdp string
		/// </summary>
		/// <param name="rdpText">The string data inside an rdp file</param>
		/// <param name="signingCertificate">The certificate you wish to use when signing</param>
		/// <returns>The signed value within an rdp file</returns>
		public static string Sign(string rdpText, X509Certificate2 signingCertificate)
		{
			List<RdpSetting> settings = ParseSettings(rdpText);

			RemoveSignSettings(settings);

			EnsureAlternateFullAddressExists(settings);

			List<RdpSetting> settingsToSign = settings.Where(setting => setting.IsSignableSetting).ToList();

			RdpSetting signScopeSetting = BuildSignScopeSetting(settingsToSign);

			settings.Add(signScopeSetting);
			settingsToSign.Add(signScopeSetting);

			RdpSetting signatureSetting = BuildSignatureSetting(settingsToSign, signingCertificate);

			settings.Add(signatureSetting);

			string signedRdpFile = FlattenSettings(settings);

			return signedRdpFile;
		}

		/// <summary>
		/// Flattens a set of settings into their rdp file equivilent
		/// </summary>
		/// <param name="settings">The IEnumerable of settings to flatten</param>
		/// <returns>The provided settings as a string in rdp file format</returns>
		private static string FlattenSettings(List<RdpSetting> settings)
		{
			StringBuilder builder = new StringBuilder();

			foreach (RdpSetting setting in settings)
			{
				builder.Append(setting).Append(WindowsNewLine);
			}

			return builder.ToString();
		}

		/// <summary>
		/// Builds a signature setting for the provided settings
		/// </summary>
		/// <param name="settings">The settings to generate the signature for</param>
		/// <param name="signingCertificate">The certificate to use to sign it</param>
		/// <returns>The rdp signature setting</returns>
		private static RdpSetting BuildSignatureSetting(List<RdpSetting> settings, X509Certificate2 signingCertificate)
		{
			string textToSign = FlattenSettings(settings);

			byte[] bytesToSign = Encoding.Unicode.GetBytes(textToSign).Concat(TwoBlankBytes).ToArray();

			byte[] settingSignature = SignBytes(bytesToSign, signingCertificate);

			uint settingSignatureLength = Convert.ToUInt32(settingSignature.Length);

			byte[] settingSignatureLengthBytes = BitConverter.GetBytes(settingSignatureLength);

			byte[] signature = SignatureHeader.Concat(settingSignatureLengthBytes).Concat(settingSignature).ToArray();

			string base64Signature = Convert.ToBase64String(signature);

			// Add the silly little spaces every 64 characters that rdpsign.exe adds:
			base64Signature = Regex.Replace(base64Signature, ".{64}", "$0  ");

			return new RdpSetting(RdpSettingHelper.SignatureSettingName, RdpSettingHelper.SignatureSettingType, base64Signature);
		}

		/// <summary>
		/// Signs a payload, using CMS, with the provided certificate
		/// </summary>
		/// <param name="payload">The bytes to sign</param>
		/// <param name="signingCertificate">The certificate to sign with</param>
		/// <returns>The signature</returns>
		private static byte[] SignBytes(byte[] payload, X509Certificate2 signingCertificate)
		{
			CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signingCertificate)
			{
				IncludeOption = X509IncludeOption.WholeChain,
				DigestAlgorithm = Oid.FromFriendlyName(RdpSignatureDigestAlgorithmName, OidGroup.All)
			};

			ContentInfo content = new ContentInfo(payload);

			SignedCms cmsPayload = new SignedCms(content, true);

			cmsPayload.ComputeSignature(signer);

			return cmsPayload.Encode();
		}

		/// <summary>
		/// Builds the sign scope setting for the provided settings
		/// </summary>
		/// <param name="settings">The settings to scope for</param>
		/// <returns>The sign scope setting containing all scopes</returns>
		private static RdpSetting BuildSignScopeSetting(List<RdpSetting> settings)
		{
			StringBuilder scopeBuilder = new StringBuilder();

			foreach (RdpSetting setting in settings)
			{
				if (!RdpSettingHelper.SecureSettingScopes.ContainsKey(setting.SettingName))
				{
					throw new ArgumentException("Setting '" + setting.SettingName + "' has no known sign scope. (Are you sure it is signable?)");
				}

				scopeBuilder.Append(RdpSettingHelper.SecureSettingScopes[setting.SettingName]).Append(',');
			}

			if (scopeBuilder.Length <= 0)
			{
				return null;
			}

			// Remove final comma
			scopeBuilder.Length--;

			string settingValue = scopeBuilder.ToString();

			return new RdpSetting(RdpSettingHelper.SignScopeSettingName, RdpSettingHelper.SignScopeSettingType, settingValue);
		}

		/// <summary>
		/// Checks if an alternate full address is supplied, if not, then all it.
		/// This stops people from adding a full address after the signing is done
		/// </summary>
		/// <param name="settings">The collection of settings to check and add to</param>
		private static void EnsureAlternateFullAddressExists(List<RdpSetting> settings)
		{
			if (settings.Any(x => x.SettingName.Equals(RdpSettingHelper.AlternateFullAddressSettingName, StringComparison.OrdinalIgnoreCase)))
			{
				return;
			}

			RdpSetting fullAddressSetting = settings.FirstOrDefault(x =>
				x.SettingName.Equals(RdpSettingHelper.FullAddressSettingName, StringComparison.OrdinalIgnoreCase)
				);

			if (fullAddressSetting == null)
			{
				throw new Exception("Supplied Rdp settings do not contain a '" + RdpSettingHelper.FullAddressSettingName + "' setting");
			}

			settings.Add(new RdpSetting(RdpSettingHelper.AlternateFullAddressSettingName, fullAddressSetting.SettingType, fullAddressSetting.SettingValue));
		}

		/// <summary>
		/// Removes any existing signatures and sign scopes
		/// </summary>
		/// <param name="settings">The collection of settings to check</param>
		private static void RemoveSignSettings(List<RdpSetting> settings)
		{
			settings.RemoveAll(setting =>
				setting.SettingName.Equals(RdpSettingHelper.SignScopeSettingName, StringComparison.OrdinalIgnoreCase) ||
				setting.SettingName.Equals(RdpSettingHelper.SignatureSettingName, StringComparison.OrdinalIgnoreCase)
				);
		}

		/// <summary>
		/// Parses a string and converts each line into an rdp setting if it is valid
		/// </summary>
		/// <param name="data">The string to parse</param>
		/// <returns>A list of rdp settings</returns>
		private static List<RdpSetting> ParseSettings(string data)
		{
			List<RdpSetting> settings = new List<RdpSetting>();

			if (string.IsNullOrWhiteSpace(data))
			{
				return settings;
			}

			using (StringReader reader = new StringReader(data))
			{
				string line;
				while ((line = reader.ReadLine()) != null)
				{
					if (string.IsNullOrWhiteSpace(line))
					{
						continue;
					}

					RdpSetting parsedSetting;

					if (RdpSetting.TryParse(line, out parsedSetting))
					{
						settings.Add(parsedSetting);
					}
				}
			}

			return settings;
		}

		/// <summary>
		/// Disposes of this rdp signer.
		/// </summary>
		public void Dispose()
		{
			if (m_disposed)
			{
				return;
			}

			m_disposed = true;

			m_signingCertificate.Dispose();
		}
	}
}