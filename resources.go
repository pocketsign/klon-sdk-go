package klon

// 署名用電子証明書リソース
const (
	ResourceSigningFirstName      = "klon/signing_first_name"
	ResourceSigningLastName       = "klon/signing_last_name"
	ResourceSigningMaidenName     = "klon/signing_maiden_name"
	ResourceSigningFullName       = "klon/signing_full_name"
	ResourceSigningPopularName    = "klon/signing_popular_name"
	ResourceSigningGender         = "klon/signing_gender"
	ResourceSigningPrefAddress    = "klon/signing_prefecture_address"
	ResourceSigningCityAddress    = "klon/signing_city_address"
	ResourceSigningFullAddress    = "klon/signing_full_address"
	ResourceSigningMovingAbroad   = "klon/signing_moving_abroad_date"
	ResourceSigningBirthYear      = "klon/signing_birth_year"
	ResourceSigningBirthDay       = "klon/signing_birth_day"
	ResourceSigningBirthDate      = "klon/signing_birth_date"
	ResourceSigningFirstNameRuby  = "klon/signing_first_name_ruby"
	ResourceSigningLastNameRuby   = "klon/signing_last_name_ruby"
	ResourceSigningMaidenNameRuby = "klon/signing_maiden_name_ruby"
	ResourceSigningFullNameRuby   = "klon/signing_full_name_ruby"
)

// 券面事項入力補助APリソース
const (
	ResourceTicketFirstName      = "klon/ticket_first_name"
	ResourceTicketLastName       = "klon/ticket_last_name"
	ResourceTicketMaidenName     = "klon/ticket_maiden_name"
	ResourceTicketFullName       = "klon/ticket_full_name"
	ResourceTicketPopularName    = "klon/ticket_popular_name"
	ResourceTicketGender         = "klon/ticket_gender"
	ResourceTicketPrefAddress    = "klon/ticket_prefecture_address"
	ResourceTicketCityAddress    = "klon/ticket_city_address"
	ResourceTicketFullAddress    = "klon/ticket_full_address"
	ResourceTicketMovingAbroad   = "klon/ticket_moving_abroad_date"
	ResourceTicketBirthYear      = "klon/ticket_birth_year"
	ResourceTicketBirthDay       = "klon/ticket_birth_day"
	ResourceTicketBirthDate      = "klon/ticket_birth_date"
	ResourceTicketFirstNameRuby  = "klon/ticket_first_name_ruby"
	ResourceTicketLastNameRuby   = "klon/ticket_last_name_ruby"
	ResourceTicketMaidenNameRuby = "klon/ticket_maiden_name_ruby"
	ResourceTicketFullNameRuby   = "klon/ticket_full_name_ruby"
)

// 手入力リソース
const (
	ResourceManualFirstName      = "klon/manual_first_name"
	ResourceManualLastName       = "klon/manual_last_name"
	ResourceManualMaidenName     = "klon/manual_maiden_name"
	ResourceManualFullName       = "klon/manual_full_name"
	ResourceManualPopularName    = "klon/manual_popular_name"
	ResourceManualGender         = "klon/manual_gender"
	ResourceManualPrefAddress    = "klon/manual_prefecture_address"
	ResourceManualCityAddress    = "klon/manual_city_address"
	ResourceManualFullAddress    = "klon/manual_full_address"
	ResourceManualMovingAbroad   = "klon/manual_moving_abroad_date"
	ResourceManualBirthYear      = "klon/manual_birth_year"
	ResourceManualBirthDay       = "klon/manual_birth_day"
	ResourceManualBirthDate      = "klon/manual_birth_date"
	ResourceManualFirstNameRuby  = "klon/manual_first_name_ruby"
	ResourceManualLastNameRuby   = "klon/manual_last_name_ruby"
	ResourceManualMaidenNameRuby = "klon/manual_maiden_name_ruby"
	ResourceManualFullNameRuby   = "klon/manual_full_name_ruby"
)

// マージ済み (最高信頼度) リソース
const (
	ResourceMergedFirstName      = "klon/merged_first_name"
	ResourceMergedLastName       = "klon/merged_last_name"
	ResourceMergedMaidenName     = "klon/merged_maiden_name"
	ResourceMergedFullName       = "klon/merged_full_name"
	ResourceMergedPopularName    = "klon/merged_popular_name"
	ResourceMergedGender         = "klon/merged_gender"
	ResourceMergedPrefAddress    = "klon/merged_prefecture_address"
	ResourceMergedCityAddress    = "klon/merged_city_address"
	ResourceMergedFullAddress    = "klon/merged_full_address"
	ResourceMergedMovingAbroad   = "klon/merged_moving_abroad_date"
	ResourceMergedBirthYear      = "klon/merged_birth_year"
	ResourceMergedBirthDay       = "klon/merged_birth_day"
	ResourceMergedBirthDate      = "klon/merged_birth_date"
	ResourceMergedFirstNameRuby  = "klon/merged_first_name_ruby"
	ResourceMergedLastNameRuby   = "klon/merged_last_name_ruby"
	ResourceMergedMaidenNameRuby = "klon/merged_maiden_name_ruby"
	ResourceMergedFullNameRuby   = "klon/merged_full_name_ruby"
)

// 連絡先リソース
const (
	ResourceEmailAddress = "klon/email_address"
	ResourcePhoneNumber  = "klon/phone_number"
)

// 顔写真リソース
const (
	ResourceFaceImage = "klon/face_image"
)

// 実行リソース (端末機能の利用やプッシュ通知送信などの権限)
const (
	ResourcePushNotification               = "klon/push_notification"
	ResourceAccessCamera                   = "klon/access_camera"
	ResourceGetCurrentPosition             = "klon/get_current_position"
	ResourceGetHighAccuracyCurrentPosition = "klon/get_high_accuracy_current_position"
	ResourceAccessFitnessData              = "klon/access_fitness_data"
)

// 証明書現況確認リソース
const (
	ResourceCheckJPKICardDigitalSignatureCertificateRevocation     = "klon/check_jpki_card_digital_signature_certificate_revocation"
	ResourceCheckJPKICardUserAuthenticationCertificateRevocation   = "klon/check_jpki_card_user_authentication_certificate_revocation"
	ResourceCheckJPKIMobileDigitalSignatureCertificateRevocation   = "klon/check_jpki_mobile_digital_signature_certificate_revocation"
	ResourceCheckJPKIMobileUserAuthenticationCertificateRevocation = "klon/check_jpki_mobile_user_authentication_certificate_revocation"
)
