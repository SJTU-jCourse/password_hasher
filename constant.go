package password_hasher

type HashAlgorithmType = string

const (
	HashAlgorithmPBK2DF HashAlgorithmType = "pbkdf2_sha256"
)

const PasswordHashIteration = 720000
