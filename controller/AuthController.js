const AWS = require('aws-sdk');
const { generateSecretHash } = require('../helper/generateSecretHash');
require('dotenv').config();

AWS.config.update({
	region: process.env.AWS_REGION,
	accessKeyId: process.env.AWS_ACCESS_KEY_ID,
	secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const cognito = new AWS.CognitoIdentityServiceProvider();

const SignUp = async (req, res) => {
	try {
		const {
			email,
			password,
		} = req.body;

		if (!email || !password) {
			return res.status(400).json({ message: 'Email and password are required.' });
		}

		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: email,
			Password: password,
			SecretHash: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
		};
		await cognito.signUp(params).promise();

		res.status(200).json({ message: 'Signup successful. Verification code sent to email.' });
	} catch (error) {
		console.error('Signup error:', error);
		if (error.code === 'UsernameExistsException') {
			return res.status(400).json({ message: 'User already exists.' });
		} else if (error.code === 'InvalidParameterException') {
			return res.status(400).json({ message: 'Invalid parameters. Check your inputs.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const ConfirmSignUp = async (req, res) => {
	const { email, code } = req.body;

	if (!email || !code) {
		return res.status(400).json({ message: 'Username and confirmation code are required.' });
	}

	const params = {
		ClientId: process.env.COGNITO_CLIENT_ID,
		Username: email,
		ConfirmationCode: code,
		SecretHash: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
	};

	try {
		await cognito.confirmSignUp(params).promise();
		res.status(200).json({ message: 'User successfully verified.' });
	} catch (error) {
		console.error('Verification error:', error);

		if (error.code === 'CodeMismatchException') {
			return res.status(400).json({ message: 'Invalid verification code.' });
		} else if (error.code === 'ExpiredCodeException') {
			return res.status(400).json({ message: 'Verification code expired. Please request a new one.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const ResendVerificationCode = async (req, res) => {
	const { email } = req.body;

	if (!email) {
		return res.status(400).json({ message: 'Email is required.' });
	}

	const params = {
		ClientId: process.env.COGNITO_CLIENT_ID,
		Username: email,
		SecretHash: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
	};

	try {
		await cognito.resendConfirmationCode(params).promise();
		res.status(200).json({ message: 'Verification code resent successfully.' });
	} catch (error) {
		console.error('Resend code error:', error);

		if (error.code === 'UserNotFoundException') {
			return res.status(404).json({ message: 'User not found.' });
		} else if (error.code === 'InvalidParameterException') {
			return res.status(400).json({ message: 'User is already confirmed.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const SignIn = async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(400).json({ message: 'Email and password are required.' });
	}

	try {

		const params = {
			AuthFlow: 'USER_PASSWORD_AUTH',
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				USERNAME: email,
				PASSWORD: password,
				SECRET_HASH: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
			},
		};

		const authResult = await cognito.initiateAuth(params).promise();
		res.status(200).json({
			message: 'Login successful.',
			idToken: authResult.AuthenticationResult.IdToken,
			accessToken: authResult.AuthenticationResult.AccessToken,
			refreshToken: authResult.AuthenticationResult.RefreshToken,
			expiresIn: authResult.AuthenticationResult.ExpiresIn,
			tokenType: authResult.AuthenticationResult.TokenType,
		});
	} catch (error) {
		console.error('SignIn error:', error);

		if (error.code === 'NotAuthorizedException') {
			return res.status(401).json({ message: 'Incorrect username or password.' });
		} else if (error.code === 'UserNotConfirmedException') {
			return res.status(403).json({ message: 'User not confirmed. Please verify your email.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const Logout = async (req, res) => {
	const accessToken = req.headers.authorization?.replace('Bearer ', '') || req.body.accessToken;

	if (!accessToken) {
		return res.status(400).json({ message: 'Access token is required for logout.' });
	}

	const params = {
		AccessToken: accessToken,
	};

	try {
		await cognito.globalSignOut(params).promise();
		res.status(200).json({ message: 'User logged out successfully.' });
	} catch (error) {
		console.error('Logout error:', error);

		if (error.code === 'NotAuthorizedException') {
			return res.status(401).json({ message: 'Invalid or expired access token.' });
		}
		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

module.exports = {
	SignUp,
	ConfirmSignUp,
	ResendVerificationCode,
	SignIn,
	Logout
};
