const AWS = require('aws-sdk');
const { generateSecretHash } = require('../helper/generateSecretHash');
const { S3Client } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const { GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuidv4 } = require('uuid');
const { default: axios } = require('axios');
const Joi = require("joi");
const jwt = require("jsonwebtoken");
require('dotenv').config();

AWS.config.update({
	region: process.env.AWS_REGION,
	accessKeyId: process.env.AWS_ACCESS_KEY_ID,
	secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const s3Client = new S3Client({
	region: process.env.AWS_REGION,
	credentials: {
		accessKeyId: process.env.AWS_ACCESS_KEY_ID,
		secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
	},
});


const cognito = new AWS.CognitoIdentityServiceProvider();

const userSchema = Joi.object({
	email:Joi.string().email().required(),
	password:Joi.string().required(),
	firstname:Joi.string().required(),
	lastname:Joi.string().required(),
	gender: Joi.string().valid("male", "female", "other"),
	country: Joi.string(),
	city: Joi.string(),
	user_type: Joi.string(),
	school: Joi.string(),
	mode: Joi.string().required(),
	district: Joi.string(),
	age: Joi.number().integer().min(0),
	source: Joi.string().required(),
  });

const RefershToken = Joi.object({
	refreshToken:Joi.string().required()
}) 

const SignUp = async (req, res) => {
	try {
		const { error, value } = userSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
	const toAttr = (name, val) => ({
		Name: name,
		Value: val !== undefined && val !== null && val !== '' ? val : 'N/A'
	});
	
	const attributes = [
		toAttr('gender', value.gender),
		toAttr('given_name', value.firstname),
		toAttr('family_name', value.lastname),
		toAttr('custom:country', value.country),
		toAttr('custom:city', value.city),
		toAttr('custom:school', value.school),
		toAttr('custom:mode', value.mode),
		toAttr('custom:district', value.district),
		toAttr('custom:age', value.age),
		toAttr('custom:source', value.source),
		toAttr('custom:user_type', value.user_type)
	];
	

	console.log('Attributes:', attributes);

		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: value.email,
			Password: value.password,
			SecretHash: generateSecretHash(value.email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
			UserAttributes:attributes
		};
		const { UserSub } = await cognito.signUp(params).promise();
		const rawPayload = {
			user_id:UserSub,
			sex:value.gender,
			country:value.country,
			city:value.city,
			user_type:value.user_type,
			school:value.school,
			mode:value.mode,
			district:value.district,
			age:value.age,
			source:value.source
		}

		const payload = Object.fromEntries(
			Object.entries(rawPayload).filter(([_, v]) => v !== undefined && v !== null && v !== '')
		  );
		try {
			const newUser = await axios.post(`${process.env.MENTAL_HEALTH_LIVE_URL}/user/createuser`,payload);
		} catch (error) {
			console.log("Error to create user in mental health:",error)
		}

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
	const { email, code, password } = req.body;

	if (!email || !code || !password) {
		return res.status(400).json({ message: 'Username ,Password and confirmation code are required.' });
	}

	const params = {
		ClientId: process.env.COGNITO_CLIENT_ID,
		Username: email,
		ConfirmationCode: code,
		SecretHash: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
	};

	try {
		await cognito.confirmSignUp(params).promise();
	} catch (error) {
		console.error('Verification error:', error);

		if (error.code === 'CodeMismatchException') {
			return res.status(400).json({ message: 'Invalid verification code.' });
		} else if (error.code === 'ExpiredCodeException') {
			return res.status(400).json({ message: 'Verification code expired. Please request a new one.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}

	try {
		const param = {
			AuthFlow: 'USER_PASSWORD_AUTH',
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				USERNAME: email,
				PASSWORD: password,
				SECRET_HASH: generateSecretHash(email, process.env.COGNITO_CLIENT_ID, process.env.COGNITO_CLIENT_SECRET),
			},
		};
	
		const authResult = await cognito.initiateAuth(param).promise();
		const user = await cognito.getUser({ AccessToken: authResult.AuthenticationResult.AccessToken }).promise();
		const token = jwt.sign({userId: user?.Username},process.env.JWT_SECRET_KEY,{expiresIn:'1h'});
		res.status(200).json({
			message: 'User verified and login successful.',
			data: {
				idToken: authResult.AuthenticationResult.IdToken,
				accessToken: authResult.AuthenticationResult.AccessToken,
				refreshToken: authResult.AuthenticationResult.RefreshToken,
				expiresIn: authResult.AuthenticationResult.ExpiresIn,
				tokenType: authResult.AuthenticationResult.TokenType,
				jwtToken: token
			}
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
		const user = await cognito.getUser({ AccessToken: authResult.AuthenticationResult.AccessToken }).promise();
		const token = jwt.sign({userId: user?.Username},process.env.JWT_SECRET_KEY,{expiresIn:'1h'});
		

		res.status(200).json({
			message: 'Login successful.',
			data: {
				idToken: authResult.AuthenticationResult.IdToken,
				accessToken: authResult.AuthenticationResult.AccessToken,
				refreshToken: authResult.AuthenticationResult.RefreshToken,
				expiresIn: authResult.AuthenticationResult.ExpiresIn,
				tokenType: authResult.AuthenticationResult.TokenType,
				jwtToken: token
			}
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

const UpdateUser = async (req, res) => {
	try {
		const accessToken = req.headers['authorization']?.split(' ')[1];
		if (!accessToken) {
			return res.status(400).json({ message: 'Access token is required.' });
		}
	    const {
			gender,
			country,
			city,
			user_type,
			school,
			mode,
			district,
			age,
			source
		} = req.body;

		const profileImage = req.file;
		const attributes = [];

		if (profileImage) {
			const key = `${uuidv4()}-${profileImage.originalname}`;


			const upload = new Upload({
				client: s3Client,
				params: {
					Bucket: process.env.AWS_BUCKET_NAME,
					Key: key,
					Body: profileImage.buffer,
					ContentType: profileImage.mimetype,
				},
			});
			const uploadResult = await upload.done();
			attributes.push({ Name: 'profile', Value: key })
		}

		if (gender) attributes.push({ Name: 'gender', Value: gender });

		// Custom fields
		if (country) attributes.push({ Name: 'custom:country', Value: country });
		if (city) attributes.push({ Name: 'custom:city', Value: city });
		if (school) attributes.push({ Name: 'custom:school', Value: school });
		if (mode) attributes.push({ Name: 'custom:mode', Value: mode });
		if (district) attributes.push({ Name: 'custom:district', Value: district });
		if (age) attributes.push({ Name: 'custom:age', Value: age });
		if (source) attributes.push({ Name: 'custom:source', Value: source });
		if(user_type) attributes.push({Name:'custom:user_type', Value:user_type})

		const params = {
			AccessToken: accessToken,
			UserAttributes: attributes
		};

		 await cognito.updateUserAttributes(params).promise();

		 const { Username } = await cognito.getUser({ AccessToken: accessToken }).promise();
		 const payload = {
			sex:gender,
			country:country,
			city:city,
			user_type:user_type,
			school:school,
			mode:mode,
			district:district,
			age:age,
			source:source
		 }
		 const token = jwt.sign({userId:Username},process.env.JWT_SECRET_KEY,{expiresIn:'1h'});

		 try {
			const UpdateUser = await axios.post(`${process.env.MENTAL_HEALTH_LIVE_URL}/user/editUser/${Username}`,payload,{
				headers:{
					Authorization: `Bearer ${token}`
				}
			});
		} catch (error) {
			console.log("Error to create user in mental health:",error)
		}

		res.status(200).json({ message: 'User attributes updated successfully.' });
	} catch (error) {
		console.error('Update user error:', error);
		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};


const GetUser = async (req, res) => {
	try {
		const accessToken = req.headers['authorization']?.split(' ')[1];

		if (!accessToken) {
			return res.status(400).json({ message: 'Access token is required.' });
		}

		const user = await cognito.getUser({ AccessToken: accessToken }).promise();

		const attributes = {};
		user.UserAttributes.forEach(attr => {
			attributes[attr.Name] = attr.Value;
		});

		let profileUrl = null;
		if (attributes['profile']) {
			const key = attributes['profile'];

			try {
				const command = new GetObjectCommand({
					Bucket: process.env.AWS_BUCKET_NAME,
					Key: key,
				});

				profileUrl = await getSignedUrl(s3Client, command, {
					expiresIn: 60 * 60 * 24,
				});
			} catch (s3Error) {
				console.error('Error generating signed URL:', s3Error);
				profileUrl = null;
			}
		}

		const cleanedAttributes = {
			firstname: attributes['given_name'],
			lastname: attributes['family_name'],
			email: attributes['email'],
			email_verified: attributes['email_verified'],
			gender: attributes['gender'],
			sub: attributes['sub'],
		};

		Object.keys(attributes).forEach(key => {
			if (key.startsWith('custom:')) {
				const newKey = key.replace('custom:', '');
				cleanedAttributes[newKey] = attributes[key];
			}
		});

		// Normalize values: replace "N/A", null, or undefined with empty string
		const normalizedData = {};
		for (const [key, value] of Object.entries(cleanedAttributes)) {
			normalizedData[key] = value === 'N/A' || value === undefined || value === null ? '' : value;
		}

		console.log('Normalized User fetched:', normalizedData);

		res.status(200).json({
			message: "User fetched successfully",
			data: {
				...normalizedData,
				profileUrl: profileUrl ?? ''
			}
		});
	} catch (error) {
		console.error('Get user error:', error);

		if (error.code === 'NotAuthorizedException') {
			return res.status(401).json({ message: 'Invalid or expired access token.' });
		}

		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const RefreshToken = async (req, res) => {

	if (!req.body || Object.keys(req.body).length === 0) {
		return res.status(400).json({ message: "Request body is missing" });
	  }

	const { error, value } = RefershToken.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

	try {
		const params = {
			AuthFlow: 'REFRESH_TOKEN_AUTH',
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				REFRESH_TOKEN: value.refreshToken,
				SECRET_HASH: process.env.COGNITO_CLIENT_SECRET,
			},
		};

		const authResult = await cognito.initiateAuth(params).promise();
		const user = await cognito.getUser({ AccessToken: authResult.AuthenticationResult.AccessToken }).promise();
		const token = jwt.sign({userId: user?.Username},process.env.JWT_SECRET_KEY,{expiresIn:'1h'});

		res.status(200).json({
			message: 'Token refresh successful.',
			data: {
				idToken: authResult.AuthenticationResult.IdToken,
				accessToken: authResult.AuthenticationResult.AccessToken,
				refreshToken: authResult.AuthenticationResult.RefreshToken,
				expiresIn: authResult.AuthenticationResult.ExpiresIn,
				tokenType: authResult.AuthenticationResult.TokenType,
				jwtToken: token
			}
		});

	} catch (error) {
		console.error('RefreshToken error:', error);

		if (error.code === 'NotAuthorizedException') {
			return res.status(401).json({ message: 'Invalid refresh token or token has expired.' });
		} else if (error.code === 'UserNotFoundException') {
			return res.status(404).json({ message: 'User not found.' });
		} else if (error.code === 'TokenRefreshException') {
			return res.status(401).json({ message: 'Token refresh failed. Please login again.' });
		}
		res.status(500).json({ error: error.message || 'Internal server error' });
	}
};

const googleCallback = async (req, res) => {
	const { code } = req.query;
  
	if (!code) {
	  return res.status(400).json({ message: 'Authorization code is missing' });
	}
  
	try {
	  const params = new URLSearchParams();
	  params.append('grant_type', 'authorization_code');
	  params.append('client_id', process.env.COGNITO_CLIENT_ID);
	  params.append('client_secret', process.env.COGNITO_CLIENT_SECRET);
	  params.append('code', code);
	  params.append('redirect_uri', process.env.COGNITO_REDIRECT_URI);
  
	  const tokenResponse = await axios.post(
		`${process.env.COGNITO_DOMAIN}/oauth2/token`,
		params.toString(),
		{
		  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		}
	  );
  
	  const { id_token, access_token, refresh_token } = tokenResponse.data;
  
	  const decoded = jwt.decode(id_token);
  
	  res.status(200).json({
		message: 'Google Sign-In successful',
		tokens: { id_token, access_token, refresh_token },
		user: decoded,
	  });
	} catch (err) {
	  console.error('Google callback error:', err?.response?.data || err.message);
	  res.status(500).json({ message: 'Failed to sign in with Google' });
	}
  };

module.exports = {
	SignUp,
	ConfirmSignUp,
	ResendVerificationCode,
	SignIn,
	Logout,
	UpdateUser,
	GetUser,
	RefreshToken,
	googleCallback
};
