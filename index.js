const express = require('express');
const multer = require('multer');
const OpenAI = require('openai');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const { unlink } = require('fs').promises; // New: for deleting files asynchronously
const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
const Stripe = require('stripe'); // New: Import Stripe library
require('dotenv').config();
const connectDB = require('./db'); // New: Import database connection
const bcrypt = require('bcrypt'); // New: Import bcrypt
const jwt = require('jsonwebtoken'); // New: Import jsonwebtoken
const session = require('express-session'); // New: Import express-session
const User = require('./models/User'); // New: Import User model
const validator = require('validator');
const nodemailer = require('nodemailer');

// Nodemailer transporter setup (using environment variables)
const transporter = nodemailer.createTransport({
  service: 'gmail', // e.g., 'gmail'
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // For Gmail, this should be an "App Password"
  },
});

const app = express();
const port = 3000;

// Initialize Stripe
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Initialize OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Middleware
app.use(cors());
app.use(express.json());

// New: Configure express-session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey', // Use a strong secret from .env
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Static file serving
app.use(express.static('.'));

// Explicit routes for main HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/success.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'success.html'));
});

// PDF processing function
async function extractContentFromPDF(pdfPath) {
  try {
    const data = new Uint8Array(fs.readFileSync(pdfPath));
    const pdf = await pdfjsLib.getDocument({ data }).promise;
    
    let content = '';
    const links = [];

    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
      const page = await pdf.getPage(pageNum);
      
      // Extract text content
      const textContent = await page.getTextContent();
      const pageText = textContent.items.map(item => item.str).join(' ');
      content += `Page ${pageNum}: ${pageText}\n\n`;
      
      // Extract links
      const annotations = await page.getAnnotations();
      for (const annotation of annotations) {
        if (annotation.subtype === 'Link' && annotation.url) {
          links.push(annotation.url);
        } else if (annotation.subtype === 'Link' && annotation.a?.URI) {
          links.push(annotation.a.URI);
        }
      }
    }

    return {
      text: content,
      links: links
    };
  } catch (error) {
    console.error('Error processing PDF:', error);
    return { text: '', links: [] };
  }
}

// Connect to MongoDB and then start the server
connectDB().then((db) => {
  const analysisCollection = db.collection('analysis_metadata'); // New: Collection for analysis results metadata

  // *** New: User Authentication Routes ***

  // POST /signup
  app.post('/signup', async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // 1. Validate Email Format
      if (!validator.isEmail(email)) {
        return res.status(400).send('Please enter a valid email address.');
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).send('User with that email already exists.');
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const user = new User({ email, passwordHash });
      await user.save();

      // 2. Send Welcome Email
      const mailOptions = {
        from: `"Scan This Scam" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Welcome to Scan This Scam!',
        html: `<h1>Welcome, ${user.email}!</h1><p>Thank you for signing up. We're excited to have you on board.</p><p>You can now start analyzing content for potential scams.</p>`,
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending welcome email:', error);
          // We don't block the signup if email fails, just log it
        } else {
          console.log('Welcome email sent:', info.response);
        }
      });

      // Automatically log in the user by generating a JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(201).json({ token, userId: user._id, email: user.email, isSubscribed: user.isSubscribed });
    } catch (error) {
      console.error('Error during signup:', error);
      res.status(500).json({ error: 'Failed to create user' });
    }
  });

  // POST /login
  app.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      const isValid = user && await bcrypt.compare(password, user.passwordHash);

      if (!isValid) return res.status(401).send('Invalid credentials');
      
      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour
      res.json({ token, userId: user._id, email: user.email, isSubscribed: user.isSubscribed });

    } catch (error) {
      console.error('Error during login:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  // New: Middleware to protect routes
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); // Invalid token
      req.user = user; // Attach user payload to request
      next();
    });
  };

  // Routes (Existing ones will be moved inside this block)
  // API endpoint for scam detection
  app.post('/api/analyze', authenticateToken, upload.any(), async (req, res) => {
    try { // Outer try block starts here
      const { text } = req.body; // text will still be in req.body for plain text inputs
      const files = req.files; // files will be an array of uploaded files
      
      let contentForAI = []; // Changed to an array for multi-modal content
      let textContentForAI = ''; // To accumulate text from various sources

      // Add initial instruction for the AI, especially if files are expected
      if (files && files.length > 0) {
        textContentForAI += "Please carefully analyze ALL provided content, including the visual content of any provided images, text from files (like PDFs), and direct text input, for any signs of scams, fraud, or malicious activity.\n\n";
      }

      // Process text inputs from req.body
      if (text) {
        textContentForAI += `Text content from input field: ${text}\n\n`;
      }

      // Process files from req.files
      if (files && files.length > 0) {
        for (const file of files) {
          let fileInfo = `File uploaded: ${file.originalname} (Type: ${file.mimetype})\n`;
          textContentForAI += fileInfo;

          if (file.mimetype === 'application/pdf') {
            console.log('Processing PDF file:', file.originalname);
            const pdfResult = await extractContentFromPDF(file.path);
            const pdfContent = pdfResult.text;
            const pdfLinks = pdfResult.links;
            
            textContentForAI += `PDF Content:\n${pdfContent}\n\n`;
            
            if (pdfLinks.length > 0) {
              textContentForAI += `PDF Links found:\n${pdfLinks.join('\n')}\n\n`;
            }
            console.log('PDF processing complete. Links found:', pdfLinks.length);
            await unlink(file.path); // Delete file after processing

          } else if (file.mimetype.startsWith('image/')) {
            console.log('Processing image file:', file.originalname);
            const imageBuffer = fs.readFileSync(file.path);
            const base64Image = imageBuffer.toString('base64');
            
            contentForAI.push({
              type: 'image_url',
              image_url: {
                url: `data:${file.mimetype};base64,${base64Image}`,
                detail: "high" // New: Specify high detail for image analysis
              },
            });
            textContentForAI += `Image content (Base64 encoded): [Image ${file.originalname}]\n\n`;
            await unlink(file.path); // Delete file after processing

          } else if (file.mimetype.startsWith('audio/')) {
            console.log('Processing audio file:', file.originalname);
            try {
              const transcription = await openai.audio.transcriptions.create({
                file: fs.createReadStream(file.path),
                model: "whisper-1",
              });
              textContentForAI += `Audio transcript:\n"${transcription.text}"\n\n`;
            } catch (transcriptionError) {
              console.error('Error during audio transcription:', transcriptionError);
              textContentForAI += `[Error transcribing audio file ${file.originalname}]\n\n`;
            } finally {
              await unlink(file.path); // Delete file after processing
            }

          } else {
            // For other file types, you might want to read their content (e.g., audio, docx, txt)
            // For now, we'll just include their info and delete them.
            console.log(`File type ${file.mimetype} for ${file.originalname} is not fully processed yet.`);
            // If it's a text-based file, you could read its content here.
            // For now, we'll just delete the file.
            await unlink(file.path); // Delete file after processing
          }
        }
      }
      
      if (!textContentForAI.trim() && contentForAI.length === 0) {
        return res.status(400).json({ error: 'No content provided for analysis' });
      }

      // Add accumulated text content as a text part to the AI content array
      if (textContentForAI.trim()) {
        contentForAI.push({
          type: 'text',
          text: `Consolidated analysis context:\n${textContentForAI.trim()}`,
        });
      }

      const systemPrompt = "You are a cybersecurity expert specializing in scam detection and fraud prevention. Analyze content for potential threats and provide actionable advice. Provide a comprehensive analysis including: 1. Risk Assessment (0-100 score) 2. Red Flags Identified 3. Potential Threats 4. Recommended Actions (delete, report, block, etc.) 5. Safety Tips. Please format your response as JSON with the following structure: { \"riskScore\": number, \"redFlags\": [array of strings], \"threats\": [array of strings], \"recommendations\": [array of strings], \"safetyTips\": [array of strings], \"summary\": \"brief summary\"}";

      console.log('Sending request to ChatGPT with content length:', JSON.stringify(contentForAI).length);
      console.log('Content for AI (full):', JSON.stringify(contentForAI, null, 2)); // Log full content

      const completion = await openai.chat.completions.create({
        model: "gpt-4o", // Updated model to gpt-4o for vision capabilities
        messages: [
          {
            role: "system",
            content: systemPrompt
          },
          {
            role: "user",
            content: contentForAI // Pass the array of content parts
          }
        ],
        temperature: 0.3,
        max_tokens: 1000, // Important for vision models
      });

      const response = completion.choices[0].message.content;
      
      // Console log the raw ChatGPT response
      console.log('=== RAW CHATGPT RESPONSE ===');
      console.log(response);
      console.log('=== END RAW RESPONSE ===');
      
      // New: Clean the response by removing markdown code block fences if present
      let cleanResponse = response.replace(/^```json\n|\n```$/g, '').trim();

      // Console log the cleaned response before parsing
      console.log('=== CLEANED CHATGPT RESPONSE FOR PARSING ===');
      console.log(cleanResponse);
      console.log('=== END CLEANED RESPONSE ===');

      // Try to parse as JSON, if it fails, return as text
      try {
        const jsonResponse = JSON.parse(cleanResponse);
        console.log('Successfully parsed JSON response');
        
        // Store results in MongoDB
        const analysisId = Date.now().toString(); // Simple unique ID
        
        let submissionType = 'text'; // Default to text
        if (files && files.length > 0) {
            const file = files[0];
            if (file.mimetype.startsWith('image/')) {
                submissionType = 'image';
            } else if (file.mimetype === 'application/pdf') {
                submissionType = 'pdf';
            } else if (file.mimetype.startsWith('audio/')) {
                submissionType = 'audio';
            } else {
                submissionType = 'file'; // Generic file
            }
        }

        await analysisCollection.insertOne({
          _id: analysisId,
          userId: req.user.userId,
          submissionType: submissionType, // New: Store submission type
          result: jsonResponse,
          createdAt: new Date()
        });

        res.json({ analysisId: analysisId }); // Return only the ID

      } catch (e) {
        console.log('Failed to parse JSON, returning fallback response');
        res.status(500).json({
          error: 'AI response parsing failed',
          details: response
        });
    } 
  } catch (error) { // Outer catch block for general errors
    console.error('Error during analysis request:', error);
    res.status(500).json({ 
      error: 'Analysis failed',
      details: error.message 
    });
  } finally {
    // No need to save to file here anymore as data is in MongoDB
  }
  });
  
  // New: Endpoint to retrieve analysis results (only if paid)
  app.get('/api/results/:analysisId', authenticateToken, async (req, res) => {
    const { analysisId } = req.params;
    try {
      // Ensure only the authenticated user can retrieve their own analysis
      const analysisDoc = await analysisCollection.findOne({ _id: analysisId, userId: req.user.userId }); // New: Include userId in query
      if (analysisDoc) {
        const user = await User.findById(req.user.userId);
        const isSubscribed = user && user.isSubscribed && user.subscriptionEndDate && user.subscriptionEndDate > new Date();
        
        if (isSubscribed) {
          res.json(analysisDoc.result); // Return the actual result
        } else {
          res.status(403).json({ error: 'A valid subscription is required to view results.' });
        }
      } else {
        res.status(404).json({ error: 'Analysis results not found or not owned by user.' }); // More specific error
      }
    } catch (error) {
      console.error('Error retrieving analysis results from MongoDB:', error);
      res.status(500).json({ error: 'Failed to retrieve analysis results' });
    }
  });
  
  // New: Endpoint to retrieve all analysis results for a logged-in user
  app.get('/api/user-scans', authenticateToken, async (req, res) => {
    try {
      const userId = req.user.userId;
      const { contentTypes, riskLevels, startDate, endDate } = req.query;

      // New: More robust query building
      let queryConditions = [{ userId: userId }];

      if (contentTypes) {
        queryConditions.push({ submissionType: { $in: contentTypes.split(',') } });
      }

      if (riskLevels) {
        const riskOrConditions = riskLevels.split(',').map(level => {
          if (level === 'low') return { 'result.riskScore': { $gte: 0, $lte: 25 } };
          if (level === 'medium') return { 'result.riskScore': { $gte: 26, $lte: 75 } };
          if (level === 'high') return { 'result.riskScore': { $gte: 76, $lte: 100 } };
        }).filter(Boolean);
        
        if (riskOrConditions.length > 0) {
          queryConditions.push({ $or: riskOrConditions });
        }
      }
      
      if (startDate || endDate) {
        const dateQuery = {};
        if (startDate) {
          dateQuery.$gte = new Date(startDate);
        }
        if (endDate) {
          dateQuery.$lte = new Date(endDate);
        }
        queryConditions.push({ createdAt: dateQuery });
      }

      const finalQuery = queryConditions.length > 1 ? { $and: queryConditions } : queryConditions[0];
      
      console.log("Executing DB query:", JSON.stringify(finalQuery, null, 2));

      const userScans = await analysisCollection.find(finalQuery).sort({ createdAt: -1 }).toArray();
      res.json(userScans);
    } catch (error) {
      console.error('Error fetching user scans from MongoDB:', error);
      res.status(500).json({ error: 'Failed to retrieve user scans' });
    }
  });

  // New: Endpoint to get a user's subscription status
  app.get('/api/user-subscription', authenticateToken, async (req, res) => {
    try {
      const userId = req.user.userId;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found.' });
      }
      
      const isSubscribed = user.isSubscribed && user.subscriptionEndDate && user.subscriptionEndDate > new Date();
      
      // If the subscription has expired, update the database
      if (user.isSubscribed && !isSubscribed) {
        user.isSubscribed = false;
        await user.save();
        console.log(`Subscription for user ${userId} has expired. Status updated.`);
      }

      res.json({ isSubscribed: isSubscribed });
    } catch (error) {
      console.error('Error fetching user subscription status:', error);
      res.status(500).json({ error: 'Failed to retrieve subscription status' });
    }
  });

  // New: Stripe Checkout Session Endpoint
    app.post('/create-checkout-session', authenticateToken, async (req, res) => {
    try {
      const { priceId } = req.body;
      const userId = req.user.userId;

      // Find the user in your database
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found.' });
      }

      let stripeCustomerId = user.stripeCustomerId;

      // If the user doesn't have a Stripe Customer ID, create one
      if (!stripeCustomerId) {
        const customer = await stripe.customers.create({
          email: user.email,
          metadata: { userId: userId },
        });
        stripeCustomerId = customer.id;
        // Save the new customer ID to the user record
        user.stripeCustomerId = stripeCustomerId;
        await user.save();
        console.log(`New Stripe Customer created and saved for user ${userId}`);
      }
      
      const price = await stripe.prices.retrieve(priceId);
      const mode = price.recurring ? 'subscription' : 'payment';

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price: priceId,
          quantity: 1,
        }],
        mode: mode,
        customer: stripeCustomerId, // Use the customer ID here
        success_url: `${req.protocol}://${req.get('host')}/success.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${req.protocol}://${req.get('host')}/cancel.html`,
        metadata: { userId: userId }, // Keep this for the webhook
      });

      res.json({ id: session.id });
    } catch (e) {
      console.error('Error creating Stripe Checkout session:', e);
      res.status(500).json({ error: e.message });
    }
  });

  // New: Endpoint to check the status of a checkout session and update the user
  app.post('/api/check-session-status', authenticateToken, async (req, res) => {
    try {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status === 'paid') {
        const user = await User.findById(req.user.userId);

        if (user && !user.isSubscribed) {
          // The user is not yet marked as subscribed, let's update them now.
          // This logic is similar to the webhook, ensuring fast updates.
          let updateData = {};
          if (session.mode === 'subscription') {
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            updateData = {
              isSubscribed: true,
              subscriptionEndDate: new Date(subscription.current_period_end * 1000),
              stripeCustomerId: session.customer,
            };
          } else if (session.mode === 'payment') {
            const farFutureDate = new Date();
            farFutureDate.setFullYear(farFutureDate.getFullYear() + 100);
            updateData = {
              isSubscribed: true,
              subscriptionEndDate: farFutureDate,
              stripeCustomerId: session.customer,
            };
          }
          await User.findByIdAndUpdate(user._id, updateData);
          console.log(`User ${user._id} subscription activated via session check.`);
        }
        
        // Confirm that the subscription is now active
        const updatedUser = await User.findById(req.user.userId);
        res.json({ isSubscribed: updatedUser.isSubscribed });

      } else {
        // If not paid, just return the current (likely false) subscription status
        res.json({ isSubscribed: false });
      }
    } catch (error) {
      console.error('Error checking session status:', error);
      res.status(500).json({ error: 'Failed to check session status' });
    }
  });

  // New: Stripe Customer Portal Session Endpoint
  app.post('/create-portal-session', authenticateToken, async (req, res) => {
    try {
      const userId = req.user.userId;
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ error: 'User not found.' });
      }
      
      if (!user.stripeCustomerId) {
        console.error(`User ${userId} attempted to access portal without a Stripe Customer ID.`);
        return res.status(400).json({ error: 'Stripe customer ID not found for this user.' });
      }

      const portalSession = await stripe.billingPortal.sessions.create({
        customer: user.stripeCustomerId,
        return_url: `${req.protocol}://${req.get('host')}/`, // Redirect back to the main page
      });

      res.json({ url: portalSession.url });
    } catch (e) {
      console.error(`Error creating Stripe Customer Portal session for user ${req.user.userId}:`, e);
      res.status(500).json({ error: 'Failed to create customer portal session.' });
    }
  });

  // Start the server after connecting to the database
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
  });

    app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('Webhook signature verification failed.', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Log the incoming event
    console.log('Stripe webhook event received:', event.type);

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const { userId } = session.metadata;

      console.log(`Processing checkout.session.completed for user ID: ${userId}`);

      if (session.payment_status === 'paid') {
        try {
          let updateData = {};

          if (session.mode === 'subscription') {
            // It's a recurring subscription
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            updateData = {
              isSubscribed: true,
              subscriptionEndDate: new Date(subscription.current_period_end * 1000),
              stripeCustomerId: session.customer,
            };
            console.log(`Successfully updated subscription for user ${userId}. End date: ${updateData.subscriptionEndDate}`);
          } else if (session.mode === 'payment') {
            // It's a one-time payment (Lifetime Access)
            // Set an end date far in the future
            const farFutureDate = new Date();
            farFutureDate.setFullYear(farFutureDate.getFullYear() + 100); // 100 years from now
            
            updateData = {
              isSubscribed: true,
              subscriptionEndDate: farFutureDate,
              stripeCustomerId: session.customer,
            };
            console.log(`Successfully updated one-time payment for user ${userId}. End date: ${updateData.subscriptionEndDate}`);
          }
          
          // Update the user record in the database
          if (Object.keys(updateData).length > 0) {
            await User.findByIdAndUpdate(userId, updateData);
            console.log(`Webhook: Successfully saved updateData for user ${userId}. Customer ID: ${updateData.stripeCustomerId}`);
          }

        } catch (error) {
          console.error(`Webhook: Failed to update user ${userId} after payment:`, error);
        }
      }
    }

    res.status(200).end();
  });
});