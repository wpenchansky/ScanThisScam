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
  const scamsCollection = db.collection('scams'); // Use a new collection name to avoid conflict if 'scams' is generic
  const analysisCollection = db.collection('analysis_metadata'); // New: Collection for analysis results metadata

  // New: MongoDB routes for scam data
  app.post('/api/upload', async (req, res) => {
    try {
      const data = req.body; // Assuming req.body contains the data to store
      const result = await scamsCollection.insertOne(data);
      res.json(result);
    } catch (error) {
      console.error('Error uploading scam data to MongoDB:', error);
      res.status(500).json({ error: 'Failed to upload scam data' });
    }
  });

  app.get('/api/scams', async (req, res) => {
    try {
      const allScams = await scamsCollection.find().toArray();
      res.json(allScams);
    } catch (error) {
      console.error('Error fetching scam data from MongoDB:', error);
      res.status(500).json({ error: 'Failed to fetch scam data' });
    }
  });

  // *** New: User Authentication Routes ***

  // POST /signup
  app.post('/signup', async (req, res) => {
    try {
      const { email, password } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).send('User with that email already exists.');
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const user = new User({ email, passwordHash });
      await user.save();

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
        await analysisCollection.insertOne({
          _id: analysisId,
          userId: req.user.userId, // New: Store userId with the analysis
          result: jsonResponse,
          status: 'pending',
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
  
  // New: Endpoint to mark analysis as paid
  app.post('/api/mark-paid', authenticateToken, async (req, res) => {
    const { analysisId } = req.body;
    try {
      // Ensure the update is for the authenticated user's analysis
      const result = await analysisCollection.updateOne(
        { _id: analysisId, userId: req.user.userId }, // New: Include userId in query
        { $set: { status: 'paid', paidAt: new Date() } }
      );
      if (result.matchedCount === 1) {
        console.log(`Analysis ID ${analysisId} marked as paid in MongoDB.`);
        res.json({ status: 'success' });
      } else {
        res.status(404).json({ error: 'Analysis ID not found or not owned by user in MongoDB' }); // More specific error
      }
    } catch (error) {
      console.error('Error marking analysis paid in MongoDB:', error);
      res.status(500).json({ error: 'Failed to mark analysis paid' });
    }
  });
  
  // New: Endpoint to retrieve analysis results (only if paid)
  app.get('/api/results/:analysisId', authenticateToken, async (req, res) => {
    const { analysisId } = req.params;
    try {
      // Ensure only the authenticated user can retrieve their own analysis
      const analysisDoc = await analysisCollection.findOne({ _id: analysisId, userId: req.user.userId }); // New: Include userId in query
      if (analysisDoc) {
        if (analysisDoc.status === 'paid' || (await User.findById(req.user.userId)).isSubscribed) {
          res.json(analysisDoc.result); // Return the actual result
        } else if (analysisDoc.status === 'pending') {
          res.status(403).json({ error: 'Payment required for these results.' });
        } else {
          res.status(404).json({ error: 'Analysis status unknown.' });
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
      const userId = req.user.userId; // Get userId from authenticated token
      const userScans = await analysisCollection.find({ userId: userId }).toArray();
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
      res.json({ isSubscribed: user.isSubscribed });
    } catch (error) {
      console.error('Error fetching user subscription status:', error);
      res.status(500).json({ error: 'Failed to retrieve subscription status' });
    }
  });

  // New: Stripe Checkout Session Endpoint
    app.post('/create-checkout-session', authenticateToken, async (req, res) => {
    try {
      const { priceId } = req.body;
      const price = await stripe.prices.retrieve(priceId);
      const mode = price.recurring ? 'subscription' : 'payment';

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price: priceId,
          quantity: 1,
        }],
        mode: mode,
        success_url: `${req.protocol}://${req.get('host')}/success.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${req.protocol}://${req.get('host')}/cancel.html`,
        metadata: { userId: req.user.userId },
      });

      res.json({ id: session.id });
    } catch (e) {
      console.error('Error creating Stripe Checkout session:', e);
      res.status(500).json({ error: e.message });
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

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const { userId } = session.metadata;

      if (session.payment_status === 'paid') {
        try {
          await User.findByIdAndUpdate(userId, { isSubscribed: true });
          console.log(`User ${userId} subscription status updated to true.`);
        } catch (error) {
          console.error(`Failed to update subscription status for user ${userId}:`, error);
        }
      }
    }

    res.status(200).end();
  });
});