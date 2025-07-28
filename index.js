const express = require('express');
const multer = require('multer');
const OpenAI = require('openai');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
require('dotenv').config();

const app = express();
const port = 3000;

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
app.use(express.static('.'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

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

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/styles.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'styles.css'));
});

// API endpoint for scam detection
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    const { text } = req.body;
    const file = req.file;
    
    let content = '';
    let fileInfo = '';
    let pdfContent = '';
    let pdfLinks = [];
    
    if (text) {
      content += `Text content: ${text}\n\n`;
    }
    
    if (file) {
      fileInfo = `File uploaded: ${file.originalname} (${file.mimetype})\n`;
      content += fileInfo;
      
      // Process PDF files
      if (file.mimetype === 'application/pdf') {
        console.log('Processing PDF file:', file.originalname);
        const pdfResult = await extractContentFromPDF(file.path);
        pdfContent = pdfResult.text;
        pdfLinks = pdfResult.links;
        
        content += `PDF Content:\n${pdfContent}\n\n`;
        
        if (pdfLinks.length > 0) {
          content += `PDF Links found:\n${pdfLinks.join('\n')}\n\n`;
        }
        
        console.log('PDF processing complete. Links found:', pdfLinks.length);
      }
    }
    
    if (!content.trim()) {
      return res.status(400).json({ error: 'No content provided for analysis' });
    }

    const prompt = `Analyze the following content for potential scams, fraud, or malicious activity. Provide a comprehensive analysis including:

1. Risk Assessment (0-100 score)
2. Red Flags Identified
3. Potential Threats
4. Recommended Actions (delete, report, block, etc.)
5. Safety Tips

Content to analyze:
${content}

Please format your response as JSON with the following structure:
{
  "riskScore": number,
  "redFlags": [array of strings],
  "threats": [array of strings],
  "recommendations": [array of strings],
  "safetyTips": [array of strings],
  "summary": "brief summary"
}`;

    console.log('Sending request to ChatGPT with content length:', content.length);
    console.log('Content preview:', content.substring(0, 500) + '...');

    const completion = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert specializing in scam detection and fraud prevention. Analyze content for potential threats and provide actionable advice."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.3,
    });

    const response = completion.choices[0].message.content;
    
    // Console log the raw ChatGPT response
    console.log('=== RAW CHATGPT RESPONSE ===');
    console.log(response);
    console.log('=== END RAW RESPONSE ===');
    
    // Try to parse as JSON, if it fails, return as text
    try {
      const jsonResponse = JSON.parse(response);
      console.log('Successfully parsed JSON response');
      res.json(jsonResponse);
    } catch (e) {
      console.log('Failed to parse JSON, returning fallback response');
      res.json({
        riskScore: 50,
        redFlags: ["Unable to parse AI response"],
        threats: ["Analysis incomplete"],
        recommendations: ["Please try again"],
        safetyTips: ["Contact support if issues persist"],
        summary: response
      });
    }

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ 
      error: 'Analysis failed',
      details: error.message 
    });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});