const axios = require('axios');

let apiKey = null;

function getApiKey() {
  if (!apiKey) {
    apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      throw new Error('MISTRAL_API_KEY is not set in environment variables');
    }
  }
  return apiKey;
}

async function chat(messages, options = {}) {
  const apiKey = getApiKey();
  const model = options.model || 'mistral-large-latest';
  const apiUrl = 'https://api.mistral.ai/v1/chat/completions';
  
  try {
    const response = await axios.post(
      apiUrl,
      {
        model,
        messages,
        temperature: options.temperature || 0.7,
        max_tokens: options.maxTokens || 2000,
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );
    
    return response.data.choices[0].message.content;
  } catch (error) {
    console.error('Mistral AI error:', error.response?.data || error.message);
    throw error;
  }
}

async function analyzeImage(imageBase64, prompt, options = {}) {
  const apiKey = getApiKey();
  const model = options.model || 'pixtral-large-latest'; // Vision model
  const apiUrl = 'https://api.mistral.ai/v1/chat/completions';
  
  try {
    const response = await axios.post(
      apiUrl,
      {
        model,
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: prompt },
              {
                type: 'image_url',
                image_url: {
                  url: `data:image/jpeg;base64,${imageBase64}`,
                },
              },
            ],
          },
        ],
        temperature: options.temperature || 0.7,
        max_tokens: options.maxTokens || 2000,
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );
    
    return response.data.choices[0].message.content;
  } catch (error) {
    console.error('Mistral AI vision error:', error.response?.data || error.message);
    throw error;
  }
}

module.exports = {
  chat,
  analyzeImage,
};

