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
    // Handle rate limiting and API errors gracefully
    if (error.response) {
      const status = error.response.status;
      const errorData = error.response.data;
      
      if (status === 429 || (errorData && errorData.code === '3505')) {
        console.warn('Mistral AI rate limit exceeded. Using fallback response.');
        // Return a generic fallback response instead of throwing
        return JSON.stringify({
          action: 'continue',
          reasoning: 'Rate limited - continuing with default actions',
          tools: [],
          priority: 'medium',
        });
      }
      
      if (status === 401 || status === 403) {
        console.error('Mistral AI authentication error. Check your API key.');
        throw new Error('Mistral AI authentication failed');
      }
      
      console.error('Mistral AI error:', errorData || error.message);
    } else {
      console.error('Mistral AI network error:', error.message);
    }
    
    // Return fallback instead of throwing to prevent crashes
    if (options.fallbackResponse) {
      return options.fallbackResponse;
    }
    
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

