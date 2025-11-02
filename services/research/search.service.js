const axios = require('axios');

// Using DuckDuckGo HTML interface for searches
// Can be replaced with Google Custom Search API if API key is available

async function search(query, limit = 10) {
  try {
    // DuckDuckGo search
    const ddgUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    
    const response = await axios.get(ddgUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      },
      timeout: 10000,
    });

    const cheerio = require('cheerio');
    const $ = cheerio.load(response.data);
    const results = [];

    $('.result').slice(0, limit).each((i, elem) => {
      const $elem = $(elem);
      const title = $elem.find('.result__a').text().trim();
      const url = $elem.find('.result__a').attr('href');
      const snippet = $elem.find('.result__snippet').text().trim();

      if (title && url) {
        results.push({
          title,
          url: url.replace(/^\/\/l\.l/, 'https://'), // Fix DuckDuckGo redirect links
          snippet,
          source: 'duckduckgo',
        });
      }
    });

    return results;
  } catch (error) {
    console.error('Search error:', error.message);
    
    // Fallback: try Google (no API)
    try {
      return await searchGoogleFallback(query, limit);
    } catch (fallbackError) {
      console.error('Fallback search error:', fallbackError.message);
      return [];
    }
  }
}

async function searchGoogleFallback(query, limit = 10) {
  // Simple Google search fallback (may be rate limited)
  try {
    const url = `https://www.google.com/search?q=${encodeURIComponent(query)}&num=${limit}`;
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      },
      timeout: 10000,
    });

    const cheerio = require('cheerio');
    const $ = cheerio.load(response.data);
    const results = [];

    $('div.g').slice(0, limit).each((i, elem) => {
      const $elem = $(elem);
      const title = $elem.find('h3').text().trim();
      const url = $elem.find('a').attr('href');
      const snippet = $elem.find('.VwiC3b').text().trim();

      if (title && url) {
        results.push({
          title,
          url,
          snippet,
          source: 'google',
        });
      }
    });

    return results;
  } catch (error) {
    console.error('Google fallback error:', error.message);
    return [];
  }
}

async function searchCVEDatabase(cveId) {
  try {
    const url = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`;
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      },
      timeout: 10000,
    });

    const cheerio = require('cheerio');
    const $ = cheerio.load(response.data);
    
    const description = $('td:contains("Description")').next().text().trim();
    const references = [];

    $('a[href^="http"]').each((i, elem) => {
      const href = $(elem).attr('href');
      const text = $(elem).text().trim();
      if (href && text) {
        references.push({ url: href, text });
      }
    });

    return {
      cveId,
      description,
      references,
    };
  } catch (error) {
    console.error(`Error searching CVE ${cveId}:`, error.message);
    return null;
  }
}

module.exports = {
  search,
  searchCVEDatabase,
};

