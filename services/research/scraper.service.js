const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');

async function fetchContent(url) {
  try {
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      },
      timeout: 10000,
    });
    return response.data;
  } catch (error) {
    console.error(`Error fetching ${url}:`, error.message);
    return null;
  }
}

async function fetchWithBrowser(url) {
  let browser = null;
  try {
    browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });
    const content = await page.content();
    return content;
  } catch (error) {
    console.error(`Error fetching with browser ${url}:`, error.message);
    return null;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

async function searchGitHub(query, limit = 10) {
  try {
    const url = `https://github.com/search?q=${encodeURIComponent(query)}&type=repositories`;
    const html = await fetchWithBrowser(url);
    if (!html) return [];

    const $ = cheerio.load(html);
    const results = [];

    $('.repo-list-item').slice(0, limit).each((i, elem) => {
      const $elem = $(elem);
      const title = $elem.find('.v-align-middle').text().trim();
      const href = $elem.find('.v-align-middle').attr('href');
      const description = $elem.find('.mb-1').text().trim();

      if (title && href) {
        results.push({
          title,
          url: `https://github.com${href}`,
          description,
          source: 'github',
        });
      }
    });

    return results;
  } catch (error) {
    console.error('Error searching GitHub:', error.message);
    return [];
  }
}

async function searchExploitDB(query, limit = 10) {
  try {
    const url = `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}`;
    const html = await fetchContent(url);
    if (!html) return [];

    const $ = cheerio.load(html);
    const results = [];

    $('table tbody tr').slice(0, limit).each((i, elem) => {
      const $elem = $(elem);
      const title = $elem.find('td:nth-child(2)').text().trim();
      const href = $elem.find('td:nth-child(2) a').attr('href');
      const cve = $elem.find('td:nth-child(3)').text().trim();

      if (title && href) {
        results.push({
          title,
          url: href.startsWith('http') ? href : `https://www.exploit-db.com${href}`,
          cve,
          source: 'exploit-db',
        });
      }
    });

    return results;
  } catch (error) {
    console.error('Error searching Exploit-DB:', error.message);
    return [];
  }
}

async function parseReadme(url) {
  try {
    let readmeUrl = url;
    if (!url.endsWith('/README.md') && !url.endsWith('/readme.md')) {
      readmeUrl = url.replace(/\/$/, '') + '/blob/master/README.md';
    }

    const content = await fetchContent(readmeUrl);
    if (!content) return null;

    return {
      content,
      url: readmeUrl,
    };
  } catch (error) {
    console.error(`Error parsing README from ${url}:`, error.message);
    return null;
  }
}

async function extractInstallationInstructions(content) {
  const instructions = {
    installCommands: [],
    dependencies: [],
    prerequisites: [],
  };

  try {
    const $ = cheerio.load(content);

    // Look for common installation patterns
    const patterns = [
      /install/i,
      /setup/i,
      /getting started/i,
      /prerequisites/i,
      /dependencies/i,
    ];

    $('code, pre').each((i, elem) => {
      const code = $(elem).text();
      
      // Extract install commands
      if (code.includes('pip install') || code.includes('npm install') || 
          code.includes('apt install') || code.includes('gem install') ||
          code.includes('cargo install') || code.includes('git clone')) {
        instructions.installCommands.push(code.trim());
      }

      // Extract dependencies
      if (code.includes('requirements.txt') || code.includes('package.json') ||
          code.includes('dependencies') || code.includes('requirements')) {
        instructions.dependencies.push(code.trim());
      }
    });

    // Extract prerequisites from text
    $('li, p').each((i, elem) => {
      const text = $(elem).text();
      if (text.match(/require|need|prerequisite|python|node|java|ruby/i)) {
        instructions.prerequisites.push(text.trim());
      }
    });

    return instructions;
  } catch (error) {
    console.error('Error extracting installation instructions:', error.message);
    return instructions;
  }
}

module.exports = {
  fetchContent,
  fetchWithBrowser,
  searchGitHub,
  searchExploitDB,
  parseReadme,
  extractInstallationInstructions,
};

