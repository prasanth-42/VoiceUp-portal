const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function categorizeComplaint(description) {
    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.2,
                topK: 1,
                topP: 0.95,
                maxOutputTokens: 10,
            }
        });

        const prompt = `Analyze this complaint and categorize it into exactly one of these categories: INFRASTRUCTURE, WATER_SUPPLY, ELECTRICITY, SANITATION, HEALTHCARE, EDUCATION, TRANSPORTATION, or OTHER.
        
        Rules for categorization:
        - INFRASTRUCTURE: For issues related to roads, bridges, buildings, and general city infrastructure
        - WATER_SUPPLY: For issues related to water supply, quality, and distribution
        - ELECTRICITY: For issues related to power supply, street lights, electrical infrastructure, and power outages
        - SANITATION: For issues related to garbage collection, waste management, and cleanliness
        - HEALTHCARE: For issues related to hospitals, clinics, medical services, and public health
        - EDUCATION: For issues related to schools, colleges, educational facilities, and learning resources
        - TRANSPORTATION: For issues related to public transport, traffic management, and vehicle-related services
        - OTHER: For any issues that don't fit into the above categories
        
        Only respond with the category name in uppercase. Here's the complaint description: ${description}`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const category = response.text().trim();

        // Validate the response
        const validCategories = ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER'];
        if (!validCategories.includes(category)) {
            // Default to OTHER if the AI returns an invalid category
            console.warn(`Invalid category returned from AI: ${category}. Defaulting to OTHER.`);
            return 'OTHER';
        }

        return category;
    } catch (error) {
        console.error('Error in categorization:', error);
        // Default to OTHER in case of error
        return 'OTHER';
    }
}

// New function to get government scheme information based on complaint category
async function getGovernmentSchemeInfo(category, description) {
    try {
        const model = genAI.getGenerativeModel({
            model: "gemini-2.0-flash",
            generationConfig: {
                temperature: 0.7,
                topK: 40,
                topP: 0.95,
                maxOutputTokens: 500,
            }
        });

        const prompt = `Based on this complaint category (${category}) and description (${description}), suggest relevant Indian government schemes that might help the citizen. 
        
        For each category, consider these schemes:
        - INFRASTRUCTURE: PM Gati Shakti, Smart Cities Mission, AMRUT
        - WATER_SUPPLY: Jal Jeevan Mission, Atal Mission for Rejuvenation and Urban Transformation (AMRUT)
        - ELECTRICITY: Saubhagya Scheme, UDAY, Deen Dayal Upadhyaya Gram Jyoti Yojana
        - SANITATION: Swachh Bharat Mission, AMRUT
        - HEALTHCARE: Ayushman Bharat, National Health Mission, PM-JAY
        - EDUCATION: Samagra Shiksha, Beti Bachao Beti Padhao, Mid-Day Meal Scheme
        - TRANSPORTATION: PM Gati Shakti, Bharatmala, Sagarmala
        
        Provide a brief description of 1-2 most relevant schemes and how they might help with this specific complaint.
        If the category is OTHER, suggest general grievance schemes like CPGRAMS.
        
        Format your response as a JSON object with these fields:
        {
            "schemes": [
                {
                    "name": "Scheme Name",
                    "description": "Brief description",
                    "relevance": "How it relates to this complaint",
                    "link": "Official website or application link"
                }
            ]
        }`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text().trim();
        
        try {
            // Try to parse the response as JSON
            return JSON.parse(text);
        } catch (parseError) {
            console.error('Error parsing scheme info JSON:', parseError);
            // Return a default structure if parsing fails
            return {
                schemes: [{
                    name: "CPGRAMS",
                    description: "Centralized Public Grievance Redress And Monitoring System",
                    relevance: "General grievance portal for all government-related complaints",
                    link: "https://pgportal.gov.in/"
                }]
            };
        }
    } catch (error) {
        console.error('Error getting government scheme info:', error);
        return {
            schemes: [{
                name: "CPGRAMS",
                description: "Centralized Public Grievance Redress And Monitoring System",
                relevance: "General grievance portal for all government-related complaints",
                link: "https://pgportal.gov.in/"
            }]
        };
    }
}

module.exports = {
    categorizeComplaint,
    getGovernmentSchemeInfo
}; 