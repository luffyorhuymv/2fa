/**
 * Google Apps Script - 2FA Sync API
 * 
 * HƯỚNG DẪN DEPLOY:
 * 1. Mở Google Sheets mới
 * 2. Extensions → Apps Script
 * 3. Paste code này vào
 * 4. Deploy → New deployment
 * 5. Type: Web app
 * 6. Execute as: Me
 * 7. Who has access: Anyone
 * 8. Deploy và copy URL
 */

// Sheet name để lưu data
const SHEET_NAME = '2FA_Data';

/**
 * Handle GET requests - Đọc dữ liệu
 */
function doGet(e) {
  try {
    const sheet = getOrCreateSheet();
    const data = sheet.getRange('A1').getValue();
    const timestamp = sheet.getRange('B1').getValue();
    
    return createResponse({
      success: true,
      data: data || '',
      timestamp: timestamp || 0
    });
  } catch (error) {
    return createResponse({
      success: false,
      error: error.message
    });
  }
}

/**
 * Handle POST requests - Ghi dữ liệu
 */
function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents);
    const { data, timestamp } = body;
    
    if (!data) {
      return createResponse({
        success: false,
        error: 'Missing data field'
      });
    }
    
    const sheet = getOrCreateSheet();
    sheet.getRange('A1').setValue(data);
    sheet.getRange('B1').setValue(timestamp || Date.now());
    
    return createResponse({
      success: true,
      message: 'Data saved successfully',
      timestamp: timestamp || Date.now()
    });
  } catch (error) {
    return createResponse({
      success: false,
      error: error.message
    });
  }
}

/**
 * Get or create the data sheet
 */
function getOrCreateSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    // Set headers
    sheet.getRange('A1').setValue('');
    sheet.getRange('B1').setValue(0);
  }
  
  return sheet;
}

/**
 * Create JSON response with CORS headers
 */
function createResponse(data) {
  return ContentService
    .createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Test function - Chạy thử trước khi deploy
 */
function testAPI() {
  // Test GET
  const getResult = doGet({});
  Logger.log('GET Result: ' + getResult.getContent());
  
  // Test POST
  const postResult = doPost({
    postData: {
      contents: JSON.stringify({
        data: 'test_encrypted_data',
        timestamp: Date.now()
      })
    }
  });
  Logger.log('POST Result: ' + postResult.getContent());
}
