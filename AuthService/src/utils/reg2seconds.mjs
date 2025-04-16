const convertToSeconds = (timeStr) => {
  const regex = /^(\d+)([a-zA-Z]+)$/; // matches a number followed by characters (e.g., 7d, 5mo)
  const match = timeStr.match(regex);
  
  if (!match) {
    throw new Error('Invalid time format');
  }
  
  const value = parseInt(match[1], 10); // numeric part
  const unit = match[2].toLowerCase(); // unit part (d, mo, m)
  
  switch (unit) {
  case 'd': // days
    return value * 24 * 60 * 60; // days to seconds
  case 'm': // minutes
    return value * 60; // minutes to seconds
  case 'h': // hours
    return value * 60 * 60; // hours to seconds
  case 'mo': // months (approximation)
    return value * 30 * 24 * 60 * 60; // months to seconds (assuming 30 days per month)
  case 'y': // years (approximation)
    return value * 365 * 24 * 60 * 60; // years to seconds (assuming 365 days per year)
  default:
    throw new Error('Unknown unit');
  }
};
export default convertToSeconds;
