import winston from 'winston';

// Define the log file path
const logFilePath = 'app.log'
console.log("Logs will be saved to "+logFilePath);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Console transport for logging to the console
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    // File transport for logging to a file
    new winston.transports.File({
      filename: logFilePath,
      level: 'info', // You can adjust the level for file logging here
    })
  ],
});

export default logger;
