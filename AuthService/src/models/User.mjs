import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSchema = new mongoose.Schema({
    userId: {
        type: Number,
        unique: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    firstName: {
        type: String
    },
    lastName: {
        type: String
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        required: true,
        default: 'user'
    },
    profilePicture: {
        type: String
    },
    loggedIn: {
        type: Boolean,
        default: false
    },
}, {
  // This enables the use of _id and will ensure virtual fields are included in toJSON
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Pre-save hook to auto-generate userId if not provided
userSchema.pre('save', async function(next) {
  if (!this.userId) {
    // Find the highest userId in the collection and increment by 1
    const highestUser = await this.constructor.findOne({}, {}, { sort: { userId: -1 } });
    this.userId = highestUser ? highestUser.userId + 1 : 1;
  }

  // Only hash the password if it's been modified (or is new)
  if (!this.isModified('password')) return next();
    
  try {
    // Generate a salt with 10 rounds
    const salt = await bcrypt.genSalt(10);
    // Hash the password along with the new salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.matchPassword = function (password) {
  return bcrypt.compare(password, this.password);
};

export default mongoose.model('User', userSchema, 'Users');
