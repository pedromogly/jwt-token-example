const mongoose = require('mongoose')

const User = mongoose.model('User', {
    name: String,
    email: String,
    pass: String
})

module.exports = User