const mongoose = require('mongoose');

const BatchSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    batch_code: {
        type: String,
        required: true,
        unique: true,
        uppercase: true
    },
    class: {
        type: String,
        required: true
    },
    teacher_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'AdminUser',
        required: true
    },
    students: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    announcements: [{
        title: { type: String, required: true },
        content: { type: String, required: true },
        teacher_id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'AdminUser',
            required: true
        },
        createdAt: { type: Date, default: Date.now }
    }]
}, {
    timestamps: true
});

module.exports = mongoose.model('Batch', BatchSchema);