const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
    batch_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Batch',
        required: true
    },
    date: {
        type: Date,
        required: true
    },
    records: [{
        student_id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        status: {
            type: String,
            enum: ['present', 'absent'],
            required: true
        },
        remarks: String
    }],
    marked_by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'AdminUser',
        required: true
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Attendance', attendanceSchema);
