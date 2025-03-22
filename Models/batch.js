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
    feesPayments: [{
        student: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        amount: {
            type: Number,
            required: true
        },
        paymentDate: {
            type: Date,
            default: Date.now
        },
        paymentMethod: {
            type: String,
            enum: ['online', 'offline'],
            required: true
        },
        status: {
            type: String,
            enum: ['paid', 'pending', 'overdue'],
            default: 'pending'
        },
        verifiedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'AdminUser'
        },
        remarks: {
            type: String
        }
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
    }],
    timetable: {
        monday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }],
        tuesday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }],
        wednesday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }],
        thursday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }],
        friday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }],
        saturday: [{
            hour: { type: Number, min: 1 },
            subject: { type: String },
            teacher: { type: String },
            startTime: { type: String },
            endTime: { type: String }
        }]
    },
    testResults: [{
        examName: { 
            type: String, 
            required: true 
        },
        date: { 
            type: Date, 
            default: Date.now 
        },
        maximumMarks: {
            type: Number,
            required: true
        },
        subject: {
            type: String,
            required: true
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'AdminUser',
            required: true
        },
        studentMarks: [{
            student: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                required: true
            },
            marks: {
                type: Number,
                required: true
            },
            remarks: {
                type: String
            }
        }]
    }]
}, {
    timestamps: true
});

module.exports = mongoose.model('Batch', BatchSchema);