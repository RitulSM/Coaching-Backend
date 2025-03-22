const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const AdminUser = require('../models/adminUser');
const User = require('../models/user');
const Batch = require('../models/batch');
const Announcement = require('../models/announcement');
const Attendance = require('../models/attendance');
const mongoose = require('mongoose');
const router = express.Router();

const registerSchema = z.object({
    name: z.string().min(1, "Name is required"),
    email: z.string().email("Invalid email format"),
    password: z.string().min(6, "Password must be at least 6 characters long")
});

const batchSchema = z.object({
    batch_code: z.string().min(1, "Batch code is required"),
    name: z.string().min(1, "Batch name is required"),
    class: z.string().min(1, "Class is required"),
    teacher_id: z.string().min(1, "Teacher ID is required")
});


router.use((req, res, next) => {
    if (req.path === '/register') {
        console.log('Request Body:', req.body);
        console.log('Content-Type:', req.headers['content-type']);
    }
    next();
});

router.post("/register", async (req, res) => {
    try {
        // Log the raw request body
        console.log('Raw request body:', req.body);

        // Add explicit type checking
        if (!req.body || typeof req.body !== 'object') {
            return res.status(400).json({
                success: false,
                message: "Invalid request body",
                received: req.body
            });
        }

        // Destructure with default values to prevent undefined
        const {
            name = undefined,
            email = undefined,
            password = undefined
        } = req.body;

        // Log the extracted values
        console.log('Extracted values:', { name, email, password });

        const validatedData = registerSchema.parse({
            name,
            email,
            password
        });
        
        const existingAdmin = await AdminUser.findOne({ email: validatedData.email });
        if (existingAdmin) {
            return res.status(409).json({
                success: false,
                message: "Admin email already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(validatedData.password, 10);
        
        const admin = await AdminUser.create({
            name: validatedData.name,
            email: validatedData.email,
            password: hashedPassword,
            role: 'admin',
            active: true
        });

        const token = jwt.sign(
            { adminId: admin._id, email: admin.email, role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(201).json({
            success: true,
            message: "Admin registration successful",
            token,
            admin: { 
                id: admin._id,
                name: admin.name, 
                email: admin.email,
                role: 'admin'
            }
        });
    } catch (error) {
        console.error("Registration error:", error);
        
        // Improve error response
        if (error.errors) {
            return res.status(400).json({ 
                success: false,
                message: "Validation error",
                errors: error.errors,
                receivedData: req.body
            });
        }
        
        res.status(500).json({ 
            success: false,
            message: "Server error during registration",
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

const validateLogin = (data) => {
  const errors = {};
  
  if (!data.email || !/^\S+@\S+\.\S+$/.test(data.email)) {
    errors.email = "Invalid email format";
  }
  
  if (!data.password) {
    errors.password = "Password is required";
  }
  
  return {
    isValid: Object.keys(errors).length === 0,
    errors
  };
};

router.post("/login", async (req, res) => {
    try {
        const validation = validateLogin(req.body);
        if (!validation.isValid) {
            return res.status(400).json({ 
                message: "Invalid input", 
                details: validation.errors 
            });
        }
        
        const { email, password } = req.body;
        
        const admin = await AdminUser.findOne({ email });
        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }
        
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password" });
        }
        
        const token = jwt.sign(
            { adminId: admin._id, email: admin.email },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );
        
        res.json({
            message: "Admin login successful",
            token,
            admin: {
                _id: admin._id,
                name: admin.name,
                email: admin.email,
                role: 'admin'
            }
        });
    } catch (error) {
        res.status(500).json({ 
            message: "Server error during login",
            details: error.message 
        });
    }
});

// Update the batch creation route to use logged-in teacher
router.post("/batches", async (req, res) => {
    try {
        const validatedData = batchSchema.parse(req.body);
        
        const admin = await AdminUser.findById(validatedData.teacher_id);
        if (!admin) {
            return res.status(404).json({
                success: false,
                message: "Teacher not found"
            });
        }

        const existingBatch = await Batch.findOne({ 
            batch_code: validatedData.batch_code.toUpperCase() 
        });
        
        if (existingBatch) {
            return res.status(409).json({
                success: false,
                message: "Batch code already exists"
            });
        }

        const batch = await Batch.create({
            batch_code: validatedData.batch_code.toUpperCase(),
            name: validatedData.name,
            class: validatedData.class,
            teacher_id: admin._id,
            students: []
        });

        const populatedBatch = await Batch.findById(batch._id)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email');

        res.status(201).json({
            success: true,
            message: "Batch created successfully",
            batch: populatedBatch
        });
    } catch (error) {
        console.error("Batch creation error:", error);
        res.status(500).json({
            success: false,
            message: "Error creating batch",
            error: error.message
        });
    }
});

// Add route to update a batch
router.put("/batches/:batchId", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { name, class: batchClass } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to update this batch"
            });
        }

        // Update batch details
        if (name) batch.name = name;
        if (batchClass) batch.class = batchClass;

        await batch.save();

        const populatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email');

        res.status(200).json({
            success: true,
            message: "Batch updated successfully",
            batch: populatedBatch
        });
    } catch (error) {
        console.error("Batch update error:", error);
        res.status(500).json({
            success: false,
            message: "Error updating batch",
            error: error.message
        });
    }
});

// Delete a batch
router.delete("/batches/:batchId", async (req, res) => {
    try {
        const { batchId } = req.params;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to delete this batch"
            });
        }

        // Delete the batch
        await Batch.findByIdAndDelete(batchId);

        res.status(200).json({
            success: true,
            message: "Batch deleted successfully"
        });
    } catch (error) {
        console.error("Batch deletion error:", error);
        res.status(500).json({
            success: false,
            message: "Error deleting batch",
            error: error.message
        });
    }
});

// Add Students to a Batch
router.post("/batches/:batchId/students",  async (req, res) => {
    try {
        const { studentIds } = req.body;

        if (!Array.isArray(studentIds) || studentIds.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid student IDs"
            });
        }

        const batch = await Batch.findById(req.params.batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify students exist and are students
        const students = await User.find({
            _id: { $in: studentIds },
            role: 'student'
        });

        if (students.length !== studentIds.length) {
            return res.status(400).json({
                success: false,
                message: "One or more invalid student IDs"
            });
        }

        // Add new students (avoid duplicates)
        const newStudentIds = studentIds.filter(id => !batch.students.includes(id));

        batch.students.push(...newStudentIds);
        await batch.save();

        const updatedBatch = await Batch.findById(batch._id)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email');

        res.json({
            success: true,
            message: "Students added successfully",
            batch: updatedBatch
        });
    } catch (error) {
        console.error("Error adding students:", error);
        res.status(500).json({
            success: false,
            message: "Error adding students",
            error: error.message
        });
    }
});

// Remove Student from a Batch
router.delete("/batches/:batchId/students/:studentId", async (req, res) => {
    try {
        const { batchId, studentId } = req.params;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to modify students for this batch"
            });
        }

        // Check if student exists in the batch
        if (!batch.students.includes(studentId)) {
            return res.status(404).json({
                success: false,
                message: "Student not found in this batch"
            });
        }

        // Remove the student from the batch
        batch.students = batch.students.filter(id => id.toString() !== studentId);
        await batch.save();

        const updatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email');

        res.status(200).json({
            success: true,
            message: "Student removed from batch successfully",
            batch: updatedBatch
        });
    } catch (error) {
        console.error("Error removing student from batch:", error);
        res.status(500).json({
            success: false,
            message: "Error removing student from batch",
            error: error.message
        });
    }
});

// Update the Get All Batches route
router.get("/batches", async (req, res) => {
    try {
        const batches = await Batch.find()
            .populate({
                path: 'teacher_id',
                model: 'AdminUser', // Change from User to AdminUser
                select: 'name email'
            })
            .populate('students', 'name email')
            .sort({ createdAt: -1 });

        console.log('Fetched batches:', batches); // Debug log

        res.json({
            success: true,
            batches: batches.map(batch => ({
                ...batch.toObject(),
                teacher_id: batch.teacher_id || null
            }))
        });
    } catch (error) {
        console.error("Error fetching batches:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching batches",
            error: error.message
        });
    }
});

// Update the get single batch route
router.get("/batches/:batchId", async (req, res) => {
    try {
        console.log('Fetching batch:', req.params.batchId); // Debug log

        const batch = await Batch.findById(req.params.batchId)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email');

        console.log('Found batch:', batch); // Debug log

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        return res.status(200).json({
            success: true,
            batch: {
                _id: batch._id,
                name: batch.name,
                batch_code: batch.batch_code,
                class: batch.class,
                teacher_id: batch.teacher_id,
                students: batch.students,
                createdAt: batch.createdAt,
                announcements: batch.announcements,
                timetable: batch.timetable
            }
        });
    } catch (error) {
        console.error("Error fetching batch details:", error);
        return res.status(500).json({
            success: false,
            message: "Error fetching batch details",
            error: error.message
        });
    }
});

// Get All Teachers
router.get("/teachers",  async (req, res) => {
    try {
        const teachers = await User.find({ role: 'teacher' }, 'name email');

        res.json({
            success: true,
            teachers,
            count: teachers.length
        });
    } catch (error) {
        console.error("Error fetching teachers:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching teachers",
            error: error.message
        });
    }
});

// Create announcement
router.post("/batches/:batchId/announcements", async (req, res) => {
    try {
        const { title, content, teacher_id } = req.body;
        const batchId = req.params.batchId;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Invalid authorization header"
            });
        }

        const tokenTeacherId = authHeader.split(' ')[1];

        // Validate teacher exists
        const teacher = await AdminUser.findById(tokenTeacherId);
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Check if batch exists
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== tokenTeacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to create announcement for this batch"
            });
        }

        // Add announcement
        if (!batch.announcements) {
            batch.announcements = [];
        }

        batch.announcements.unshift({
            title,
            content,
            teacher_id: tokenTeacherId,
            createdAt: new Date()
        });

        await batch.save();

        const populatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('announcements.teacher_id', 'name email');

        res.status(201).json({
            success: true,
            message: "Announcement created successfully",
            announcement: populatedBatch.announcements[0]
        });

    } catch (error) {
        console.error("Error creating announcement:", error);
        res.status(500).json({
            success: false,
            message: "Error creating announcement",
            error: error.message
        });
    }
});

// Get batch announcements
router.get("/batches/:batchId/announcements", async (req, res) => {
    try {
        const batch = await Batch.findById(req.params.batchId)
            .populate('teacher_id', 'name email')
            .populate('announcements.teacher_id', 'name email');

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        res.json({
            success: true,
            announcements: batch.announcements
        });
    } catch (error) {
        console.error("Error fetching announcements:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching announcements",
            error: error.message
        });
    }
});

// Add route to update an announcement
router.put("/batches/:batchId/announcements/:announcementId", async (req, res) => {
    try {
        const { batchId, announcementId } = req.params;
        const { title, content } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to update announcements for this batch"
            });
        }

        // Find the announcement
        const announcementIndex = batch.announcements.findIndex(
            a => a._id.toString() === announcementId
        );

        if (announcementIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "Announcement not found"
            });
        }

        // Update the announcement
        if (title) batch.announcements[announcementIndex].title = title;
        if (content) batch.announcements[announcementIndex].content = content;
        batch.announcements[announcementIndex].updatedAt = new Date();

        await batch.save();

        const populatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('announcements.teacher_id', 'name email');

        res.status(200).json({
            success: true,
            message: "Announcement updated successfully",
            announcement: populatedBatch.announcements[announcementIndex]
        });
    } catch (error) {
        console.error("Error updating announcement:", error);
        res.status(500).json({
            success: false,
            message: "Error updating announcement",
            error: error.message
        });
    }
});

// Add route to delete an announcement
router.delete("/batches/:batchId/announcements/:announcementId", async (req, res) => {
    try {
        const { batchId, announcementId } = req.params;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to delete announcements for this batch"
            });
        }

        // Find and remove the announcement
        const announcementIndex = batch.announcements.findIndex(
            a => a._id.toString() === announcementId
        );

        if (announcementIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "Announcement not found"
            });
        }

        batch.announcements.splice(announcementIndex, 1);
        await batch.save();

        res.status(200).json({
            success: true,
            message: "Announcement deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting announcement:", error);
        res.status(500).json({
            success: false,
            message: "Error deleting announcement",
            error: error.message
        });
    }
});

// Mark attendance for a batch
router.post("/batches/:batchId/attendance", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { date, records } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Check if attendance already marked for this date
        const existingAttendance = await Attendance.findOne({
            batch_id: batchId,
            date: new Date(date)
        });

        if (existingAttendance) {
            return res.status(400).json({
                success: false,
                message: "Attendance already marked for this date"
            });
        }

        const attendance = await Attendance.create({
            batch_id: batchId,
            date: new Date(date),
            records: records,
            marked_by: teacherId
        });

        const populatedAttendance = await Attendance.findById(attendance._id)
            .populate('records.student_id', 'name email')
            .populate('marked_by', 'name');

        res.status(201).json({
            success: true,
            message: "Attendance marked successfully",
            attendance: populatedAttendance
        });

    } catch (error) {
        console.error("Error marking attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error marking attendance",
            error: error.message
        });
    }
});

router.get("/batches/:batchId/attendance", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { startDate, endDate } = req.query;

        const query = {
            batch_id: batchId
        };

        if (startDate && endDate) {
            query.date = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }

        const attendance = await Attendance.find(query)
            .populate('records.student_id', 'name email')
            .populate('marked_by', 'name')
            .sort({ date: -1 });

        res.json({
            success: true,
            attendance
        });

    } catch (error) {
        console.error("Error fetching attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching attendance",
            error: error.message
        });
    }
});

// Add this new route
router.get("/batches/:batchId/student-attendance/:studentId", async (req, res) => {
    try {
        const { batchId, studentId } = req.params;
        const { startDate, endDate } = req.query;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Build query
        const query = {
            batch_id: batchId,
            'records.student_id': studentId
        };

        if (startDate && endDate) {
            query.date = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }

        // Fetch attendance records
        const attendanceRecords = await Attendance.find(query)
            .sort({ date: -1 });

        // Format records for the specific student
        const formattedRecords = attendanceRecords.map(record => {
            const studentRecord = record.records.find(
                r => r.student_id.toString() === studentId
            );
            return {
                date: record.date,
                status: studentRecord.status,
                remarks: studentRecord.remarks || ''
            };
        });

        // Calculate statistics
        const totalClasses = formattedRecords.length;
        const present = formattedRecords.filter(r => r.status === 'present').length;
        const absent = totalClasses - present;
        const attendancePercentage = totalClasses > 0 ? (present / totalClasses) * 100 : 0;

        res.json({
            success: true,
            attendance: {
                records: formattedRecords,
                statistics: {
                    totalClasses,
                    present,
                    absent,
                    attendancePercentage: Math.round(attendancePercentage * 100) / 100
                }
            }
        });

    } catch (error) {
        console.error("Error fetching student attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching student attendance",
            error: error.message
        });
    }
});

// Add route to update attendance record
router.put("/batches/:batchId/attendance/:attendanceId", async (req, res) => {
    try {
        const { batchId, attendanceId } = req.params;
        const { records } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to update attendance for this batch"
            });
        }

        // Find the attendance record
        const attendance = await Attendance.findById(attendanceId);
        if (!attendance) {
            return res.status(404).json({
                success: false,
                message: "Attendance record not found"
            });
        }

        // Verify the attendance belongs to this batch
        if (attendance.batch_id.toString() !== batchId) {
            return res.status(400).json({
                success: false,
                message: "Attendance record does not belong to this batch"
            });
        }

        // Update the attendance records
        if (records && Array.isArray(records)) {
            attendance.records = records;
        }

        await attendance.save();

        const populatedAttendance = await Attendance.findById(attendanceId)
            .populate('records.student_id', 'name email')
            .populate('marked_by', 'name');

        res.status(200).json({
            success: true,
            message: "Attendance updated successfully",
            attendance: populatedAttendance
        });
    } catch (error) {
        console.error("Error updating attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error updating attendance",
            error: error.message
        });
    }
});

// Add route to delete attendance record
router.delete("/batches/:batchId/attendance/:attendanceId", async (req, res) => {
    try {
        const { batchId, attendanceId } = req.params;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to delete attendance for this batch"
            });
        }

        // Find the attendance record
        const attendance = await Attendance.findById(attendanceId);
        if (!attendance) {
            return res.status(404).json({
                success: false,
                message: "Attendance record not found"
            });
        }

        // Verify the attendance belongs to this batch
        if (attendance.batch_id.toString() !== batchId) {
            return res.status(400).json({
                success: false,
                message: "Attendance record does not belong to this batch"
            });
        }

        // Delete the attendance record
        await Attendance.findByIdAndDelete(attendanceId);

        res.status(200).json({
            success: true,
            message: "Attendance record deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error deleting attendance",
            error: error.message
        });
    }
});

// Add or update timetable for a batch
router.post("/batches/:batchId/timetable", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { day, timetableEntries } = req.body;
        
        // Validate day
        const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        if (!validDays.includes(day.toLowerCase())) {
            return res.status(400).json({
                success: false,
                message: "Invalid day. Must be one of: monday, tuesday, wednesday, thursday, friday, saturday"
            });
        }
        
        // Validate timetable entries
        if (!Array.isArray(timetableEntries)) {
            return res.status(400).json({
                success: false,
                message: "timetableEntries must be an array"
            });
        }
        
        // Validate each entry
        for (const entry of timetableEntries) {
            if (!entry.hour || !entry.subject) {
                return res.status(400).json({
                    success: false,
                    message: "Each timetable entry must have hour and subject"
                });
            }
            
            if (entry.hour < 1 || entry.hour > 8) {
                return res.status(400).json({
                    success: false,
                    message: "Hour must be between 1 and 8"
                });
            }
        }
        
        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        // Initialize timetable if it doesn't exist
        if (!batch.timetable) {
            batch.timetable = {
                monday: [],
                tuesday: [],
                wednesday: [],
                thursday: [],
                friday: [],
                saturday: []
            };
        }
        
        // Update the timetable for the specified day
        batch.timetable[day.toLowerCase()] = timetableEntries;
        
        // Save the batch
        await batch.save();
        
        return res.status(200).json({
            success: true,
            message: "Timetable updated successfully",
            timetable: batch.timetable
        });
    } catch (error) {
        console.error("Error updating timetable:", error);
        return res.status(500).json({
            success: false,
            message: "Error updating timetable",
            error: error.message
        });
    }
});

// Get timetable for a batch
router.get("/batches/:batchId/timetable", async (req, res) => {
    try {
        const { batchId } = req.params;
        
        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        // Return the timetable
        return res.status(200).json({
            success: true,
            timetable: batch.timetable || {
                monday: [],
                tuesday: [],
                wednesday: [],
                thursday: [],
                friday: [],
                saturday: []
            }
        });
    } catch (error) {
        console.error("Error fetching timetable:", error);
        return res.status(500).json({
            success: false,
            message: "Error fetching timetable",
            error: error.message
        });
    }
});

// Add route to delete a specific timetable entry
router.delete("/batches/:batchId/timetable/:day/:hour", async (req, res) => {
    try {
        const { batchId, day, hour } = req.params;
        const hourNum = parseInt(hour);
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Validate day
        const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        if (!validDays.includes(day.toLowerCase())) {
            return res.status(400).json({
                success: false,
                message: "Invalid day. Must be one of: monday, tuesday, wednesday, thursday, friday, saturday"
            });
        }
        
        // Validate hour
        if (isNaN(hourNum) || hourNum < 1 || hourNum > 8) {
            return res.status(400).json({
                success: false,
                message: "Hour must be a number between 1 and 8"
            });
        }
        
        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to modify timetable for this batch"
            });
        }
        
        // Check if timetable exists
        if (!batch.timetable || !batch.timetable[day.toLowerCase()]) {
            return res.status(404).json({
                success: false,
                message: "Timetable not found for this day"
            });
        }
        
        // Find and remove the entry
        const daySchedule = batch.timetable[day.toLowerCase()];
        const entryIndex = daySchedule.findIndex(entry => entry.hour === hourNum);
        
        if (entryIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "Timetable entry not found for this hour"
            });
        }
        
        // Remove the entry
        batch.timetable[day.toLowerCase()].splice(entryIndex, 1);
        
        // Save the batch
        await batch.save();
        
        return res.status(200).json({
            success: true,
            message: "Timetable entry deleted successfully",
            timetable: batch.timetable
        });
    } catch (error) {
        console.error("Error deleting timetable entry:", error);
        return res.status(500).json({
            success: false,
            message: "Error deleting timetable entry",
            error: error.message
        });
    }
});

// Add route to update a specific timetable entry
router.put("/batches/:batchId/timetable/:day/:hour", async (req, res) => {
    try {
        const { batchId, day, hour } = req.params;
        const { subject, teacher, startTime, endTime } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacherAdmin = await AdminUser.findById(teacherId);
        
        if (!teacherAdmin) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        if (!subject) {
            return res.status(400).json({
                success: false,
                message: "Subject is required"
            });
        }

        // Validate day
        const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        if (!validDays.includes(day.toLowerCase())) {
            return res.status(400).json({
                success: false,
                message: "Invalid day. Must be one of: monday, tuesday, wednesday, thursday, friday, saturday"
            });
        }
        
        // Convert hour to number
        const hourNum = parseInt(hour);
        if (isNaN(hourNum) || hourNum < 1) {
            return res.status(400).json({
                success: false,
                message: "Hour must be a positive number"
            });
        }
        
        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to modify timetable for this batch"
            });
        }
        
        // Initialize timetable if it doesn't exist
        if (!batch.timetable) {
            batch.timetable = {
                monday: [],
                tuesday: [],
                wednesday: [],
                thursday: [],
                friday: [],
                saturday: []
            };
        }
        
        // Find the entry
        const daySchedule = batch.timetable[day.toLowerCase()] || [];
        const entryIndex = daySchedule.findIndex(entry => entry.hour === hourNum);
        
        if (entryIndex === -1) {
            // Entry doesn't exist, create a new one
            batch.timetable[day.toLowerCase()].push({
                hour: hourNum,
                subject,
                teacher,
                startTime,
                endTime
            });
        } else {
            // Update existing entry
            batch.timetable[day.toLowerCase()][entryIndex].subject = subject;
            
            // Update teacher if provided
            if (teacher !== undefined) {
                batch.timetable[day.toLowerCase()][entryIndex].teacher = teacher;
            }
            
            // Update startTime if provided
            if (startTime !== undefined) {
                batch.timetable[day.toLowerCase()][entryIndex].startTime = startTime;
            }
            
            // Update endTime if provided
            if (endTime !== undefined) {
                batch.timetable[day.toLowerCase()][entryIndex].endTime = endTime;
            }
        }
        
        // Sort entries by hour
        batch.timetable[day.toLowerCase()].sort((a, b) => a.hour - b.hour);
        
        // Save the batch
        await batch.save();
        
        return res.status(200).json({
            success: true,
            message: "Timetable entry updated successfully",
            timetable: batch.timetable
        });
    } catch (error) {
        console.error("Error updating timetable entry:", error);
        return res.status(500).json({
            success: false,
            message: "Error updating timetable entry",
            error: error.message
        });
    }
});

// Add route to clear all timetable entries for a day
router.delete("/batches/:batchId/timetable/:day", async (req, res) => {
    try {
        const { batchId, day } = req.params;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const teacherId = authHeader.split(' ')[1];
        const teacher = await AdminUser.findById(teacherId);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Validate day
        const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        if (!validDays.includes(day.toLowerCase())) {
            return res.status(400).json({
                success: false,
                message: "Invalid day. Must be one of: monday, tuesday, wednesday, thursday, friday, saturday"
            });
        }
        
        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to modify timetable for this batch"
            });
        }
        
        // Check if timetable exists
        if (!batch.timetable) {
            batch.timetable = {
                monday: [],
                tuesday: [],
                wednesday: [],
                thursday: [],
                friday: [],
                saturday: []
            };
        }
        
        // Clear the entries for the day
        batch.timetable[day.toLowerCase()] = [];
        
        // Save the batch
        await batch.save();
        
        return res.status(200).json({
            success: true,
            message: `Timetable entries for ${day} cleared successfully`,
            timetable: batch.timetable
        });
    } catch (error) {
        console.error("Error clearing timetable entries:", error);
        return res.status(500).json({
            success: false,
            message: "Error clearing timetable entries",
            error: error.message
        });
    }
});

// Create a test for a batch
router.post("/batches/:batchId/tests", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { examName, maximumMarks, subject } = req.body;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to add test to this batch"
            });
        }

        // Create the test
        const newTest = {
            examName,
            maximumMarks,
            subject,
            createdBy: teacherId,
            studentMarks: []
        };

        batch.testResults.push(newTest);
        await batch.save();

        const updatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('testResults.createdBy', 'name email');

        const addedTest = updatedBatch.testResults[updatedBatch.testResults.length - 1];

        res.status(201).json({
            success: true,
            message: "Test created successfully",
            test: addedTest
        });
    } catch (error) {
        console.error("Test creation error:", error);
        res.status(500).json({
            success: false,
            message: "Error creating test",
            error: error.message
        });
    }
});

// Get all tests for a batch
router.get("/batches/:batchId/tests", async (req, res) => {
    try {
        const { batchId } = req.params;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to view tests for this batch"
            });
        }

        // Get populated batch data
        const populatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('testResults.createdBy', 'name email')
            .populate('testResults.studentMarks.student', 'name email');
        
        res.status(200).json({
            success: true,
            tests: populatedBatch.testResults || []
        });
    } catch (error) {
        console.error("Error fetching tests:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching tests",
            error: error.message
        });
    }
});

// Get a specific test for a batch
router.get("/batches/:batchId/tests/:testId", async (req, res) => {
    try {
        const { batchId, testId } = req.params;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to view this test"
            });
        }
        
        // Get populated batch
        const populatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('testResults.createdBy', 'name email')
            .populate('testResults.studentMarks.student', 'name email');

        // Find the test
        const test = populatedBatch.testResults.id(testId);
        if (!test) {
            return res.status(404).json({
                success: false,
                message: "Test not found"
            });
        }

        res.status(200).json({
            success: true,
            test
        });
    } catch (error) {
        console.error("Error fetching test:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching test",
            error: error.message
        });
    }
});

// Update a test or add student marks
router.put("/batches/:batchId/tests/:testId", async (req, res) => {
    try {
        const { batchId, testId } = req.params;
        const { examName, maximumMarks, subject, studentMarks } = req.body;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to update test for this batch"
            });
        }

        // Find the test
        const test = batch.testResults.id(testId);
        if (!test) {
            return res.status(404).json({
                success: false,
                message: "Test not found"
            });
        }

        // Update test details if provided
        if (examName) test.examName = examName;
        if (maximumMarks) test.maximumMarks = maximumMarks;
        if (subject) test.subject = subject;
        
        // Add or update student marks if provided
        if (studentMarks && Array.isArray(studentMarks)) {
            for (const mark of studentMarks) {
                const existingMarkIndex = test.studentMarks.findIndex(
                    sm => sm.student.toString() === mark.student
                );
                
                if (existingMarkIndex >= 0) {
                    // Update existing mark
                    test.studentMarks[existingMarkIndex].marks = mark.marks;
                    if (mark.remarks) {
                        test.studentMarks[existingMarkIndex].remarks = mark.remarks;
                    }
                } else {
                    // Add new mark
                    test.studentMarks.push({
                        student: mark.student,
                        marks: mark.marks,
                        remarks: mark.remarks || ''
                    });
                }
            }
        }

        await batch.save();

        const updatedBatch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('testResults.createdBy', 'name email')
            .populate('testResults.studentMarks.student', 'name email');

        const updatedTest = updatedBatch.testResults.id(testId);

        res.status(200).json({
            success: true,
            message: "Test updated successfully",
            test: updatedTest
        });
    } catch (error) {
        console.error("Test update error:", error);
        res.status(500).json({
            success: false,
            message: "Error updating test",
            error: error.message
        });
    }
});

// Delete a test
router.delete("/batches/:batchId/tests/:testId", async (req, res) => {
    try {
        const { batchId, testId } = req.params;
        
        // Get the teacher ID from the authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authorization header is required"
            });
        }

        const token = authHeader.split(' ')[1];
        const teacherId = token;

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacherId) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to delete test for this batch"
            });
        }

        // Find and remove the test
        const testIndex = batch.testResults.findIndex(
            test => test._id.toString() === testId
        );
        
        if (testIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "Test not found"
            });
        }

        batch.testResults.splice(testIndex, 1);
        await batch.save();

        res.status(200).json({
            success: true,
            message: "Test deleted successfully"
        });
    } catch (error) {
        console.error("Test deletion error:", error);
        res.status(500).json({
            success: false,
            message: "Error deleting test",
            error: error.message
        });
    }
});

// Get fees payment data for a batch
router.get("/batches/:batchId/fees", async (req, res) => {
    try {
        const { batchId } = req.params;
        
        // Validate batchId
        if (!batchId || !mongoose.Types.ObjectId.isValid(batchId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid batch ID"
            });
        }
        
        const batch = await Batch.findById(batchId)
            .populate('feesPayments.student', 'name email')
            .populate('feesPayments.verifiedBy', 'name email');
        
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }
        
        res.status(200).json({
            success: true,
            feesPayments: batch.feesPayments || []
        });
    } catch (error) {
        console.error("Error fetching fees data:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching fees payment data",
            error: error.message
        });
    }
});

// Add or update fees payment record
router.post("/batches/:batchId/fees", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { studentId, amount, paymentMethod, status, remarks } = req.body;
        const authHeader = req.headers.authorization;

        // Validate batchId
        if (!batchId || !mongoose.Types.ObjectId.isValid(batchId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid batch ID"
            });
        }

        // Validate studentId
        if (!studentId || !mongoose.Types.ObjectId.isValid(studentId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid student ID"
            });
        }

        // Validate required fields
        if (!amount || isNaN(amount) || Number(amount) <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid amount"
            });
        }

        if (!paymentMethod || !['online', 'offline'].includes(paymentMethod)) {
            return res.status(400).json({
                success: false,
                message: "Invalid payment method"
            });
        }

        if (!status || !['paid', 'pending', 'overdue'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: "Invalid payment status"
            });
        }

        // Validate authentication
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const teacher = await AdminUser.findById(decoded.id);
        
        if (!teacher) {
            return res.status(401).json({
                success: false,
                message: "Invalid teacher credentials"
            });
        }

        // Find the batch
        const batch = await Batch.findById(batchId);
        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify teacher owns this batch
        if (batch.teacher_id.toString() !== teacher._id.toString()) {
            return res.status(403).json({
                success: false,
                message: "Unauthorized to modify fees for this batch"
            });
        }

        // Verify student is enrolled in the batch
        if (!batch.students.includes(studentId)) {
            return res.status(404).json({
                success: false,
                message: "Student not found in this batch"
            });
        }

        // Check if payment record already exists for this student
        const existingPaymentIndex = batch.feesPayments.findIndex(
            payment => payment.student.toString() === studentId
        );

        const paymentData = {
            student: studentId,
            amount: Number(amount),
            paymentMethod,
            status,
            remarks: remarks || '',
            paymentDate: new Date(),
            verifiedBy: teacher._id
        };

        if (existingPaymentIndex !== -1) {
            // Update existing payment
            batch.feesPayments[existingPaymentIndex] = {
                ...batch.feesPayments[existingPaymentIndex],
                ...paymentData
            };
        } else {
            // Add new payment
            batch.feesPayments.push(paymentData);
        }

        await batch.save();

        // Fetch updated batch with populated fields
        const updatedBatch = await Batch.findById(batchId)
            .populate('feesPayments.student', 'name email')
            .populate('feesPayments.verifiedBy', 'name email');

        res.status(200).json({
            success: true,
            message: "Fees payment record updated successfully",
            feesPayments: updatedBatch.feesPayments
        });
    } catch (error) {
        console.error("Error updating fees payment:", error);
        
        // Handle specific error types
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token"
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: "Authentication token expired"
            });
        }

        res.status(500).json({
            success: false,
            message: "Error updating fees payment record",
            error: error.message
        });
    }
});

module.exports = router;
