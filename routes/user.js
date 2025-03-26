const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const User = require('../models/user');
const Batch = require('../models/batch');
const authMiddleware = require('../middleware/auth');
const Attendance = require('../models/attendance'); // Add this import
const mongoose = require('mongoose');
const router = express.Router();


const registerSchema = z.object({
    name: z.string().min(1, "Name is required"),
    email: z.string().email("Invalid email format"),
    password: z.string().min(6, "Password must be at least 6 characters long")
});

const loginSchema = z.object({
    email: z.string().email("Invalid email format"),
    password: z.string().min(1, "Password is required")
});

const profileSchema = z.object({
    name: z.string().optional(),
    email: z.string().email("Invalid email format").optional(),
    currentPassword: z.string().optional(),
    newPassword: z.string().min(6, "New password must be at least 6 characters long").optional()
});

const joinBatchSchema = z.object({
    batch_code: z.string().min(1, "Batch code is required")
});

const parentRegisterSchema = z.object({
    name: z.string().min(1, "Name is required"),
    email: z.string().email("Invalid email format"),
    studentEmail: z.string().email("Invalid student email format"),
    password: z.string().min(6, "Password must be at least 6 characters long")
});

router.post("/register", async (req, res) => {
    try {
        const parsedData = registerSchema.parse(req.body);
        const { name, email, password } = parsedData;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: "Email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT_ROUNDS));
        
        // Create student account
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            role: 'student'
        });

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(201).json({
            message: "Student registration successful",
            token,
            user: { name: user.name, email: user.email, role: user.role }
        });
    } catch (error) {
        res.status(400).json({ message: error.errors || "Invalid input" });
    }
});

// Login route
router.post("/login", async (req, res) => {
    try {
        const parsedData = loginSchema.parse(req.body);
        const { email, password } = parsedData;
        
        // Find user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // If it's a parent, fetch the associated student information
        let studentInfo = null;
        if (user.role === 'parent') {
            const student = await User.findOne({ parentEmail: user.email });
            if (student) {
                studentInfo = {
                    id: student._id,
                    name: student.name,
                    email: student.email
                };
            }
        }

        res.status(200).json({
            message: "Login successful",
            token,
            user: { 
                id: user._id,
                name: user.name, 
                email: user.email, 
                role: user.role,
                studentInfo // Will be null for students and teachers
            }
        });
    } catch (error) {
        res.status(400).json({ message: error.errors || "Invalid input" });
    }
});

// Student-specific login route
router.post("/login/student", async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        const student = await User.findOne({ email, role: 'student' });
        if (!student) {
            return res.status(404).json({
                success: false,
                message: "Student not found"
            });
        }

        const isPasswordValid = await bcrypt.compare(password, student.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid password"
            });
        }

        const token = jwt.sign(
            { userId: student._id, email: student.email, role: 'student' },
            process.env.JWT_SECRET,
            { expiresIn: "24h" } // Extended token validity
        );

        res.json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: student._id,
                name: student.name,
                email: student.email,
                role: 'student'
            }
        });
    } catch (error) {
        console.error('Student login error:', error);
        res.status(500).json({
            success: false,
            message: "Login failed",
            error: error.message
        });
    }
});

// Parent-specific login route
router.post("/login/parent", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        // Explicitly check for parent role
        const parent = await User.findOne({ 
            email: email,
            role: 'parent'
        });

        if (!parent) {
            return res.status(404).json({
                success: false,
                message: "Parent account not found with this email"
            });
        }

        const isPasswordValid = await bcrypt.compare(password, parent.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid password"
            });
        }

        // Find linked students
        const linkedStudents = await User.find(
            { parentEmail: email, role: 'student' },
            'name email'
        );

        const token = jwt.sign(
            { 
                userId: parent._id,
                email: parent.email,
                role: 'parent'
            },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );

        res.json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: parent._id,
                name: parent.name,
                email: parent.email,
                role: 'parent'
            },
            linkedStudents
        });
    } catch (error) {
        console.error('Parent login error:', error);
        res.status(500).json({
            success: false,
            message: "Login failed. Please try again.",
            error: error.message
        });
    }
});

router.put("/profile", async (req, res) => {
    try {
        const parsedData = profileSchema.parse(req.body);
        const { name, email, currentPassword, newPassword } = parsedData;
        
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        if (currentPassword && newPassword) {
            const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
            if (!isPasswordValid) return res.status(401).json({ message: "Current password is incorrect" });
            user.password = await bcrypt.hash(newPassword, Number(process.env.SALT_ROUNDS));
        }

        if (name) user.name = name;
        if (email) {
            const existingUser = await User.findOne({ email, _id: { $ne: user._id } });
            if (existingUser) return res.status(409).json({ message: "Email already exists" });
            user.email = email;
        }

        await user.save();
        res.json({ message: "Profile updated successfully" });
    } catch (error) {
        res.status(400).json({ message: error.errors || "Invalid input" });
    }
});

router.post("/join-batch", async (req, res) => {
    try {
        const { batch_code } = req.body;
        const authHeader = req.headers.authorization;

        // Debug logs
        console.log('Received join batch request:', { 
            batch_code,
            authHeader
        });

        if (!batch_code || !authHeader) {
            return res.status(400).json({
                success: false,
                message: "Batch code and authorization header are required"
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        console.log('Decoded token:', decoded); // Debug log

        // Rest of the join batch logic...
        const student = await User.findById(decoded.userId);

        if (!student || student.role !== 'student') {
            return res.status(403).json({
                success: false,
                message: "Only students can join batches"
            });
        }

        const batch = await Batch.findOne({ 
            batch_code: batch_code.toUpperCase() 
        });

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found. Please check the batch code"
            });
        }

        if (batch.students.includes(student._id)) {
            return res.status(409).json({
                success: false,
                message: "You are already enrolled in this batch"
            });
        }

        batch.students.push(student._id);
        await batch.save();

        res.json({
            success: true,
            message: "Successfully joined batch",
            batch: {
                code: batch.batch_code,
                name: batch.name,
                class: batch.class
            }
        });
    } catch (error) {
        console.error('Join batch error:', error);
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired token"
            });
        }
        res.status(500).json({
            success: false,
            message: "Error joining batch",
            error: error.message
        });
    }
});

router.get("/my-batches", async (req, res) => {
    try {
        const { student_id } = req.query;
        
        if (!student_id) {
            return res.status(400).json({
                success: false,
                message: "Student ID is required"
            });
        }

        const batches = await Batch.find({
            students: student_id
        })
        .populate('teacher_id', 'name email')
        .sort({ createdAt: -1 });

        res.json({
            success: true,
            batches: batches.map(batch => ({
                _id: batch._id,
                name: batch.name,
                batch_code: batch.batch_code,
                class: batch.class,
                teacher: {
                    name: batch.teacher_id?.name || 'Not Assigned',
                    email: batch.teacher_id?.email
                },
                studentsCount: batch.students.length,
                createdAt: batch.createdAt
            }))
        });
    } catch (error) {
        console.error("Error fetching batches:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching batches"
        });
    }
});

router.get("/parent/student-batches", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        console.log('Auth header received:', authHeader); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded token:', decoded); // Debug log

        const parent = await User.findById(decoded.userId);
        if (!parent || parent.role !== 'parent') {
            return res.status(403).json({
                success: false,
                message: "Parent access required"
            });
        }

        // Find all students linked to this parent
        const students = await User.find({ parentEmail: parent.email });
        console.log('Found students:', students); // Debug log
        
        const studentBatches = await Promise.all(
            students.map(async (student) => {
                const batches = await Batch.find({ 
                    students: student._id 
                })
                .populate('teacher_id', 'name email')
                .populate('students', 'name email')
                .sort({ createdAt: -1 });
                
                return {
                    student: {
                        id: student._id,
                        name: student.name,
                        email: student.email
                    },
                    batches: batches.map(batch => ({
                        _id: batch._id,
                        name: batch.name,
                        batch_code: batch.batch_code,
                        class: batch.class,
                        teacher_id: batch.teacher_id,
                        studentsCount: batch.students.length,
                        announcements: batch.announcements?.length || 0,
                        createdAt: batch.createdAt
                    }))
                };
            })
        );

        res.json({
            success: true,
            data: studentBatches
        });
    } catch (error) {
        console.error('Parent batches error:', error);
        res.status(error.status || 500).json({
            success: false,
            message: error.message || "Failed to fetch student batches"
        });
    }
});

// Get batch details for student
router.get("/student/batches/:batchId", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { userId } = req.query;
        const authHeader = req.headers.authorization;

        console.log('Received request:', {
            batchId,
            userId,
            authHeader
        });

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = authHeader.split(' ')[1];
        
        try {
            // Verify the token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Decoded token:', decoded);

            // Check if the token contains userId that matches the request
            if (decoded.userId !== userId) {
                console.log('User ID mismatch:', {
                    tokenUserId: decoded.userId,
                    requestUserId: userId
                });
                return res.status(403).json({
                    success: false,
                    message: "User ID mismatch"
                });
            }

            // Find the batch with populated fields
            const batch = await Batch.findById(batchId)
                .populate('teacher_id', 'name email')
                .populate('students', 'name email')
                .lean();

            if (!batch) {
                return res.status(404).json({
                    success: false,
                    message: "Batch not found"
                });
            }

            // Check if student is enrolled
            const isEnrolled = batch.students.some(
                student => student._id.toString() === userId
            );

            if (!isEnrolled) {
                return res.status(403).json({
                    success: false,
                    message: "You are not enrolled in this batch"
                });
            }

            const formattedBatch = {
                _id: batch._id,
                name: batch.name,
                batch_code: batch.batch_code,
                class: batch.class,
                teacher: batch.teacher_id,
                studentsCount: batch.students.length,
                students: batch.students,
                announcements: batch.announcements || [],
                createdAt: batch.createdAt
            };

            res.json({
                success: true,
                batch: formattedBatch
            });

        } catch (tokenError) {
            console.error('Token verification error:', tokenError);
            return res.status(401).json({
                success: false,
                message: "Invalid or expired token",
                error: tokenError.message
            });
        }
    } catch (error) {
        console.error("Error fetching batch details:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching batch details",
            error: error.message
        });
    }
});

// Get batch details for parent
router.get("/parent/batches/:batchId", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { parentId, studentId } = req.query;
        const authHeader = req.headers.authorization;

        console.log('Request details:', { batchId, parentId, studentId }); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        // Verify parent and student relationship
        const parent = await User.findById(parentId);
        const student = await User.findById(studentId);

        if (!parent || parent.role !== 'parent') {
            return res.status(403).json({
                success: false,
                message: "Parent access required"
            });
        }

        if (!student || student.parentEmail !== parent.email) {
            return res.status(403).json({
                success: false,
                message: "Invalid student access"
            });
        }

        // Find and verify batch
        const batch = await Batch.findById(batchId)
            .populate('teacher_id', 'name email')
            .populate('students', 'name email')
            .lean();

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify student enrollment
        if (!batch.students.some(s => s._id.toString() === studentId)) {
            return res.status(403).json({
                success: false,
                message: "Student not enrolled in this batch"
            });
        }

        // Format response
        const formattedBatch = {
            _id: batch._id,
            name: batch.name,
            batch_code: batch.batch_code,
            class: batch.class,
            teacher: batch.teacher_id,
            student: student,
            studentsCount: batch.students.length,
            announcements: batch.announcements || [],
            createdAt: batch.createdAt
        };

        res.json({
            success: true,
            batch: formattedBatch
        });

    } catch (error) {
        console.error("Error fetching batch details:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching batch details",
            error: error.message
        });
    }
});

// Add this route after existing routes
router.get("/student/batches/:batchId/attendance", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { userId } = req.query;
        const { startDate, endDate } = req.query;
        const authHeader = req.headers.authorization;

        console.log('Fetching attendance:', { batchId, userId, startDate, endDate }); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Build query for attendance records
        const query = {
            batch_id: batchId
        };

        if (startDate && endDate) {
            query.date = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }

        // Fetch all attendance records for the batch
        const attendanceRecords = await Attendance.find(query)
            .populate('marked_by', 'name')
            .sort({ date: -1 });

        // Filter and format records for the specific student
        const formattedAttendance = attendanceRecords.map(record => {
            const studentRecord = record.records.find(
                r => r.student_id.toString() === userId
            );
            
            return studentRecord ? {
                date: record.date,
                status: studentRecord.status,
                remarks: studentRecord.remarks || '',
                marked_by: record.marked_by.name
            } : null;
        }).filter(Boolean);

        // Calculate statistics
        const totalClasses = formattedAttendance.length;
        const present = formattedAttendance.filter(record => record.status === 'present').length;
        const absent = totalClasses - present;
        const attendancePercentage = totalClasses > 0 ? (present / totalClasses) * 100 : 0;

        res.json({
            success: true,
            attendance: {
                records: formattedAttendance,
                statistics: {
                    totalClasses,
                    present,
                    absent,
                    attendancePercentage: Math.round(attendancePercentage * 100) / 100
                }
            }
        });

    } catch (error) {
        console.error("Error fetching attendance:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching attendance records",
            error: error.message
        });
    }
});

// Add this new route for parent to view student attendance
router.get("/parent/batches/:batchId/student-attendance/:studentId", async (req, res) => {
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

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Verify parent has access to this student
        const parent = await User.findById(decoded.userId);
        const student = await User.findById(studentId);

        if (!parent || parent.role !== 'parent') {
            return res.status(403).json({
                success: false,
                message: "Parent access required"
            });
        }

        if (!student || student.parentEmail !== parent.email) {
            return res.status(403).json({
                success: false,
                message: "Not authorized to view this student's attendance"
            });
        }

        // Build query for attendance records
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

        const attendanceRecords = await Attendance.find(query)
            .populate('marked_by', 'name')
            .sort({ date: -1 });

        // Format the attendance records
        const formattedRecords = attendanceRecords.map(record => {
            const studentRecord = record.records.find(
                r => r.student_id.toString() === studentId
            );
            return {
                date: record.date,
                status: studentRecord.status,
                remarks: studentRecord.remarks || '',
                marked_by: record.marked_by.name
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
            message: "Error fetching attendance records",
            error: error.message
        });
    }
});

// Get timetable for a batch (for students)
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

// Get timetable for a batch (for parents)
router.get("/parent/batches/:batchId/timetable", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { studentId } = req.query;
        
        if (!studentId) {
            return res.status(400).json({
                success: false,
                message: "Student ID is required"
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
        
        // Verify student is in this batch
        const isStudentInBatch = batch.students.some(id => id.toString() === studentId);
        if (!isStudentInBatch) {
            return res.status(403).json({
                success: false,
                message: "Student is not enrolled in this batch"
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

// Get tests for a specific batch (student view)
router.get('/student/batches/:batchId/tests', async (req, res) => {
    try {
        const { batchId } = req.params;
        const authHeader = req.headers.authorization;

        console.log('Auth header for student test results:', authHeader); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify the JWT token
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Decoded student token:', decoded); // Debug log
            
            const studentId = decoded.userId;
            const student = await User.findById(studentId);
            
            if (!student) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid student credentials"
                });
            }
            
            // Check if student is enrolled in the batch
            const batch = await Batch.findById(batchId);
            
            if (!batch) {
                return res.status(404).json({
                    success: false,
                    message: "Batch not found"
                });
            }
            
            const isEnrolled = batch.students.some(
                id => id.toString() === studentId
            );
            
            if (!isEnrolled) {
                return res.status(403).json({
                    success: false,
                    message: "Student not enrolled in this batch"
                });
            }
            
            // Get a populated version of the batch
            const populatedBatch = await Batch.findById(batchId)
                .populate('testResults.createdBy', 'name email')
                .populate('testResults.studentMarks.student', 'name email');
            
            // Return all tests for the batch
            res.status(200).json({
                success: true,
                tests: populatedBatch.testResults || []
            });
        } catch (jwtError) {
            console.error('JWT verification error:', jwtError);
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token"
            });
        }
    } catch (error) {
        console.error("Error fetching tests:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching tests",
            error: error.message
        });
    }
});

// Get tests for a specific batch (parent view)
router.get('/parent/batches/:batchId/tests', async (req, res) => {
    try {
        const { batchId } = req.params;
        const { studentId } = req.query;
        const authHeader = req.headers.authorization;

        console.log('Auth header for parent test results:', authHeader); // Debug log
        console.log('Request details:', { batchId, studentId }); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        if (!studentId) {
            return res.status(400).json({
                success: false,
                message: "Student ID is required as a query parameter"
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify the JWT token
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Decoded parent token:', decoded); // Debug log
            
            const parentId = decoded.userId;
            const parent = await User.findById(parentId);
            
            if (!parent) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid parent credentials"
                });
            }
            
            // Check if the student exists and is related to the parent
            const student = await User.findById(studentId);
            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: "Student not found"
                });
            }
            
            if (student.parentEmail !== parent.email) {
                return res.status(403).json({
                    success: false,
                    message: "Not authorized to view this student's information"
                });
            }
            
            // Check if student is enrolled in the batch
            const batch = await Batch.findById(batchId);
            
            if (!batch) {
                return res.status(404).json({
                    success: false,
                    message: "Batch not found"
                });
            }
            
            const isEnrolled = batch.students.some(
                id => id.toString() === studentId
            );
            
            if (!isEnrolled) {
                return res.status(403).json({
                    success: false,
                    message: "Student not enrolled in this batch"
                });
            }
            
            // Get a populated version of the batch
            const populatedBatch = await Batch.findById(batchId)
                .populate('testResults.createdBy', 'name email')
                .populate('testResults.studentMarks.student', 'name email');
            
            // Return all tests for the batch
            res.status(200).json({
                success: true,
                tests: populatedBatch.testResults || []
            });
        } catch (jwtError) {
            console.error('JWT verification error:', jwtError);
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token"
            });
        }
    } catch (error) {
        console.error("Error fetching tests:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching tests",
            error: error.message
        });
    }
});

// Parent-only registration route
router.post("/register/parent", async (req, res) => {
    try {
        const parsedData = parentRegisterSchema.parse(req.body);
        const { name, email, studentEmail, password } = parsedData;
        
        // Check if parent email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: "Email already exists" });
        }

        // Check if student email exists
        const student = await User.findOne({ email: studentEmail, role: 'student' });
        if (!student) {
            return res.status(404).json({ message: "Student email not found. Please register the student first." });
        }

        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT_ROUNDS));
        
        // Create parent account
        const parent = await User.create({
            name,
            email,
            password: hashedPassword,
            role: 'parent'
        });

        // Update the student with parent email
        await User.findByIdAndUpdate(student._id, { parentEmail: email });

        const token = jwt.sign(
            { userId: parent._id, email: parent.email, role: parent.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(201).json({
            message: "Parent registration successful",
            token,
            user: { name: parent.name, email: parent.email, role: parent.role }
        });
    } catch (error) {
        res.status(400).json({ message: error.errors || "Invalid input" });
    }
});

// Get student's fees payment status for a batch
router.get("/student/batches/:batchId/fees", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { userId } = req.query;
        
        if (!batchId || !mongoose.Types.ObjectId.isValid(batchId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid batch ID"
            });
        }

        if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid user ID"
            });
        }

        // Find the batch with populated fields
        const batch = await Batch.findById(batchId)
            .populate('feesPayments.student', 'name email')
            .lean();

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Check if student is enrolled
        const isEnrolled = batch.students.some(
            student => student.toString() === userId
        );

        if (!isEnrolled) {
            return res.status(403).json({
                success: false,
                message: "Student is not enrolled in this batch"
            });
        }

        // Get fee payment for the student
        const feesPayment = batch.feesPayments.find(
            payment => payment.student._id.toString() === userId || payment.student.toString() === userId
        ) || null;

        res.json({
            success: true,
            feesPayment
        });
    } catch (error) {
        console.error("Error fetching fees payment:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching fees payment information",
            error: error.message
        });
    }
});

// Get parent's child fees payment status for a batch
router.get("/parent/batches/:batchId/fees", async (req, res) => {
    try {
        const { batchId } = req.params;
        const { parentId, studentId } = req.query;

        if (!batchId || !mongoose.Types.ObjectId.isValid(batchId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid batch ID"
            });
        }

        if (!studentId || !mongoose.Types.ObjectId.isValid(studentId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid student ID"
            });
        }

        // Verify parent and student relationship
        const parent = await User.findById(parentId);
        const student = await User.findById(studentId);

        if (!parent || parent.role !== 'parent') {
            return res.status(403).json({
                success: false,
                message: "Parent access required"
            });
        }

        if (!student || student.parentEmail !== parent.email) {
            return res.status(403).json({
                success: false,
                message: "Invalid student access"
            });
        }

        // Find and verify batch
        const batch = await Batch.findById(batchId)
            .populate('feesPayments.student', 'name email')
            .lean();

        if (!batch) {
            return res.status(404).json({
                success: false,
                message: "Batch not found"
            });
        }

        // Verify student enrollment
        if (!batch.students.some(s => s.toString() === studentId)) {
            return res.status(403).json({
                success: false,
                message: "Student not enrolled in this batch"
            });
        }

        // Get fee payment for the student
        const feesPayment = batch.feesPayments.find(
            payment => payment.student._id.toString() === studentId || payment.student.toString() === studentId
        ) || null;

        res.json({
            success: true,
            feesPayment
        });
    } catch (error) {
        console.error("Error fetching fees payment:", error);
        res.status(500).json({
            success: false,
            message: "Error fetching fees payment information",
            error: error.message
        });
    }
});

module.exports = router;