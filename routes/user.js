const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const User = require('../models/user');
const Batch = require('../models/batch');
const authMiddleware = require('../middleware/auth');
const router = express.Router();


const registerSchema = z.object({
    name: z.string().min(1, "Name is required"),
    email: z.string().email("Invalid email format"),
    parentEmail: z.string().email("Invalid parent email format"),
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

router.post("/register", async (req, res) => {
    try {
        const parsedData = registerSchema.parse(req.body);
        const { name, email, parentEmail, password } = parsedData;
        
        const existingUser = await User.findOne({ 
            $or: [
                { email },
                { email: parentEmail }
            ]
        });
        if (existingUser) {
            return res.status(409).json({ message: "Email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT_ROUNDS));
        
        // Create student account
        const user = await User.create({
            name,
            email,
            parentEmail,
            password: hashedPassword,
            role: 'student'
        });

        // Create parent account with same password
        await User.create({
            name: `Parent of ${name}`,
            email: parentEmail,
            password: hashedPassword,
            role: 'parent'
        });

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.status(201).json({
            message: "Registration successful",
            token,
            user: { name: user.name, email: user.email, parentEmail: user.parentEmail, role: user.role }
        });
    } catch (error) {
        res.status(400).json({ message: error.errors || "Invalid input" });
    }
});

// Legacy login route (kept for backward compatibility)
router.post("/login", async (req, res) => {
    try {
        const parsedData = loginSchema.parse(req.body);
        const { email, password } = parsedData;
        const user = await User.findOne({
            $or: [
                { email: email },
                { parentEmail: email }
            ]
        });

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

        res.json({
            message: "Login successful",
            token,
            user: { 
                name: user.name, 
                email: user.email, 
                parentEmail: user.parentEmail,
                role: user.role
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

module.exports = router;