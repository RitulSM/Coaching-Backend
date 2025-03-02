const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const AdminUser = require('../models/adminUser');
const User = require('../models/user');
const Batch = require('../models/batch');
const Announcement = require('../models/announcement');
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
      { expiresIn: "1h" }
    );
    
    res.json({
      message: "Admin login successful",
      token,
      admin: { name: admin.name, email: admin.email }
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

        res.json({
            success: true,
            batch: {
                _id: batch._id,
                name: batch.name,
                batch_code: batch.batch_code,
                class: batch.class,
                teacher_id: batch.teacher_id,
                students: batch.students,
                createdAt: batch.createdAt,
                status: 'active' // You can modify this based on your requirements
            }
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

module.exports = router;
