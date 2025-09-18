const { body, param, query, validationResult } = require('express-validator');

// Validation middleware
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Task validation rules
const taskValidation = {
  create: [
    body('title').trim().notEmpty().withMessage('Title is required')
      .isLength({ max: 255 }).withMessage('Title too long'),
    body('status').optional().isIn(['todo', 'in_progress', 'dev_completed', 'pr_in_review', 'pr_merged', 'qa_deployed', 'qa_testing_completed', 'done']),
    body('priority').optional().isIn(['low', 'medium', 'high']),
    body('category').optional().isIn(['office', 'own']),
    body('type').optional().isIn(['work', 'learning']),
    body('due_date').optional().isISO8601(),
    body('due_time').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    body('important').optional().isBoolean(),
    validate
  ],
  update: [
    param('id').isInt().withMessage('Invalid task ID'),
    body('title').optional().trim().notEmpty(),
    body('status').optional().isIn(['todo', 'in_progress', 'dev_completed', 'pr_in_review', 'pr_merged', 'qa_deployed', 'qa_testing_completed', 'done']),
    body('priority').optional().isIn(['low', 'medium', 'high']),
    validate
  ],
  delete: [
    param('id').isInt().withMessage('Invalid task ID'),
    validate
  ],
  getById: [
    param('id').isInt().withMessage('Invalid task ID'),
    validate
  ]
};

// Auth validation rules
const authValidation = {
  register: [
    body('username').trim().notEmpty().withMessage('Username is required')
      .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters'),
    body('phone').matches(/^\d{10,15}$/).withMessage('Phone must be 10-15 digits'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
      .matches(/\d/).withMessage('Password must contain at least one number'),
    validate
  ],
  login: [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    validate
  ],
  forgotPassword: [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('new_password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    validate
  ]
};

// Project validation
const projectValidation = {
  create: [
    body('name').trim().notEmpty().withMessage('Project name is required')
      .isLength({ max: 100 }).withMessage('Project name too long'),
    body('kind').optional().isIn(['office', 'personal']),
    validate
  ]
};

// Comment validation
const commentValidation = {
  create: [
    param('id').isInt().withMessage('Invalid task ID'),
    body('comment').trim().notEmpty().withMessage('Comment is required')
      .isLength({ max: 1000 }).withMessage('Comment too long'),
    validate
  ]
};

module.exports = {
  taskValidation,
  authValidation,
  projectValidation,
  commentValidation,
  validate
};
