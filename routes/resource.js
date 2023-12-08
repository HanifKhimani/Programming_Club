const express = require('express');
const router = express.Router();
const recourseController = require('../controllers/resourceController');
const ensureAuthenticated=require('../config/auth.js').ensureAuthenticated;

router.get("/",ensureAuthenticated,recourseController.Resource_get_all);
module.exports = router;