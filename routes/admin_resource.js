const express = require('express');
const router = express.Router();
const admin_recourseController = require('../controllers/admin_resourceController');
const is_admin=require('../config/auth.js').isAdmin;

// see all resource
router.get("/",admin_recourseController.Resource_get_all);

// write/compose the resource
router.get("/compose",is_admin,admin_recourseController.compose_get);
router.post("/compose",is_admin,admin_recourseController.compose_post);

// update the resource
router.get("/compose/:id",is_admin,admin_recourseController.compose_update_get);
router.post("/compose/:id",is_admin,admin_recourseController.compose_update);

// delete the resource
router.post("/delete_resource",is_admin,admin_recourseController.compose_delete);

module.exports = router;