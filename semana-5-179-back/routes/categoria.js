/* import routerx from 'express-promise-router';
import categoriaController from '../controllers/CategoriaController';
import auth from '../middlewares/auth'; */
const routerx = require('express-promise-router');
const categoriaController = require('../controllers/CategoriaController');
const auth = require('../middlewares/auth');


const router = routerx();

router.post('/add', auth.verifyAlmacenero, categoriaController.add);
router.get('/list', auth.verifyAlmacenero, categoriaController.list);
router.put('/update', auth.verifyAlmacenero, categoriaController.update);
router.put('/activate', auth.verifyAlmacenero, categoriaController.activate);
router.put('/deactivate', auth.verifyAlmacenero, categoriaController.deactivate);


module.exports = router;