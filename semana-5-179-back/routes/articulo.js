/* un Ejemplo  de como se veria la ruta listar - modelo del  articulo*/
const routerx = require('express-promise-router');
const articuloController = require('../controllers/ArticuloController');
const auth = require('../middlewares/auth');

const router = routerx();

router.post('/add', auth.verifyAlmacenero, articuloController.add);
router.get('/list', articuloController.list);
router.put('/update', auth.verifyAlmacenero, articuloController.update);
router.put('/activate', auth.verifyAlmacenero, articuloController.activate);
router.put('/deactivate', auth.verifyAlmacenero, articuloController.deactivate);

module.exports = router;