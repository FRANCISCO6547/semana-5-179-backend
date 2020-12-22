var jwt = require('jsonwebtoken');
const models = require('../models');

async function checkToken(token){
  let _idd=null;
  try{
    const{_id}=await jwt.decode(token);
    _idd=_id;
  }catch(e){
    return false;
  }
  const user=await models.Usuario.findOne({where: {id:_idd, estado: 1}});
  if(user){
    const token=jwt.sign({_id: _idd}, 'secretKeyToGenerateToken', {expiresIn: '1d'});
    return {token, rol: user.rol};
  }else{
    return false;
  }
}

module.exports = {

    //generar el token
    encode: async(_id, rol) => {
      const token=jwt.sign({_id: _id, rol: rol}, 'secretKeyToGenerateToken', {expiresIn: '1d'});
      return token;
    },
    //permite decodificar el token
    decode: async(token) => {
        try {
          const{_id}=await jwt.verify(token, 'secretKeyToGenerateToken');
          const user=await models.Usuario.findOne({where:{_id, estado: 1}});
          if(user){
            return user;
          }else{
            return false;
          }
        } catch (e) {
            const newToken=await checkToken(token);
            return newToken;
        }

    }
}