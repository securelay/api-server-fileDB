import * as helper from './helper.js';
import Fastify from 'fastify';

const port = parseInt(process.env.PORT);
const bodyLimit = parseInt(process.env.BODYLIMIT);
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX);
const rateLimitTimeWindow = process.env.RATE_LIMIT_TIME_WINDOW;
const rateLimitBan = parseInt(process.env.RATE_LIMIT_BAN);
const rateLimitMax404 = parseInt(process.env.RATE_LIMIT_MAX_404);
const rateLimitTimeWindow404 = process.env.RATE_LIMIT_TIME_WINDOW_404;
const rateLimitBan404 = parseInt(process.env.RATE_LIMIT_BAN_404);

helper.setupDB();

// Impose content-length limit
const fastify = Fastify({
  logger: true,
  ignoreTrailingSlash: true,
  bodyLimit: bodyLimit
})

// Enable parser for application/x-www-form-urlencoded
fastify.register(import('@fastify/formbody'))

// Enable CORS
fastify.register(import('@fastify/cors'))

// Enable ratelimiter
await fastify.register(import('@fastify/rate-limit'), {
  global: true,
  max: rateLimitMax,
  timeWindow: rateLimitTimeWindow,
  ban: rateLimitBan
})

// Rate limits for preventing guessing of URLS through 404s
fastify.setNotFoundHandler({
  preHandler: fastify.rateLimit({
    max: rateLimitMax404,
    timeWindow: rateLimitTimeWindow404,
    ban: rateLimitBan404
  })
})

const callUnauthorized = function(reply, msg){
    reply.code(401);
    reply.send({message: msg, error: "Unauthorized", statusCode: reply.statusCode});
}

const callInternalServerError = function(reply, msg){
    reply.code(500);
    reply.send({message: msg, error: "Internal Server Error", statusCode: reply.statusCode});
}

fastify.get('/', (request, reply) => {
    reply.redirect('https://securelay.github.io');
})

fastify.get('/keys', (request, reply) => {
    reply.send(helper.genKeyPair());
})

fastify.get('/keys/:key', (request, reply) => {
    const { key } = request.params;
    const keyType = helper.validate(key);
    if (keyType === 'public') {
        reply.send({type: "public"});
    } else if (keyType === 'private') {
        reply.send({type: "private", public: helper.genPublicKey(key)});
    } else {
        reply.callNotFound();
    }
})

fastify.post('/public/:publicKey', (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        helper.publicProduce(publicKey, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/private/:privateKey', (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        const dataArray = helper.privateConsume(privateKey);
        if (!dataArray.length) throw 404;
        reply.send(dataArray);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.post('/private/:privateKey', (request, reply) => {
    const { privateKey } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        helper.privateProduce(privateKey, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/public/:publicKey', (request, reply) => {
    const { publicKey } = request.params;
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        const data = helper.publicConsume(publicKey);
        if (!data) throw 404;
        reply.send(data);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.post('/private/:privateKey/:key', (request, reply) => {
    const { privateKey, key } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        helper.oneToOneProduce(privateKey, key, JSON.stringify(request.body));
        reply.send({message: "Done", error: "Ok", statusCode: reply.statusCode});
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/public/:publicKey/:key', (request, reply) => {
    const { publicKey, key } = request.params;
    try {
        if (helper.validate(publicKey) !== 'public') throw 401;
        const data = helper.oneToOneConsume(publicKey, key);
        if (!data) throw 404;
        reply.send(data);
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Public');
        } else if (err == 404) {
            reply.callNotFound();
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/private/:privateKey/:key', (request, reply) => {
    const { privateKey, key } = request.params;
    try {
        if (helper.validate(privateKey) !== 'private') throw 401;
        reply.send(helper.oneToOneIsConsumed(privateKey, key));
    } catch (err) {
        if (err == 401) {
            callUnauthorized(reply, 'Provided key is not Private');
        } else {
            callInternalServerError(reply, err);
        }
    }    
})

fastify.get('/gc', (request, reply) => { 
    helper.gc();
    return 'Garbage cleaner launched.'
});

fastify.listen({ port: port, host: '0.0.0.0' }, (err) => {
  if (err) throw err
})

// Run garbage cleaner every 4 hrs
setTimeout(helper.gc, 4*3600*1000)
