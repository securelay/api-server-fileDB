/*
Brief: Testing
Run: node --env-file=.env test.js
*/

import * as helper from './helper.js';


const key = helper.genKeyPair();

console.log(JSON.stringify(key));

console.log('This should show public: ' + helper.validate(key.public));
console.log('This should show private: ' + helper.validate(key.private));
console.log('This should show false: ' + helper.validate('random'));

helper.setupDB();

helper.publicProduce(key.public, 'dataA');
helper.publicProduce(key.public, 'dataB');
helper.publicProduce(key.public, 'dataC');

console.log(JSON.stringify(helper.privateConsume(key.private)));

helper.privateProduce(key.private, 'data');
console.log(JSON.stringify(helper.publicConsume(key.public)));

helper.oneToOneProduce(key.private, 'some Key', 'data for one to one at some key');
console.log(JSON.stringify(helper.oneToOneConsume(key.public, 'some Key')));
console.log(helper.oneToOneIsConsumed(key.private, 'some Key'));

helper.gc();

console.log('End of synchronous execution. Anything logged after this is from async only!')
