const mongoose = require('mongoose');
const axios = require('axios')
const mongoConnectionUrl = "mongodb+srv://cinoy:informationsecurity@cluster0.m9mrb.mongodb.net/test"

let connectToMongo = function () {
    return new Promise((resolve, reject) => {
        try {
            mongoose.connect(mongoConnectionUrl, {
                useNewUrlParser: true,
                useUnifiedTopology: true
            });
            let db = mongoose.connection;

            // When successfully connected
            db.on('connected', function () {
                console.log(' Mongoose default connection open');
                resolve();
            });

            db.once('open', function callback() {
                console.log(' Connection to Mongo Successful');
            });

            db.on('error', function onError(err) {
                reject(err);
                console.log(' Connection to Mongo Unsuccessful: ' + err.message);
            });

            // When the connection is disconnected
            db.on('disconnected', function () {
                console.log(' Mongoose default connection disconnected');
            });
        }
        catch (error) {
            console.log("Error in MONGO connection" + JSON.stringify(error));
            reject(error);
        }

    })

};

let Schema = mongoose.Schema;

let User = new Schema({
    username: { type: String, required: true, index: { unique: true } },
    id: { type: String },
    credentials: [
        Object
    ]

});



async function fetchData(requestBody) {
    const options = {
        url: 'https://mlclouddeploy-cga6ejs7iq-el.a.run.app/',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        data: requestBody
    };

    try {
        const response = await axios(options);
        const responseData = response.data;
        return responseData;
    } catch (error) {
        console.error(error);
        throw error;
    }
}

module.exports.User = mongoose.model('User', User, 'User');
module.exports.mongoConnection = mongoose.connection;
module.exports.connectToMongo = connectToMongo;
module.exports.fetchData = fetchData